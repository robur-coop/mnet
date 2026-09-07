let src = Logs.Src.create "icmpv4"

module Log = (val Logs.src_log src : Logs.LOG)

module Packet = struct
  type 'a t = { code: int; kind: 'a kind; checksum: int; shdr: 'a }

  and 'a kind =
    | Echo_reply : id_and_seq kind
    | Destination_unreachable : next_hop_mtu kind
    | Source_quench : unused kind
    | Redirect : Ipaddr.V4.t kind
    | Echo_request : id_and_seq kind
    | Time_exceeded : unused kind
    | Parameter_problem : pointer kind
    | Timestamp_request : id_and_seq kind
    | Timestamp_reply : id_and_seq kind
    | Information_request : id_and_seq kind
    | Information_reply : id_and_seq kind

  and id_and_seq = int * int
  and next_hop_mtu = Hop of int [@@unboxed]
  and pointer = Pointer of int [@@unboxed]
  and unused = Unused
  and packet = Packet : 'a t -> packet

  type 'a message = 'a t

  open Bin

  let unused =
    record ~name:"unused" (fun _ _ -> Unused)
    |+ field beuint16 (Fun.const 0)
    |+ field beuint16 (Fun.const 0)
    |> sealr

  let ipaddr = map beint32 Ipaddr.V4.of_int32 Ipaddr.V4.to_int32

  let id_and_seq =
    record ~name:"id-and-seq" (fun id seq -> (id, seq))
    |+ field ~name:"id" beuint16 fst
    |+ field ~name:"seq" beuint16 snd
    |> sealr

  let next_hop_mtu =
    record ~name:"next-hop-mtu" (fun _ mtu -> Hop mtu)
    |+ field beuint16 (Fun.const 0)
    |+ field ~name:"mtu" beuint16 (fun (Hop mtu) -> mtu)
    |> sealr

  let pointer =
    record ~name:"pointer" (fun ptr _ -> Pointer ptr)
    |+ field ~name:"ptr" uint8 (fun (Pointer ptr) -> ptr)
    |+ field (bytes (fixed 3)) (Fun.const "\000\000\000")
    |> sealr

  let body kind shdr =
    record ~name:"icmpv4" (fun code checksum shdr ->
        { kind; code; checksum; shdr })
    |+ field ~name:"code" uint8 (fun t -> t.code)
    |+ field ~name:"checksum" beuint16 (fun t -> t.checksum)
    |+ field ~name:"rest-of-header" shdr (fun t -> t.shdr)
    |> sealr

  let packet =
    let prj (echo_reply : id_and_seq message -> packet case_p)
        (destination_unreachable : next_hop_mtu message -> packet case_p)
        (source_quench : unused message -> packet case_p)
        (redirect : Ipaddr.V4.t message -> packet case_p)
        (echo_request : id_and_seq message -> packet case_p)
        (time_exceeded : unused message -> packet case_p)
        (parameter_problem : pointer message -> packet case_p)
        (timestamp_request : id_and_seq message -> packet case_p)
        (timestamp_reply : id_and_seq message -> packet case_p)
        (information_request : id_and_seq message -> packet case_p)
        (information_reply : id_and_seq message -> packet case_p) (Packet t) =
      match t.kind with
      | Echo_reply -> echo_reply t
      | Destination_unreachable -> destination_unreachable t
      | Source_quench -> source_quench t
      | Redirect -> redirect t
      | Echo_request -> echo_request t
      | Time_exceeded -> time_exceeded t
      | Parameter_problem -> parameter_problem t
      | Timestamp_request -> timestamp_request t
      | Timestamp_reply -> timestamp_reply t
      | Information_request -> information_request t
      | Information_reply -> information_reply t
    in
    let inj t = Packet t in
    variant ~name:"icmpv4" prj
    |~ case1 ~tag:0 (body Echo_reply id_and_seq) inj
    |~ case1 ~tag:3 (body Destination_unreachable next_hop_mtu) inj
    |~ case1 ~tag:4 (body Source_quench unused) inj
    |~ case1 ~tag:5 (body Redirect ipaddr) inj
    |~ case1 ~tag:8 (body Echo_request id_and_seq) inj
    |~ case1 ~tag:11 (body Time_exceeded unused) inj
    |~ case1 ~tag:12 (body Parameter_problem pointer) inj
    |~ case1 ~tag:13 (body Timestamp_request id_and_seq) inj
    |~ case1 ~tag:14 (body Timestamp_reply id_and_seq) inj
    |~ case1 ~tag:15 (body Information_request id_and_seq) inj
    |~ case1 ~tag:16 (body Information_reply id_and_seq) inj
    |> sealv ~tag:uint8

  let decode_packet = Staged.unstage (Bin.decode packet)
  let encode_packet = Staged.unstage (Bin.to_string packet)

  let decode ?(off = 0) str =
    let len = String.length str - off in
    let pos = ref (Off.v off) in
    let pkt = decode_packet str ~len pos in
    if Utcp.Checksum.digest_string ~off ~len str != 0 then
      invalid_arg "Invalid ICMPv4 checksum";
    let pos = (!pos :> int) in
    let payload = String.sub str pos (String.length str - pos) in
    (pkt, payload)

  let decode ?off bstr =
    try Ok (decode ?off bstr)
    with exn ->
      Log.err (fun m ->
          m "Got an exception while decoding ICMPv4 packet: %s"
            (Printexc.to_string exn));
      Error `Invalid_ICMPv4_packet

  let to_bytes pkt = Bytes.unsafe_of_string (encode_packet (Packet pkt))
end

let input ipv4 pkt payload =
  let dst = pkt.IPv4.src in
  match Packet.decode payload with
  | Error _ ->
      Log.err (fun m -> m "Invalid ICMPv4 packet:");
      Log.err (fun m -> m "@[<hov>%a@]" (Hxd_string.pp Hxd.default) payload)
  | Ok (Packet pkt, payload) ->
      begin match pkt.kind with
      | Packet.Echo_request ->
          Log.debug (fun m -> m "Echo request");
          let pkt =
            { Packet.code= 0; kind= Echo_reply; checksum= 0; shdr= pkt.shdr }
          in
          let buf = Packet.to_bytes pkt in
          let chk =
            Utcp.Checksum.digest_strings [ Bytes.unsafe_to_string buf; payload ]
          in
          Bytes.set_uint16_be buf 2 chk;
          let pkt = Bytes.unsafe_to_string buf in
          let pkt = IPv4.Writer.of_strings ipv4 [ pkt; payload ] in
          let result = IPv4.write ipv4 dst ~protocol:1 pkt in
          let err _ =
            Log.err (fun m -> m "Impossible to send ICMPv4 echo-reply packet")
          in
          let _ = Result.map_error err result in
          ()
      | _ -> Log.debug (fun m -> m "Ignore ICMPv4 packet")
      end

type t = {
    mutex: Miou.Mutex.t
  ; condition: Miou.Condition.t
  ; queue: (IPv4.packet * string) Queue.t
  ; ipv4: IPv4.t
  ; orphans: unit Miou.orphans
}

let rec clean orphans =
  match Miou.care orphans with
  | None | Some None -> ()
  | Some (Some prm) -> (
      match Miou.await prm with
      | Ok () -> clean orphans
      | Error exn ->
          Log.err (fun m ->
              m "Unexpected exception from an ICMPv4 task: %s"
                (Printexc.to_string exn));
          clean orphans)

let rec handler t =
  clean t.orphans;
  let todo =
    Miou.Mutex.protect t.mutex @@ fun () ->
    while Queue.is_empty t.queue do
      Miou.Condition.wait t.condition t.mutex
    done;
    let todo = Queue.create () in
    Queue.transfer t.queue todo;
    todo
  in
  let fn (pkt, payload) =
    ignore (Miou.async ~orphans:t.orphans @@ fun () -> input t.ipv4 pkt payload)
  in
  Queue.iter fn todo; handler t

type daemon = unit Miou.t * t

let handler ipv4 : daemon =
  let mutex = Miou.Mutex.create () in
  let condition = Miou.Condition.create () in
  let queue = Queue.create () in
  let orphans = Miou.orphans () in
  let t = { mutex; condition; queue; ipv4; orphans } in
  (Miou.async (fun () -> handler t), t)

let kill (prm, _) = Miou.cancel prm

let transfer (_, t) (pkt, payload) =
  let payload =
    match payload with
    | IPv4.Slice bstr -> Slice_bstr.to_string bstr
    | IPv4.String str -> str
  in
  Miou.Mutex.protect t.mutex @@ fun () ->
  Queue.push (pkt, payload) t.queue;
  Miou.Condition.signal t.condition
