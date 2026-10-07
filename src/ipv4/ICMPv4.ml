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
  and k = Kind : 'a kind -> k
  and 'a message = 'a t

  let kind_of_int : int -> k option = function
    | 0 -> Some (Kind Echo_reply)
    | 3 -> Some (Kind Destination_unreachable)
    | 4 -> Some (Kind Source_quench)
    | 5 -> Some (Kind Redirect)
    | 8 -> Some (Kind Echo_request)
    | 11 -> Some (Kind Time_exceeded)
    | 12 -> Some (Kind Parameter_problem)
    | 13 -> Some (Kind Timestamp_request)
    | 14 -> Some (Kind Timestamp_reply)
    | 15 -> Some (Kind Information_request)
    | 16 -> Some (Kind Information_reply)
    | _ -> None

  let kind_to_int : type a. a kind -> int = function
    | Echo_reply -> 0
    | Destination_unreachable -> 3
    | Source_quench -> 4
    | Redirect -> 5
    | Echo_request -> 8
    | Time_exceeded -> 11
    | Parameter_problem -> 12
    | Timestamp_request -> 13
    | Timestamp_reply -> 14
    | Information_request -> 15
    | Information_reply -> 16

  (* NOTE(dinosaure): the rest-of-header is always 4 bytes. *)
  let decode_id_and_seq str off : id_and_seq =
    (String.get_uint16_be str off, String.get_uint16_be str (off + 2))

  let decode_shdr : type a. a kind -> string -> int -> a =
   fun kind str off ->
    match kind with
    | Echo_reply -> decode_id_and_seq str off
    | Echo_request -> decode_id_and_seq str off
    | Timestamp_request -> decode_id_and_seq str off
    | Timestamp_reply -> decode_id_and_seq str off
    | Information_request -> decode_id_and_seq str off
    | Information_reply -> decode_id_and_seq str off
    | Destination_unreachable -> Hop (String.get_uint16_be str (off + 2))
    | Source_quench -> Unused
    | Time_exceeded -> Unused
    | Redirect -> Ipaddr.V4.of_int32 (String.get_int32_be str off)
    | Parameter_problem -> Pointer (String.get_uint8 str off)

  let encode_id_and_seq ((id, seq) : id_and_seq) buf off =
    Bytes.set_uint16_be buf off id;
    Bytes.set_uint16_be buf (off + 2) seq

  let encode_shdr : type a. a kind -> a -> bytes -> int -> unit =
   fun kind shdr buf off ->
    match kind with
    | Echo_reply -> encode_id_and_seq shdr buf off
    | Echo_request -> encode_id_and_seq shdr buf off
    | Timestamp_request -> encode_id_and_seq shdr buf off
    | Timestamp_reply -> encode_id_and_seq shdr buf off
    | Information_request -> encode_id_and_seq shdr buf off
    | Information_reply -> encode_id_and_seq shdr buf off
    | Destination_unreachable ->
        let (Hop mtu) = shdr in
        Bytes.set_uint16_be buf off 0;
        Bytes.set_uint16_be buf (off + 2) mtu
    | Source_quench -> Bytes.set_int32_be buf off 0l
    | Time_exceeded -> Bytes.set_int32_be buf off 0l
    | Redirect -> Bytes.set_int32_be buf off (Ipaddr.V4.to_int32 shdr)
    | Parameter_problem ->
        let (Pointer ptr) = shdr in
        Bytes.set_int32_be buf off 0l;
        Bytes.set_uint8 buf off ptr

  let decode ?(off = 0) str =
    let len = String.length str - off in
    if off < 0 || len < 8 then invalid_arg "ICMPv4 packet too small";
    let pkt =
      match kind_of_int (String.get_uint8 str off) with
      | None -> invalid_arg "Unknown ICMPv4 type"
      | Some (Kind kind) ->
          let code = String.get_uint8 str (off + 1) in
          let checksum = String.get_uint16_be str (off + 2) in
          let shdr = decode_shdr kind str (off + 4) in
          Packet { kind; code; checksum; shdr }
    in
    if Utcp.Checksum.digest_string ~off ~len str != 0 then
      invalid_arg "Invalid ICMPv4 checksum";
    let payload = String.sub str (off + 8) (len - 8) in
    (pkt, payload)

  let decode ?off bstr =
    try Ok (decode ?off bstr)
    with exn ->
      Log.err (fun m ->
          m "Got an exception while decoding ICMPv4 packet: %s"
            (Printexc.to_string exn));
      Error `Invalid_ICMPv4_packet

  let to_bytes pkt =
    let buf = Bytes.create 8 in
    Bytes.set_uint8 buf 0 (kind_to_int pkt.kind);
    Bytes.set_uint8 buf 1 pkt.code;
    Bytes.set_uint16_be buf 2 pkt.checksum;
    encode_shdr pkt.kind pkt.shdr buf 4;
    buf
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
