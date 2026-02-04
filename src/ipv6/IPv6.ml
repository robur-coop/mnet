let src = Logs.Src.create "mnet.ipv6"

module SBstr = Slice_bstr
module Log = (val Logs.src_log src : Logs.LOG)

module Packet = struct
  let _unsafe_hdr_into ?(hop_limit = 64) src dst ~protocol ?(off = 0) bstr =
    Bstr.set_int32_be bstr (off + 0) 0x60000000l;
    Bstr.set_uint16_be bstr (off + 4) 0;
    Bstr.set_uint8 bstr (off + 6) protocol;
    Bstr.set_uint8 bstr (off + 7) hop_limit;
    let src = Ipaddr.V6.to_string src in
    Bstr.blit_from_string src ~src_off:0 bstr ~dst_off:(off + 8) ~len:16;
    let dst = Ipaddr.V6.to_string dst in
    Bstr.blit_from_string dst ~src_off:0 bstr ~dst_off:(off + 24) ~len:16
end

let ( let* ) = Result.bind

type handler = protocol:int -> Ipaddr.V6.t -> Ipaddr.V6.t -> SBstr.t -> unit

type t = {
    eth: Ethernet.t
  ; mutable ndpv6: NDPv6.t
  ; lmtu: int
  ; tags: Logs.Tag.set
  ; mutable handler: handler
  ; cnt: int Atomic.t
}

type daemon = unit Miou.t

let write eth { NDPv6.Packet.dst; len; fn } =
  let fn bstr = fn bstr; len in
  let protocol = Ethernet.IPv6 in
  Ethernet.write_directly_into eth ~len ~dst ~protocol fn

let ignore ~protocol:_ _src _dst _payload = ()
let _1s = 1_000_000_000

let rec daemon t =
  let now = Mkernel.clock_monotonic () in
  let ndpv6, outs = NDPv6.tick t.ndpv6 ~now `Tick in
  t.ndpv6 <- ndpv6;
  List.iter (write t.eth) outs;
  Mkernel.sleep _1s;
  daemon t

let kill = Miou.cancel

let create ~now ?(handler = ignore) eth =
  let lmtu = Ethernet.mtu eth in
  let mac = Ethernet.mac eth in
  let ndpv6, pkts = NDPv6.make ~now ~lmtu ~mac in
  List.iter (write eth) pkts;
  let tags = Logs.Tag.empty in
  let cnt = Atomic.make 0 in
  let t = { eth; ndpv6; lmtu; tags; handler; cnt } in
  let daemon = Miou.async @@ fun () -> daemon t in
  Ok (t, daemon)

let set_handler t handler =
  Atomic.incr t.cnt;
  t.handler <- handler;
  if Atomic.get t.cnt > 1 then
    Log.warn (fun m -> m ~tags:t.tags "IPv6 handler modified more than once")

(*
let segment_and_coalesce ~mtu seq =
  let max = mtu - 48 in
  let buf = Bytes.create max in
  let rec go buf_pos seq () =
    match seq () with
    | Seq.Nil ->
        if buf_pos = 0 then Seq.Nil
        else
          let last = Bytes.sub_string buf 0 buf_pos in
          Seq.Cons (last, Seq.empty)
    | Seq.Cons (str, next) -> fill pos str next ()
  and fill buf_pos str next () =
    let str_len = String.length str in
    let rem = max - pos in
    if str_len <= rem then begin
      Bytes.blit_string str 0 buf buf_pos str_len;
      if buf_pos + str_len = max then Seq.Cons (Bytes.to_string buf, go 0 next)
      else go (buf_pos + str_len) next ()
    end
    else begin
      Bytes.blit_string str 0 buf pos rem;
      let rem_str = String.sub str rem (str_len - rem) in
      Seq.Cons (Bytes.to_string buf, fun () -> fill 0 rem_str next ())
    end
  in
  go 0 seq

let _to_chunks ~mtu seq =
  let seq = segment_and_coalesce ~mtu seq in
  match seq () with
  | Seq.Nil -> None (* nothing to encode *)
  | Seq.Cons (x0, rem) -> begin
      assert (String.length x0 <= mtu - 48);
      match rem () with
      | Seq.Nil ->
          (* no fragmentation *)
          let len = String.length x0 in
          let fn bstr =
            Bstr.blit_from_string x0 ~src_off:0 bstr ~dst_off:0 ~len;
            len
          in
          Some (Seq.singleton fn)
      | Seq.Cons (x1, rem) when String.length x1 <= 8 && Seq.is_empty rem ->
          (* no fragmentation *)
          let len0 = String.length x0 in
          let len1 = String.length x1 in
          let fn bstr =
            Bstr.blit_from_string x0 ~src_off:0 bstr ~dst_off:0 ~len:len0;
            Bstr.blit_from_string x1 ~src_off:0 bstr ~dst_off:len0 ~len:len1;
            len0 + len1
          in
          Some (Seq.singleton fn)
      | Seq.Cons (x1, rem) ->
          (* fragmentation *)
          let seq = Seq.cons x0 (Seq.cons x1 rem) in
          let fn str =
            let len = String.length str in
            assert (len <= mtu - 48);
            let fn bstr =
              Bstr.blit_from_string str ~src_off:0 bstr ~dst_off:0 ~len;
              len
            in
            fn
          in
          Some (Seq.map fn seq)
    end
*)

let with_hdr ~src ~dst ~protocol ~len fn =
  let fn bstr =
    Bstr.set_int32_be bstr 0 0x60000000l;
    Bstr.set_uint16_be bstr 4 len;
    Bstr.set_uint8 bstr 6 protocol;
    Bstr.set_uint8 bstr 7 64 (* HOP limit *);
    let src = Ipaddr.V6.to_octets src in
    Bstr.blit_from_string src ~src_off:0 bstr ~dst_off:8 ~len:16;
    let dst = Ipaddr.V6.to_octets dst in
    Bstr.blit_from_string dst ~src_off:0 bstr ~dst_off:24 ~len:16;
    fn (Bstr.shift bstr 40)
  in
  fn

let into ~mtu ~src ~dst ~protocol ~len user's_fn =
  if len > mtu - 40 then begin
    let bstr = Bstr.create len in
    let tmp = Bytes.create 4 in
    Mirage_crypto_rng.generate_into tmp ~off:0 4;
    let uid = Bytes.get_int32_ne tmp 0 in
    user's_fn bstr;
    let max = mtu - 48 in
    let rec go acc src_off =
      if len - src_off <= 0 then List.rev acc
      else
        let chunk = Int.min max (len - src_off) in
        let last = if src_off + chunk >= len then true else false in
        let fn dst =
          Bstr.set_uint8 dst 0 protocol;
          Bstr.set_uint8 dst 1 0;
          let v = (src_off / 8) lsl 3 in
          let v = if last then v else v lor 1 in
          Bstr.set_uint16_be dst 2 v;
          Bstr.set_int32_be dst 4 uid;
          Bstr.blit bstr ~src_off dst ~dst_off:8 ~len:chunk
        in
        let fn = with_hdr ~src ~dst ~protocol:44 ~len:chunk fn in
        go ({ NDPv6.Packet.len= chunk + 48; fn } :: acc) (src_off + chunk)
    in
    go [] 0
  end
  else
    let fn = with_hdr ~src ~dst ~protocol ~len user's_fn in
    [ { NDPv6.Packet.len= len + 40; fn } ]

let at_most_one = function [] | [ _ ] -> true | _ -> false

let write_directly t ~now ?src dst ~protocol ~len user's_fn =
  let src = NDPv6.src t.ndpv6 ?src dst in
  let* ndpv6, next_hop, mtu = NDPv6.next_hop t.ndpv6 dst in
  match mtu with
  | None ->
      (* NOTE(dinosaure): we try with MTU=Link-MTU (generally, 1500). However,
         this PMTU may fail for the intended destination. The only valid PMTU in
         all cases is 1280. *)
      let mtu = t.lmtu in
      let pkts = into ~mtu ~src ~dst ~protocol ~len user's_fn in
      (* NOTE(dinosaure): we should never fragment a TCP packet. *)
      if protocol = 6 (* TCP *) && not (at_most_one pkts) then
        Log.warn (fun m -> m "Fragmentation of IPv6/TCP packets");
      let ndpv6, outs = NDPv6.send ndpv6 ~now ~dst next_hop pkts in
      List.iter (write t.eth) outs;
      t.ndpv6 <- ndpv6;
      Ok ()
  | Some mtu ->
      let pkts = into ~mtu ~src ~dst ~protocol ~len user's_fn in
      let ndpv6, outs = NDPv6.send ndpv6 ~now ~dst next_hop pkts in
      List.iter (write t.eth) outs;
      t.ndpv6 <- ndpv6;
      Ok ()

let input t pkt =
  match NDPv6.decode t.ndpv6 pkt.Ethernet.payload with
  | Error err ->
      Log.err (fun m -> m "Invalid IPv6 packet: %a" NDPv6.pp_error err);
      let str = SBstr.to_string pkt.Ethernet.payload in
      Log.err (fun m -> m "@[<hov>%a@]" (Hxd_string.pp Hxd.default) str)
  | Ok (`Default (protocol, src, dst, payload)) ->
      t.handler ~protocol src dst payload
  | Ok (`TCP (src, dst, payload)) -> t.handler ~protocol:6 src dst payload
  | Ok (`UDP (src, dst, payload)) -> t.handler ~protocol:17 src dst payload
  | Ok event ->
      let now = Mkernel.clock_monotonic () in
      let ndpv6, outs = NDPv6.tick ~now t.ndpv6 event in
      List.iter (write t.eth) outs;
      t.ndpv6 <- ndpv6
