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

module Key = struct
  type t = { src: Ipaddr.V6.t; dst: Ipaddr.V6.t; uid: int; protocol: int }

  let equal a b =
    Ipaddr.V6.compare a.src b.src = 0
    && Ipaddr.V6.compare a.dst b.dst = 0
    && a.uid = b.uid

  let hash t = Hashtbl.hash (t.src, t.dst, t.uid)
end

module Fragments = Fragments.Make (Key)

type t = {
    eth: Ethernet.t
  ; mutable ndpv6: NDPv6.t
  ; fragments: Fragments.t
  ; lmtu: int
  ; tags: Logs.Tag.set
  ; mutable handler: handler
  ; cnt: int Atomic.t
}

and payload = Fragments.payload = Slice of SBstr.t | String of string
and handler = protocol:int -> Ipaddr.V6.t -> Ipaddr.V6.t -> payload -> unit
and daemon = unit Miou.t

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

type mode = NDPv6.mode = Random | EUI64 | Static of Ipaddr.V6.Prefix.t

let create ~now ?(handler = ignore) eth mode =
  let lmtu = Ethernet.mtu eth in
  let mac = Ethernet.mac eth in
  let ndpv6, pkts = NDPv6.make ~now ~lmtu ~mac mode in
  List.iter (write eth) pkts;
  let tags = Logs.Tag.empty in
  let cnt = Atomic.make 0 in
  let fragments = Fragments.create () in
  let t = { eth; ndpv6; lmtu; tags; handler; cnt; fragments } in
  let daemon = Miou.async @@ fun () -> daemon t in
  Ok (t, daemon)

let set_handler t handler =
  Atomic.incr t.cnt;
  t.handler <- handler;
  if Atomic.get t.cnt > 1 then
    Log.warn (fun m -> m ~tags:t.tags "IPv6 handler modified more than once")

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
    let max = (mtu - 48) / 8 * 8 in
    (* must be multiple of 8 *)
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
        let fn = with_hdr ~src ~dst ~protocol:44 ~len:(chunk + 8) fn in
        go ({ NDPv6.Packet.len= chunk + 48; fn } :: acc) (src_off + chunk)
    in
    go [] 0
  end
  else
    let fn = with_hdr ~src ~dst ~protocol ~len user's_fn in
    [ { NDPv6.Packet.len= len + 40; fn } ]

let at_most_one = function [] | [ _ ] -> true | _ -> false
let src t ~dst = NDPv6.src t.ndpv6 dst

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
  | Error (`Unknown_ICMP_packet _) -> ()
  | Error `Drop -> ()
  | Error err ->
      Log.err (fun m -> m "Invalid IPv6 packet: %a" NDPv6.pp_error err);
      let str = SBstr.to_string pkt.Ethernet.payload in
      Log.err (fun m -> m "@[<hov>%a@]" (Hxd_string.pp Hxd.default) str)
  | Ok (`Packet (protocol, src, dst, payload)) ->
      t.handler ~protocol src dst (Slice payload)
  | Ok
      (`Fragment (src, dst, { NDPv6.Fragment.protocol; uid; off; last; payload }))
    ->
      let now = Mkernel.clock_monotonic () in
      let key = { Key.src; dst; uid; protocol } in
      let len = SBstr.length payload in
      let pkt = Fragments.insert ~now t.fragments key ~off ~len ~last payload in
      let fn ({ Key.src; dst; protocol; _ }, payload) =
        t.handler ~protocol src dst payload
      in
      Option.iter fn pkt
  | Ok event ->
      let now = Mkernel.clock_monotonic () in
      let ndpv6, outs = NDPv6.tick ~now t.ndpv6 event in
      List.iter (write t.eth) outs;
      t.ndpv6 <- ndpv6
