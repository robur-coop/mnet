let src = Logs.Src.create "mnet.ethernet"

module Log = (val Logs.src_log src : Logs.LOG)

module Packet = struct
  type protocol = ARPv4 | IPv4 | IPv6
  type t = { src: Macaddr.t; dst: Macaddr.t; protocol: protocol option }

  let guard err fn = if fn () then Ok () else Error err

  let protocol_of_int = function
    | 0x0806 -> Some ARPv4
    | 0x0800 -> Some IPv4
    | 0x86dd -> Some IPv6
    | _ -> None

  let protocol_to_int = function
    | ARPv4 -> 0x0806
    | IPv4 -> 0x0800
    | IPv6 -> 0x86dd

  let decode bstr ~len =
    let ( let* ) = Result.bind in
    let* () = guard `Invalid_ethernet_packet @@ fun () -> len >= 14 in
    let dst = Macaddr.of_octets_exn (Bstr.sub_string bstr ~off:0 ~len:6) in
    let src = Macaddr.of_octets_exn (Bstr.sub_string bstr ~off:6 ~len:6) in
    let protocol = Bstr.get_uint16_be bstr 12 in
    let protocol = protocol_of_int protocol in
    let payload = Slice_bstr.make ~off:14 ~len:(len - 14) bstr in
    Ok ({ src; dst; protocol }, payload)

  let encode_into t ?(off = 0) bstr =
    match t.protocol with
    | None ->
        Fmt.invalid_arg
          "Ethernet.Packet.encode_into: you must specify a protocol"
    | Some protocol ->
        let protocol = protocol_to_int protocol in
        Bstr.blit_from_string (Macaddr.to_octets t.dst) ~src_off:0 bstr
          ~dst_off:(off + 0) ~len:6;
        Bstr.blit_from_string (Macaddr.to_octets t.src) ~src_off:0 bstr
          ~dst_off:(off + 6) ~len:6;
        Bstr.set_uint16_be bstr 12 protocol
end

type protocol = Packet.protocol = ARPv4 | IPv4 | IPv6

type t = {
    net: Mkernel.Net.t
  ; mutable handler: handler
  ; mtu: int
  ; mac: Macaddr.t
  ; tags: Logs.Tag.set
  ; bstr_ic: Bstr.t
  ; bstr_oc: Bstr.t
  ; extern: extern option
  ; cnt: int Atomic.t
}

and 'a packet = {
    src: Macaddr.t option
  ; dst: Macaddr.t
  ; protocol: Packet.protocol
  ; payload: 'a
}

and extern = External : 'net hypercalls -> extern [@@unboxed]

and 'net hypercalls = {
    device: 'net
  ; swr: 'net -> ?off:int -> ?len:int -> Bstr.t -> unit
  ; srd: 'net -> ?off:int -> ?len:int -> Bstr.t -> int
}

and handler = Slice_bstr.t packet -> unit

exception Packet_ignored

let mac { mac; _ } = mac
let uninteresting_packet _ = raise_notrace Packet_ignored

let write_directly_into t ?len:plus (packet : (Bstr.t -> int) packet) =
  let fn = packet.payload in
  let src = Option.value ~default:t.mac packet.src in
  let tags = Logs.Tag.add Tags.mac src Logs.Tag.empty in
  let pkt = { Packet.src; dst= packet.dst; protocol= Some packet.protocol } in
  Packet.encode_into pkt ~off:0 t.bstr_oc;
  let bstr = Bstr.sub t.bstr_oc ~off:14 ~len:(Bstr.length t.bstr_oc - 14) in
  let plus' = fn bstr in
  Option.iter (fun plus -> assert (plus = plus')) plus;
  Log.debug (fun m ->
      m ~tags "write ethernet packet src:%a -> dst:%a (%d byte(s))" Macaddr.pp
        src Macaddr.pp packet.dst plus');
  Log.debug (fun m ->
      m ~tags "@[<hov>%a@]"
        (Hxd_string.pp Hxd.default)
        (Bstr.sub_string t.bstr_oc ~off:0 ~len:(14 + plus')));
  (* TODO(dinosaure): we must figure out about the impact of such branch. We
     also should compare when we directly use [Mkernel.net.write] or if we can
     wrap [read]/[write] into an [External] value (to simplify the API). *)
  match t.extern with
  | None ->
      (* TODO(dinosaure): use [Mkernel.Net.write_into]. *)
      Mkernel.Net.write_bigstring t.net ~off:0 ~len:(14 + plus') t.bstr_oc
  | Some (External { device; swr; _ }) ->
      swr device ~off:0 ~len:(14 + plus') t.bstr_oc

let of_interest t dst =
  Macaddr.compare dst t.mac == 0 || Macaddr.is_unicast dst == false

let handler t bstr ~len =
  if len >= 14 then
    let tags = t.tags in
    match Packet.decode bstr ~len with
    | Error _ ->
        let str = Bstr.sub_string t.bstr_ic ~off:0 ~len in
        Log.err (fun m -> m ~tags "Invalid Ethernet packet");
        Log.err (fun m -> m ~tags "@[<hov>%a@]" (Hxd_string.pp Hxd.default) str)
    | Ok ({ Packet.protocol= Some protocol; src; dst }, payload) -> begin
        try
          if of_interest t dst then
            t.handler { src= Some src; dst; protocol; payload }
        with
        | Packet_ignored -> ()
        | exn ->
            Log.err (fun m ->
                m ~tags "Unexpected exception from the user's handler: %s"
                  (Printexc.to_string exn))
      end
    | Ok _ -> ()

let rec daemon t =
  let len =
    match t.extern with
    | None -> Mkernel.Net.read_bigstring t.net t.bstr_ic
    | Some (External { device; srd; _ }) -> srd device t.bstr_ic
  in
  handler t t.bstr_ic ~len; daemon t

let write_directly_into t ?len ?src ~dst ~protocol fn =
  let pkt = { src; dst; protocol; payload= fn } in
  write_directly_into t ?len pkt

let guard err fn = if fn () then Ok () else Error err

type daemon = unit Miou.t

let create ?(mtu = 1500) ?(handler = uninteresting_packet) mac net =
  let ( let* ) = Result.bind in
  let* () = guard `MTU_too_small @@ fun () -> mtu > 14 in
  (* enough for Ethernet packets *)
  let bstr_ic = Bstr.create (14 + mtu) in
  let bstr_oc = Bstr.create (14 + mtu) in
  (* NOTE(dinosaure): the first [Bstr.sub] does a [malloc()], then any
     [Bstr.sub] are cheap. We should use [Slice] instead of [Bstr]. TODO! *)
  let bstr_ic = Bstr.sub bstr_ic ~off:0 ~len:(14 + mtu) in
  let bstr_oc = Bstr.sub bstr_oc ~off:0 ~len:(14 + mtu) in
  let tags = Logs.Tag.empty in
  let tags = Logs.Tag.add Tags.mac mac tags in
  let extern = None in
  let cnt = Atomic.make 0 in
  let t = { net; handler; mtu; mac; tags; bstr_ic; bstr_oc; extern; cnt } in
  let daemon = Miou.async @@ fun () -> daemon t in
  Ok (daemon, t)

let mtu { mtu; _ } = mtu
let macaddr { mac; _ } = mac
let tags { tags; _ } = tags

let set_handler t handler =
  Atomic.incr t.cnt;
  t.handler <- handler;
  let tags = t.tags in
  if Atomic.get t.cnt > 1 then
    Log.warn (fun m -> m ~tags "Ethernet handler modified more than once")

let extend_handler_with t handler =
  let handler pkt = try t.handler pkt with Packet_ignored -> handler pkt in
  t.handler <- handler

let kill = Miou.cancel
