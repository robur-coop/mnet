let src = Logs.Src.create "mnet.ipv6"
let guard err fn = if fn () then Ok () else Error err

module Log = (val Logs.src_log src : Logs.LOG)
module SBstr = Slice_bstr

module Packet = struct
  type 'a packet = {
      src: Ipaddr.V6.t
    ; dst: Ipaddr.V6.t
    ; length: int
    ; nhdr: int
    ; hlim: int
  }

  let decode slice =
    let ( let* ) = Result.bind in
    let version = SBstr.get_uint8 slice 0 in
    let* () = guard `Invalid_IPv6_packet @@ fun () -> version lsr 4 = 0b0110 in
    let length = SBstr.get_uint16_be slice 4 in
    let nhdr = SBstr.get_uint8 slice 6 in
    let hlim = SBstr.get_uint8 slice 7 in
    let src = SBstr.sub_string slice ~off:8 ~len:16 in
    let* src = Ipaddr.V6.of_octets src in
    let dst = SBstr.sub_string slice ~off:24 ~len:16 in
    let* dst = Ipaddr.V6.of_octets dst in
    let payload = SBstr.shift slice in
    let pkt = { src; dst; length; nhdr; hlim } in
    Ok (pkt, payload)
end
