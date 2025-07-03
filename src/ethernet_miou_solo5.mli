module Packet : sig
  type protocol = ARPv4 | IPv4 | IPv6
  type t = { src: Macaddr.t; dst: Macaddr.t; protocol: protocol option }

  val decode :
       Bstr.t
    -> len:int
    -> (t * Slice_bstr.t, [> `Invalid_ethernet_packet ]) result

  val encode_into : t -> ?off:int -> Bstr.t -> unit
end

type t
type daemon

val mac : t -> Macaddr.t

type protocol = Packet.protocol = ARPv4 | IPv4 | IPv6

type 'a packet = {
    src: Macaddr.t option
  ; dst: Macaddr.t
  ; protocol: protocol
  ; payload: 'a
}

type handler = Slice_bstr.t packet -> unit

val write_directly_into :
     t
  -> ?src:Macaddr.t
  -> dst:Macaddr.t
  -> protocol:protocol
  -> (Bstr.t -> int)
  -> unit

val create :
     ?mtu:int
  -> ?handler:(Slice_bstr.t packet -> unit)
  -> Macaddr.t
  -> Miou_solo5.Net.t
  -> (daemon * t, [> `MTU_too_small ]) result
(** NOTE(dinosaure): Note that the handler managing the Ethernet frames does not
    run cooperatively but from the main task that manages all the I/O. In other
    words, it is not possible to write a new frame from the [handler]. This must
    be done "outside" (in another task), otherwise a deadlock may occur. *)

val kill : daemon -> unit
val mtu : t -> int
val macaddr : t -> Macaddr.t
val set_handler : t -> handler -> unit
