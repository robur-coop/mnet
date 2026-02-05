module SBstr = Slice_bstr

type t
type daemon
type payload = Slice of SBstr.t | String of string
type handler = protocol:int -> Ipaddr.V6.t -> Ipaddr.V6.t -> payload -> unit
type mode = Random | EUI64 | Static of Ipaddr.V6.Prefix.t

val create :
     now:int
  -> ?handler:handler
  -> Ethernet.t
  -> mode
  -> (t * daemon, [> `MTU_too_small ]) result

val kill : daemon -> unit
val set_handler : t -> handler -> unit

val write_directly :
     t
  -> now:int
  -> ?src:Ipaddr.V6.t
  -> Ipaddr.V6.t
  -> protocol:int
  -> len:int
  -> (Bstr.t -> unit)
  -> (unit, [> `Packet_too_big | `Destination_unreachable of int ]) result

val input : t -> SBstr.t Ethernet.packet -> unit
