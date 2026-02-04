module SBstr = Slice_bstr

type t
type handler = protocol:int -> Ipaddr.V6.t -> Ipaddr.V6.t -> SBstr.t -> unit

val create : ?handler:handler -> Ethernet.t -> (t, [> `MTU_too_small ]) result
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
