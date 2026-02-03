module SBstr = Slice_bstr

type t

val create : Ethernet.t -> (t, [> `MTU_too_small ]) result

val write_directly :
     t
  -> now:int
  -> ?src:Ipaddr.V6.t
  -> Ipaddr.V6.t
  -> protocol:int
  -> len:int
  -> (Bstr.t -> unit)
  -> (unit, [> `Packet_too_big | `Route_not_found ]) result

val input : t -> SBstr.t Ethernet.packet -> unit
