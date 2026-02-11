type state

type error =
  [ `Route_not_found | `Destination_unreachable of int | `Packet_too_big ]

val create : IPv4.t -> IPv6.t -> state

val recvfrom :
     state
  -> ?src:Ipaddr.t
  -> port:int
  -> ?off:int
  -> ?len:int
  -> ?trigger:Miou.Trigger.t
  -> bytes
  -> int * (Ipaddr.t * int)

val sendto :
     state
  -> dst:Ipaddr.t
  -> ?src_port:int
  -> port:int
  -> ?off:int
  -> ?len:int
  -> string
  -> (unit, [> error ]) result

val sendfn :
     state
  -> dst:Ipaddr.t
  -> ?src_port:int
  -> port:int
  -> len:int
  -> (Slice_bstr.t -> unit)
  -> (unit, [> error ]) result

val handler_ipv4 : state -> IPv4.packet * IPv4.payload -> unit
