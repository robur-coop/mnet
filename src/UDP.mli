type state

val create : IPv4.t -> IPv6.t -> state

val recvfrom :
     state
  -> ?src:Ipaddr.V4.t
  -> port:int
  -> ?off:int
  -> ?len:int
  -> ?trigger:Miou.Trigger.t
  -> bytes
  -> int * (Ipaddr.V4.t * int)

val sendto :
     state
  -> dst:Ipaddr.V4.t
  -> ?src_port:int
  -> port:int
  -> ?off:int
  -> ?len:int
  -> string
  -> (unit, [> `Route_not_found ]) result

val sendfn :
     state
  -> dst:Ipaddr.V4.t
  -> ?src_port:int
  -> port:int
  -> len:int
  -> (Slice_bstr.t -> unit)
  -> (unit, [> `Route_not_found ]) result

val handler : state -> IPv4.packet * IPv4.payload -> unit
