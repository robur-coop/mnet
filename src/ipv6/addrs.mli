type t

val make :
     now:int
  -> iid:string
  -> ?addr:Ipaddr.V6.Prefix.t
  -> int
  -> t * Neighbors.Packet.t

val tick :
     t
  -> now:int
  -> iid:string
  -> [> `NA of Ipaddr.V6.t * Ipaddr.V6.t * Neighbors.NA.t
     | `RA of Ipaddr.V6.t * Ipaddr.V6.t * Routers.RA.t ]
  -> t * Neighbors.Packet.t list

val is_my_addr : t -> Ipaddr.V6.t -> bool
val select : t -> Ipaddr.V6.t -> Ipaddr.V6.t
