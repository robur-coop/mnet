type t

val make : int -> t

type action =
  [ `Send_NS of [ `Unspecified | `Specified ] * Ipaddr.V6.t * Ipaddr.V6.t ]

val tick :
     t
  -> now:int
  -> [> `NA of Ipaddr.V6.t * Ipaddr.V6.t * Neighbors.NA.t ]
  -> t * Neighbors.Packet.t list

val is_my_addr : t -> Ipaddr.V6.t -> bool
val select : t -> Ipaddr.V6.t -> Ipaddr.V6.t
