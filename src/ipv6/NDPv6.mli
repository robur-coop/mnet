module SBstr = Slice_bstr

module Packet : sig
  type t = { dst: Macaddr.t; len: int; fn: Bstr.t -> unit }
  type user's_packet = { len: int; fn: Bstr.t -> unit }
end

type t

val make : lmtu:int -> t
val src : t -> ?src:Ipaddr.V6.t -> Ipaddr.V6.t -> Ipaddr.V6.t

type event =
  [ `Default of int * Ipaddr.V6.t * Ipaddr.V6.t * SBstr.t
  | `Drop
  | `NA of Ipaddr.V6.t * Ipaddr.V6.t * Neighbors.NA.t
  | `NS of Ipaddr.V6.t * Ipaddr.V6.t * Neighbors.NS.t
  | `Packet_too_big of Ipaddr.V6.t * Ipaddr.V6.t * int
  | `Ping of Ipaddr.V6.t * Ipaddr.V6.t * int * int * SBstr.t
  | `Pong of SBstr.t
  | `RA of Ipaddr.V6.t * Ipaddr.V6.t * Routers.RA.t
  | `Prefix of Prefixes.Pfx.t
  | `Redirect of Dsts.Redirect.t
  | `TCP of Ipaddr.V6.t * Ipaddr.V6.t * SBstr.t
  | `UDP of Ipaddr.V6.t * Ipaddr.V6.t * SBstr.t
  | `Tick ]

val tick : t -> now:int -> event -> t * Packet.t list

val next_hop :
     t
  -> Ipaddr.V6.t
  -> (t * Ipaddr.V6.t * int option, [> `Packet_too_big ]) result

val send :
     t
  -> now:int
  -> dst:Ipaddr.V6.t
  -> Ipaddr.V6.t
  -> Packet.user's_packet list
  -> t * Packet.t list

type error =
  [ `Bad_version
  | `Destination_unreachable
  | `Drop
  | `Drop_RS
  | `ICMP_error of int * int * int
  | `Invalid_ICMP_checksum
  | `Msg of string
  | `Parameter_problem
  | `Time_exceeded
  | `Truncated
  | `Unknown_ICMP_packet of int ]

val decode : t -> SBstr.t -> (event, [> error ]) result
