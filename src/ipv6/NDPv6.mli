module SBstr = Slice_bstr

module Packet : sig
  type t = { dst: Macaddr.t; len: int; fn: Bstr.t -> unit }
  type user's_packet = { len: int; fn: Bstr.t -> unit }
end

module RS : sig
  val encode_into : mac:Macaddr.t -> (Ipaddr.V6.t -> Ipaddr.V6.t) -> Packet.t
end

module Fragment : sig
  type t = { uid: int; off: int; protocol: int; payload: SBstr.t; last: bool }
end

type mode = Random | EUI64 | Static of Ipaddr.V6.Prefix.t
type t

val make : now:int -> lmtu:int -> mac:Macaddr.t -> mode -> t * Packet.t list
val src : t -> ?src:Ipaddr.V6.t -> Ipaddr.V6.t -> Ipaddr.V6.t
val addresses : t -> Ipaddr.V6.Prefix.t list

type event =
  [ `Packet of int * Ipaddr.V6.t * Ipaddr.V6.t * SBstr.t
  | `Destination_unreachable of Dsts.Unreachable.t
  | `NA of Ipaddr.V6.t * Ipaddr.V6.t * Neighbors.NA.t
  | `NS of Ipaddr.V6.t * Ipaddr.V6.t * Neighbors.NS.t
  | `Packet_too_big of Dsts.PTB.t
  | `Ping of Ipaddr.V6.t * Ipaddr.V6.t * int * int * SBstr.t
  | `Pong of SBstr.t
  | `RA of Ipaddr.V6.t * Ipaddr.V6.t * Routers.RA.t
  | `Redirect of Ipaddr.V6.t * Dsts.Redirect.t
  | `Fragment of Ipaddr.V6.t * Ipaddr.V6.t * Fragment.t
  | `Tick ]

val tick : t -> now:int -> event -> t * Packet.t list

val next_hop :
     t
  -> Ipaddr.V6.t
  -> ( t * Ipaddr.V6.t * int option
     , [> `Packet_too_big | `Destination_unreachable of int ] )
     result

val send :
     t
  -> now:int
  -> dst:Ipaddr.V6.t
  -> Ipaddr.V6.t
  -> Packet.user's_packet list
  -> t * Packet.t list

type error =
  [ `Bad_version
  | `Drop
  | `ICMP_error of int * int * int
  | `Invalid_ICMP_checksum
  | `Msg of string
  | `Parameter_problem
  | `Time_exceeded
  | `Truncated
  | `Unknown_ICMP_packet of int ]

val pp_error : error Fmt.t
val decode : t -> SBstr.t -> (event, [> error ]) result
