module SBstr = Slice_bstr

type packet = { size: int; filler: Bstr.t -> int }
type t
type action = [ Neighbors.action | `Send of Macaddr.t * int option * packet ]

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

val tick : t -> now:int -> event -> t * action list

val send :
     t
  -> now:int
  -> Ipaddr.V6.t
  -> packet
  -> (t * action list, [> `Packet_too_big ]) result

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
