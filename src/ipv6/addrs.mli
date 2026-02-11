(** IPv6 address management.

    This module manages the set of IPv6 addresses assigned to the local
    interface. It handles both link-local ([fe80::/10]) and global ([2000::/3])
    addresses. Addresses are generated based on the configured
    {!type:NDPv6.mode} and updated in response to Router Advertisement and
    Neighbor Advertisement events.

    The Interface Identifier (IID) is either random, derived from the MAC
    address (EUI-64), or user-specified. *)

type t
(** The set of configured IPv6 addresses. *)

val make :
     now:int
  -> iid:string
  -> ?addr:Ipaddr.V6.Prefix.t
  -> int
  -> t * Neighbors.Packet.t list
(** [make ~now ~iid ?addr lifetime] creates an initial address set.
    - [now] (nanoseconds): the current monotonic time.
    - [iid]: the Interface IDentifier (8 bytes) derived from the MAC address or
      generated randomly.
    - [addr]: an optional static IPv6 prefix to use (instead of waiting for
      Router Advertisements (which do not reach the unikernel directly).
    - [lifetime] (nanoseconds): the initial preferred lifetime for addresses.

    Some packets are also returned and must be sent. *)

val tick :
     t
  -> now:int
  -> iid:string
  -> [> `NA of Ipaddr.V6.t * Ipaddr.V6.t * Neighbors.NA.t
     | `RA of Ipaddr.V6.t * Ipaddr.V6.t * Routers.RA.t ]
  -> t * Neighbors.Packet.t list
(** [tick t ~now ~iid event] updates the address set in response to an NDPv6
    event. Router Advertisements may provide new prefixes for global address
    generation. Neighbor Advertisements may confirm duplicate addresses. *)

val is_my_addr : t -> Ipaddr.V6.t -> bool
(** [is_my_addr t addr] returns [true] if [addr] is one of the locally
    configured addresses (either link-local or global). *)

val select : t -> Ipaddr.V6.t -> Ipaddr.V6.t
(** [select t dst] selects a source address for communicating with [dst]. *)

val addresses : t -> Ipaddr.V6.Prefix.t list
(** [addresses t] returns all configured IPv6 address prefixes. *)
