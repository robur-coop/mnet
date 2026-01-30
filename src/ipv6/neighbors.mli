module NA : sig
  type t = {
      router: bool
    ; solicited: bool
    ; override: bool
    ; target: Ipaddr.V6.t
    ; tlla: Macaddr.t option
  }
end

module NS : sig
  type t = { target: Ipaddr.V6.t; slla: Macaddr.t option }
end

type t
(** A set of entries about individual neighbors to which traffic has been sent
    recently. Entries are keyed on the neighbor's on-link unicast IP address and
    contain such information as its link-layer address, a flag indicating
    whether the neighbor is a router or a host (see {!val:is_router}), a pointer
    to any queued packets waiting for address resolution to complete, etc. A
    Neighbor Cache entry also contains information used by the Neighbor
    Unreachability Detection algorithm, including the reachability state, the
    number of unanswered probes, and the time the next Neighbor Unreachability
    Detection event is scheduled to take place. *)

type action =
  [ `Send_ICMPv6_neighbor_unreachable
  | `Send_NS of [ `Unspecified | `Specified ] * Ipaddr.V6.t * Ipaddr.V6.t
  | `Send_queued_packets of Ipaddr.V6.t
  | `Cancel of Ipaddr.V6.t ]

val tick :
     t
  -> now:int
  -> [> `NA of Ipaddr.V6.t * Ipaddr.V6.t * NA.t
     | `NS of Ipaddr.V6.t * Ipaddr.V6.t * NS.t ]
  -> action list * t

val lladdr : t -> Ipaddr.V6.t -> Macaddr.t option
(** [lladdr t addr] tries to find the Link-Layer address of the given IPv6
    address [addr] from [t]. *)

val query : t -> now:int -> Ipaddr.V6.t -> t * Macaddr.t option * action list
val is_reachable : t -> Ipaddr.V6.t -> bool
val is_router : t -> Ipaddr.V6.t -> bool option
