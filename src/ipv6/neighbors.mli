(** IPv6 Neighbor Cache.

    The Neighbor Cache ({{:https://www.rfc-editor.org/rfc/rfc4861#section-5.1} RFC 4861 Section 5.1}})
    stores information about individual neighbors to which traffic has been sent
    recently. Each entry maps an IPv6 address to its link-layer (MAC) address,
    along with reachability state used by the Neighbor Unreachability Detection
    (NUD) algorithm.

    When a packet needs to be sent to a neighbor whose MAC address is unknown,
    a Neighbor Solicitation is sent and the packet is queued until a Neighbor
    Advertisement is received. *)

module Packet : sig
  type t = {
      lladdr: Macaddr.t
    ; dst: Ipaddr.V6.t
    ; len: int
    ; fn: src:Ipaddr.V6.t -> Bstr.t -> unit
  }
end

module NA : sig
  type t = {
      router: bool
    ; solicited: bool
    ; override: bool
    ; target: Ipaddr.V6.t
    ; tlla: Macaddr.t option
  }

  val pp : t Fmt.t
end

(** {1 Neighbor Solicitation} *)

module NS : sig
  type t = { target: Ipaddr.V6.t; slla: Macaddr.t option }

  val pp : t Fmt.t

  val encode_into : lladdr:Macaddr.t -> dst:Ipaddr.V6.t -> t -> Packet.t
  (** [encode_into ~lladdr ~dst ns] creates an outgoing Neighbor Solicitation
      packet destined to [dst] via link-layer address [lladdr]. *)
end

(** {1 Neighbor Cache} *)

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

val make : int -> t
(** [make capacity] creates a new neighbor cache with the given initial
    [capacity]. *)

(** Actions produced by {!val:tick} and {!val:query}.
    - [Packet pkt]: send [pkt] to the network.
    - [Cancel addr]: cancel pending operations for [addr] (neighbor resolution
      failed after all retries).
    - [Release_with (addr, mac)]: the link-layer address for [addr] has been
      resolved to [mac]; queued packets can now be sent. *)
type action =
  | Packet of Packet.t
  | Cancel of Ipaddr.V6.t
  | Release_with of Ipaddr.V6.t * Macaddr.t

val tick :
     t
  -> mac:Macaddr.t
  -> now:int
  -> [> `NA of Ipaddr.V6.t * Ipaddr.V6.t * NA.t
     | `NS of Ipaddr.V6.t * Ipaddr.V6.t * NS.t ]
  -> action list * t
(** [tick t ~mac ~now event] processes an NDPv6 event and returns a list of
    actions and the updated cache. Neighbor Advertisements update existing
    entries; Neighbor Solicitations may trigger a reply. *)

val lladdr : t -> Ipaddr.V6.t -> Macaddr.t option
(** [lladdr t addr] looks up the link-layer (MAC) address of [addr] in the
    cache. Returns [None] if the address is not cached. *)

val query :
     t
  -> mac:Macaddr.t
  -> now:int
  -> Ipaddr.V6.t
  -> t * Macaddr.t option * action option
(** [query t ~mac ~now addr] looks up or initiates resolution of the link-layer
    address for [addr].
    - If the address is cached and reachable, returns [Some mac].
    - If the address is not cached, returns [None] and an action to send a
      Neighbor Solicitation. *)

val is_reachable : t -> Ipaddr.V6.t -> bool
(** [is_reachable t addr] returns [true] if [addr] is in the cache and its
    reachability state indicates it is currently reachable. Used by the router
    selection algorithm to prefer reachable routers. *)

val is_router : t -> Ipaddr.V6.t -> bool option
(** [is_router t addr] returns [Some true] if [addr] is a known router,
    [Some false] if it is a known host, or [None] if [addr] is not in the cache.
*)

(**/**)

val cs_of_len_and_protocol : len:int -> protocol:int -> Cstruct.t
