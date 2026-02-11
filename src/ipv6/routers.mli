(** IPv6 default router list.

    The default router list
    ({{:https://www.rfc-editor.org/rfc/rfc4861#section-5.1} RFC 4861 Section
      5.1}) maintains the set of routers to which packets may be forwarded.
    Entries are populated from Router Advertisements and have associated
    invalidation timers.

    The router selection algorithm ({!val:select}) favors routers known to be
    reachable (via the {!module:Neighbors} cache) over those whose reachability
    is suspect. *)

(** {1 Router Advertisement} *)

module RA : sig
  type t = {
      current_hop_limit: int
    ; preference: int
    ; router_lifetime: int
    ; reachable_time: int option
    ; retrans_timer: int option
    ; slla: Macaddr.t option
    ; lmtu: int option
    ; prefix: Prefixes.Pfx.t list
  }

  val pp : t Fmt.t
end

(** {1 Router list} *)

type t
(** A list of routers to which packets may be sent. Entries point to entries in
    the {!type:Neighbors.t}; the algorithm for selecting a default router favors
    routers known to be reachable over those whose reachability is suspect. Each
    entry also has an associated invalidation timer value (extracted from
    {!type:RA.t}) used to delete entries that are no longer advertised. *)

val make : int -> t
(** [make capacity] creates an empty router list with the given initial
    capacity. *)

val mem : t -> Ipaddr.V6.t -> bool
(** [mem t addr] returns [true] if [addr] is in the router list. *)

val tick :
     t
  -> now:int
  -> [> `RA of Ipaddr.V6.t * Ipaddr.V6.t * RA.t ]
  -> Ipaddr.V6.t list * t
(** [tick t ~now event] processes a Router Advertisement event and returns the
    list of expired (invalidated) router addresses along with the updated router
    list. New routers are added; existing routers have their lifetimes
    refreshed. *)

val select :
     t
  -> is_reachable:(Ipaddr.V6.t -> bool)
  -> Ipaddr.V6.t
  -> Ipaddr.V6.t * int option * t
(** [select t ~is_reachable dst] selects the best default router for reaching
    [dst]. The algorithm prefers routers whose [is_reachable] returns [true].
    Returns [(router_addr, pmtu, t')] where [pmtu] is the Path MTU if known. *)
