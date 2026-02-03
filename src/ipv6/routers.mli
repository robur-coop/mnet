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
end

type t
(** A list of routers to which packets may be sent. Entries point to entries in
    the {!type:Neighbors.t}; the algorithm for selecting a default router favors
    routers known to be reachable over those whose reachability is suspect. Each
    entry also has an associated invalidation timer value (extracted from
    {!type:RA.t}) used to delete entries that are no longer advertised. *)

val make : int -> t

val tick :
     t
  -> now:int
  -> [> `RA of Ipaddr.V6.t * Ipaddr.V6.t * RA.t ]
  -> Ipaddr.V6.t list * t

val select :
     t
  -> is_reachable:(Ipaddr.V6.t -> bool)
  -> Ipaddr.V6.t
  -> Ipaddr.V6.t * int option * t
