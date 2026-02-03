module Pfx : sig
  type t = {
      on_link: bool
    ; autonomous: bool
    ; valid_lifetime: int option
    ; preferred_lifetime: int option
    ; prefix: Ipaddr.V6.Prefix.t
  }
end

type t
(** A list of the prefixes that define a set of addresses that are on-link.
    Entries are created from information received in Router Advertisements (see
    {!val:Routers.RA.t}). Each entry has an associated invalidation timer value
    (extracted from the advertisement) used to expire prefixes when they become
    invalid. A special "infinity" timer value specifies that a prefix remains
    valid forever, unless a new (finite) value is received in a subsequent
    advertisement. *)

val make : int -> t
val tick : t -> now:int -> Pfx.t list -> t
val is_local : t -> Ipaddr.V6.t -> bool
