(** IPv6 on-link prefix list.

    The prefix list
    ({{:https://www.rfc-editor.org/rfc/rfc4861#section-5.1} RFC 4861 Section
      5.1}) maintains the set of IPv6 prefixes that are considered on-link. An
    address is on-link if it falls within one of these prefixes, meaning packets
    can be sent directly to the destination without going through a router.

    Entries are learned from Router Advertisements (the Prefix Information
    option) and have associated validity lifetimes. *)

(** {1 Prefix information} *)

module Pfx : sig
  type t = {
      on_link: bool
    ; autonomous: bool
    ; valid_lifetime: int option
    ; preferred_lifetime: int option
    ; prefix: Ipaddr.V6.Prefix.t
  }

  val pp : t Fmt.t
end

(** {1 Prefix list} *)

type t
(** A list of the prefixes that define a set of addresses that are on-link.
    Entries are created from information received in Router Advertisements (see
    {!val:Routers.RA.t}). Each entry has an associated invalidation timer value
    (extracted from the advertisement) used to expire prefixes when they become
    invalid. A special "infinity" timer value specifies that a prefix remains
    valid forever, unless a new (finite) value is received in a subsequent
    advertisement. *)

val make : int -> t
(** [make capacity] creates an empty prefix list with the given initial
    [capacity]. *)

val tick : t -> now:int -> Pfx.t list -> t
(** [tick t ~now pfxs] updates the prefix list with the prefixes [pfxs] received
    from a Router Advertisement. New prefixes are added; existing prefixes have
    their lifetimes refreshed. Expired prefixes are removed. *)

val is_local : t -> Ipaddr.V6.t -> bool
(** [is_local t addr] returns [true] if [addr] falls within any of the on-link
    prefixes in the list. On-link addresses can be reached directly (without
    routing through a default router). *)
