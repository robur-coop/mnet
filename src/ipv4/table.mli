(** Key-value store with disposable entries.

    This module provides a hash table that separates values into two categories:
    - {i trusted} values: configured by the user (e.g. the local IP address in
      the ARP table). These are {b never} automatically evicted.
    - {i disposable} values: learned from the network (e.g. ARP replies from
      remote hosts). These can be evicted when new entries are added, preventing
      an attacker from causing an [Out_of_memory] error by flooding the network
      with entries.

    This distinction is critical for network protocol tables (like ARP) where
    information comes from two sources with different trust levels. *)

(** {1 Value interface} *)

module type V = sig
  type t

  val is_disposable : t -> bool
  (** [is_disposable v] returns [true] if [v] was learned from the network and
      can be safely evicted under memory pressure. Returns [false] for
      user-configured entries that must be preserved. *)
end

(** {1 Functor} *)

module Make (K : Hashtbl.HashedType) (V : V) : sig
  type t
  (** A mutable key-value store. *)

  type key = K.t
  type value = V.t

  val create : int -> t
  (** [create n] creates a new table with initial capacity [n]. *)

  val add : t -> key -> value -> unit
  (** [add t key value] binds [key] to [value]. If the table already contains
      disposable entries and is under memory pressure, some disposable entries
      may be evicted to make room. Trusted entries are never evicted. *)

  val find : t -> key -> value
  (** [find t key] returns the value bound to [key].

      @raise Not_found if [key] is not in the table. *)

  val remove : t -> key -> unit
  (** [remove t key] removes the binding for [key] (if any). *)

  val fold : (key -> value -> 'acc -> 'acc) -> t -> 'acc -> 'acc
  (** [fold fn t init] folds over all bindings in the table. *)

  val reset : t -> unit
  (** [reset t] removes {b all} bindings (both trusted and disposable). *)

  val iter : (key -> value -> unit) -> t -> unit
  (** [iter fn t] iterates over all bindings in the table. *)
end
