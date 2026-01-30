(* The objective of this module is to have a KV store in which certain data is
   {i disposable}. In general, when it comes to network configuration, we always
   have two sources for the same type of information:
   - the user source, which we can trust
   - the network, which can provide us with the same type of information

   The information from the latter may be useful to keep, but we must prevent an
   attacker from causing an [Out_of_memory] error by sending the packets we want
   to keep.

   This table therefore separates the values into two types: those that are
   disposable (i.e. coming from the network) and those that the user wishes to
   define. With each {!val:Make.add}, we {i clean up} those that are disposable.
 *)

module type V = sig
  type t

  val is_disposable : t -> bool
end

module Make (K : Hashtbl.HashedType) (V : V) : sig
  type t
  type key = K.t
  type value = V.t

  val create : int -> t
  val add : t -> key -> value -> unit
  val find : t -> key -> value
  val remove : t -> key -> unit
  val fold : (key -> value -> 'acc -> 'acc) -> t -> 'acc -> 'acc
  val reset : t -> unit
  val iter : (key -> value -> unit) -> t -> unit
end
