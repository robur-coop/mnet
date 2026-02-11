(** [Fragments] is a module that implements an IPv4/IPv6 packet reassembly
    algorithm with a limit on memory consumption (using an LRU) and lifetime.

    The first thing to note about IPv4 and IPv6 protocols is that fragmentation
    is usually quite rare (in the sense that the TCP or QUIC protocol should be
    able to exchange packets of the correct size). However, there may be cases
    of fragmentation. A fairly simple example to simulate fragmentation is to
    ping with a size greater than 1500 bytes (which is the default size for an
    Ethernet interface). *)

module SBstr = Slice_bstr

(** The type of content in an IPv4/IPv6 packet. It should be noted (the happy
    path) that if the data is a slice, it corresponds (without copying) to the
    Ethernet frame: this case signals to the user that there has been no
    fragmentation. Otherwise, the content is a reassembly (which necessarily
    involves copying) of the packets received. *)
type payload = Slice of SBstr.t | String of string

module Make (Key : Hashtbl.HashedType) : sig
  type t
  (** The type of a mutable cache. *)

  val create : ?to_expire:int -> unit -> t
  (** [create ?to_expire ()] creates a new cache where fragments are kept until
      [to_expire] nanoseconds (defaults to 10s). *)

  val insert :
       now:int
    -> t
    -> Key.t
    -> ?last:bool
    -> off:int
    -> len:int
    -> SBstr.t
    -> (Key.t * payload) option
  (** [insert ~now cache key ?last ~off ~len slice] inserts a new slice into the
      given cache identified by the given [key]. The user can specify a sub-view
      of the given slice and must informs if the payload is the last one or not
      with the [last] value (defaults to [false]).

      If the cache is able to reassemble packets identified by [key] or if the
      given slice is not fragmented, it returns the key and the data. Otherwise,
      it returns [None]. *)
end
