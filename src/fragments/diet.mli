(** Discrete Interval Encoding Tree (DIET).

    A DIET is an efficient representation of a set of integers as a set of
    non-overlapping intervals. It is used by the fragment reassembly engine to
    track which byte ranges of a fragmented packet have been received.

    For example, after receiving fragments at offsets [0..99] and [200..299],
    the DIET contains the intervals [\[0, 99\]] and [\[200, 299\]]. When the
    missing fragment [100..199] arrives, the intervals merge into a single
    [\[0, 299\]], signalling that reassembly is complete. *)

type t
(** An immutable set of non-overlapping intervals. *)

val empty : t
(** The empty set (no intervals). *)

val add : off:int -> len:int -> t -> t
(** [add ~off ~len t] adds the interval [\[off, off + len - 1\]] to the set.
    Adjacent or overlapping intervals are automatically merged. *)

val diff : t -> t -> t
(** [diff a b] returns the set of intervals in [a] that are not covered by [b].
    This is used to determine which byte ranges are still missing during
    reassembly. *)

val is_empty : t -> bool
(** [is_empty t] returns [true] if [t] contains no intervals. After computing
    [diff expected received], an empty result means all bytes have been
    received. *)
