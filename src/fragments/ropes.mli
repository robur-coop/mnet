(** Ropes for fragment reassembly.

    A rope is a tree-based data structure for efficient insertion of
    non-contiguous string fragments at arbitrary offsets. It is used during
    IPv4/IPv6 packet reassembly to accumulate fragments as they arrive
    (potentially out of order) without copying on each insertion.

    The rope has two states:
    - {!type:unknown}: the total size is not yet known (the last fragment has
      not arrived).
    - {!type:fixed}: the total size is known, allowing final conversion to bytes
      via {!val:to_bytes}.

    {2 Invariant.}

    Fragments must not overlap. Inserting a fragment that overlaps with an
    existing one raises {!exception:Overlap}. *)

(** Uninhabited type used as a phantom marker for ropes whose total size is
    known. *)
type fixed = |

(** Uninhabited type used as a phantom marker for ropes whose total size is not
    yet known. *)
type unknown = |

type 'a t =
  | Str : string -> fixed t
  | Unknown : 'a size -> 'a t
  | App : {
        l: fixed t
      ; r: 'a t
      ; weight: int
      ; l_len: int
      ; r_len: 'a size
    }
      -> 'a t
      (** A rope parameterized by its size state (['a] is either {!type:fixed}
          or {!type:unknown}).

          - [Str s]: a leaf containing the string [s] (always {!type:fixed}).
          - [Unknown size]: an empty rope with the given size information.
          - [App]: an internal node joining a left (fixed-size) subtree and a
            right subtree. [weight] is the total number of bytes stored in the
            left subtree and is used to navigate to the correct insertion point.
      *)

and 'a size =
  | Length : int -> fixed size
  | Limitless : unknown size
      (** The size of a rope.
          - [Length n]: the rope has a known total size of [n] bytes.
          - [Limitless]: the total size is not yet known. *)

exception Out_of_bounds
(** Raised by {!val:insert} if the fragment extends beyond the rope's known
    size. *)

exception Overlap
(** Raised by {!val:insert} if the fragment overlaps with previously inserted
    data. *)

val length : 'a t -> 'a size
(** [length t] returns the size information of the rope. *)

val weight : 'a t -> int
(** [weight t] returns the total number of payload bytes stored in the rope.
    When [weight t = n] for a fixed rope of [Length n], all fragments have been
    inserted. *)

val insert : off:int -> string -> 'a t -> 'a t
(** [insert ~off str t] inserts [str] at byte offset [off] in the rope.

    @raise Out_of_bounds if [off + String.length str] exceeds the known size.
    @raise Overlap if [str] overlaps with an already-inserted fragment. *)

val fixed : max:int -> unknown t -> fixed t
(** [fixed ~max t] converts an {!type:unknown}-size rope to a {!type:fixed}-size
    rope with total size [max]. This is called when the last fragment arrives
    and the total payload size becomes known. *)

val to_bytes : fixed t -> Diet.t * bytes
(** [to_bytes t] converts a fixed-size rope to a [(gaps, buf)] pair where [buf]
    contains all inserted fragments at their correct offsets and [gaps] is a
    {!type:Diet.t} representing the byte ranges that have {b not} been filled.

    When the reassembly is complete, [gaps] should be empty (i.e.
    [Diet.is_empty gaps = true]). *)
