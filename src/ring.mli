type t
(** Type of a ringbuffer. *)

(** {2 Utilities.}

    Length of a ring buffer must be a power of two. Here we have few functions
    to help to user to generate a power of two value or to check if a value is a
    power of two. Due to this constraint, a ring buffer {b can not} be larger
    than {!val:max_ke_length} (otherwise, we raise an exception). *)

val is_power_of_two : int -> bool
val to_power_of_two : int -> int
val max_ke_length : int

(** {2 Ringbuffer.} *)

val create : ?limit:int option -> int -> t
(** [create ?limit len] creates a new ring-buffer of [len] bytes. [len] must be
    a power of two (you can use {!val:to_power_of_two} to round-up a number to a
    next power of two).

    When the user uses {!val:push}, it may involve expanding the ring buffer in
    order to ensure that the entire given [str] string is added. In this case,
    it may be worth imposing a limit so that the ring buffer does not grow
    beyond a certain number of bytes (for example, DNS packets cannot be larger
    than 65,535 bytes, so a limit of [0x2000] bytes is ideal).

    By default, [limit] is set to [0x2000]. The given [len] must be lesser or
    equal to the given [limit] ({b by default}, [len] should be always lesser or
    equal than [0x2000]).

    It is possible not to impose a limit on the ring buffer ([~limit:None]), but
    it should be noted that OCaml has a limit on buffer allocation, which is
    {!val:max_ke_length}: we cannot exceed this limit.

    @raise Invalid_argument
      if [len] or [limit] is not power of two [len] is not lesser or equal to
      [limit]. *)

val unsafe_create : ?limit:int option -> int -> t
(** [unsafe_create ?limit len] is like {!val:create} without verification.
    Useful when you create a ring-buffer from constants. *)

val push : t -> string -> unit
(** [push t str] inserts the given [str] into the given ring-buffer [t]. This
    operation can involves an allocation if the current size of the ring-buffer
    is not enough to store the given [str].

    However, if a limit was specified (see {!val:create}), we ensure to not
    allocate more than what it was specified. In that case, we raise a [Failure]
    exception.

    @raise Failure
      if we reach the specified limit (see {!val:create}) or the
      {!val:max_ke_length} limit. *)

val peek : t -> string option

val peek_into : t -> (bytes -> off:int -> len:int -> unit) -> unit
(** [peek_into t filler] calls [filler] using the available bytes in the given
    ring buffer [t] that have not yet been used. Note that there may be several
    calls to [filler] (particularly if the bytes are not contiguous). Only a
    call to {val:compress} ensures that [peek_into] calls [filler] only once.
*)

val peek_into_bytes : t -> ?off:int -> ?len:int -> bytes -> int

val length : t -> int
(** [length t] is the number of bytes which have not yet been used. *)

val shift : t -> int -> unit
(** [shift t len] advances the given ring buffer [t] by [len] bytes.

    @raise Invalid_argument if [len] goes too far. *)

val unsafe_shift : t -> int -> unit
(** [unsafe_shift t len] does the same as {!shift} but it does not raise an
    exception. *)

val available : t -> int
(** [available t] is the number of bytes available in the given ring buffer [t].
*)

val compress : t -> unit
(** [compress t] updates the ring buffer so that the available internal buffer
    is continuous. This means that a subsequent call to {!val:peek_into} will
    require only a single call to its {i filler}. *)
