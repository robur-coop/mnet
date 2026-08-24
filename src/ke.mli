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
val unsafe_create : ?limit:int option -> int -> t
val push : t -> string -> unit
val peek : t -> string option
val peek_into : t -> (bytes -> off:int -> len:int -> unit) -> unit
val peek_into_bytes : t -> ?off:int -> ?len:int -> bytes -> int
val length : t -> int
val shift : t -> int -> unit
val unsafe_shift : t -> int -> unit
val available : t -> int
val compress : t -> unit
