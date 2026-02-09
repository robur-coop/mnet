module IPv4 = IPv4
module IPv6 = IPv6

exception Net_unreach
exception Closed_by_peer
exception Connection_refused

module TCP : sig
  type state
  type flow
  type daemon

  val handler : state -> Ipaddr.t -> Ipaddr.t -> Bstr.t -> unit
  val create : name:string -> IPv4.t -> IPv6.t -> daemon * state
  val kill : daemon -> unit

  val connect : state -> Ipaddr.t * int -> flow
  (** [connect state ipaddr port] is a Solo5 friendly {!val:Unix.connect}. *)

  val get : flow -> (string list, [> `Eof | `Refused ]) result
  (** [get flow] allows reading from a given [flow] {b without} involving a
      temporary buffer. In other words, the data returned is that from the
      Ethernet frame.

      If data exists in the internal buffer, [get] flushes it and prepends this
      content to what we obtain from the Ethernet frames. *)

  val read : flow -> ?off:int -> ?len:int -> bytes -> int
  (** [read flow buf ~off ~len] reads up to [len] bytes (defaults to
      [Bytes.length buf - off] from the given connection [flow], storing them in
      byte sequence [buf], starting at position [off] in [buf] (defaults to
      [0]). It returns the actual number of characters read, between 0 and [len]
      (inclusive).

      {b NOTE}: In order to be able to deliver data without loss despite the
      fixed size of the given buffer [buf], an internal buffer is used to store
      the overflow and ensure that it is delivered to the next [read] call. In
      other words, [read] is {i buffered}, which involves copying. If, for
      performance reasons, you would like to avoid copying, we recommend using
      {!val:get}.

      @raise Net_unreach if network is unreachable.
      @raise Invalid_argument
        if [off] and [len] do not designate a valid range of [buf]. *)

  val really_read : flow -> ?off:int -> ?len:int -> bytes -> unit
  (** [really_read flow buf ~off ~len] reads [len] bytes (defaults to
      [Bytes.length buf - off]) from the given connection [flow], storing them
      in byte sequence [buf], starting at position [off] in [buf] (defaults to
      [0]). If [len = 0], [really_read] does nothing.

      @raise Net_unreach if network is unreachable.
      @raise End_of_file
        if {!val:Unix.read} returns [0] before [len] characters have been read.
      @raise Invalid_argument
        if [off] and [len] do not designate a valid range of [buf]. *)

  val write : flow -> ?off:int -> ?len:int -> string -> unit
  (** [write fd str ~off ~len] writes [len] bytes (defaults to
      [String.length str - off]) from byte sequence [buf], starting at offset
      [off] (defaults to [0]), to the given connection [flow].

      {b NOTE}: This function can potentially emit one or more effects and, by
      extension, give Miou the opportunity to reschedule. Furthermore, it is not
      advisable to use this function with finalisers such as those required by
      the [Miou.Ownership.create] function. For this, it is preferable to use
      {!val:write_directly}.

      @raise Net_unreach if network is unreachable.
      @raise Connection_refused
        if the given connection is not connected to a peer.
      @raise Closed_by_peer if the peer closed the given connection on its side.
      @raise Invalid_argument
        if [off] and [len] do not designate a valid range of [buf]. *)

  val write_without_interruption :
    flow -> ?off:int -> ?len:int -> string -> unit
  (** [write_without_interruption] writes [len] bytes (defaults to
      [String.length str - off]) from byte sequence [buf], starting at offset
      [off] (defaults to [0]), to the given connection [flow].

      {b NOTE}: This function does not perform any effects and can not be
      interrupted. If the user wants to emit something from an abnormal
      termination, this function can be useful.

      @raise Connection_refused
        if the given connection is not connected to a peer.
      @raise Closed_by_peer if the peer closed the given connection on its side
      @raise Invalid_argument
        if [off] and [len] do not designate a valid range of [buf]. *)

  val close : flow -> unit
  (** [close flow] closes properly the given [flow].

      {b NOTE}: [close] has the particularity of being effective and
      uninterrupted. That is to say, this function does not give Miou the
      opportunity to perform another task. Furthermore, it is possible to use
      [close] in the finalisation of a resource (with [Miou.Ownership.create]).

      {[
        let handler flow =
          let finally = Mnet.TCP.close in
          let r = Miou.Ownership.create ~finally flow in
          Miou.Ownership.own r;
          ...
          Mnet.TCP.close flow;
          Miou.Ownership.disown r
      ]} *)

  val shutdown : flow -> [ `read | `write | `read_write ] -> unit
  val peers : flow -> (Ipaddr.t * int) * (Ipaddr.t * int)
  val tags : flow -> Logs.Tag.set

  type listen

  val listen : state -> int -> listen
  val accept : state -> listen -> flow
end

type stack

val stack :
     name:string
  -> ?gateway:Ipaddr.V4.t
  -> ?ipv6:IPv6.mode
  -> Ipaddr.V4.Prefix.t
  -> (stack * TCP.state * UDP.state) Mkernel.arg

val addresses : stack -> Ipaddr.Prefix.t list
val kill : stack -> unit
