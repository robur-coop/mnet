module Ethernet = Ethernet_miou_solo5
module ARPv4 = Arp_miou_solo5
module IPv4 = Ipv4_miou_solo5
module ICMPv4 = Icmpv4_miou_solo5
module UDPv4 = Udpv4_miou_solo5

exception Net_unreach
exception Closed_by_peer
exception Connection_refused

module TCPv4 : sig
  type state
  type flow
  type daemon

  val handler : state -> IPv4.packet * IPv4.payload -> unit
  val create : name:string -> IPv4.t -> daemon * state
  val kill : daemon -> unit

  val connect : state -> Ipaddr.V4.t * int -> flow
  (** [connect state ipaddr port] is a Solo5 friendly {!val:Unix.connect}. *)

  val get : flow -> (string list, [> `Eof | `Refused ]) result

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

      @raise Net_unreach if network is unreachable.
      @raise Connection_refused
        if the given connection is not connected to a peer.
      @raise Closed_by_peer if the peer closed the given connection on its side.
      @raise Invalid_argument
        if [off] and [len] do not designate a valid range of [buf]. *)

  val close : flow -> unit
  (** [close flow] closes properly the given [flow]. *)

  val peers : flow -> (Ipaddr.t * int) * (Ipaddr.t * int)

  type listen

  val listen : state -> int -> listen
  val accept : state -> listen -> flow
end

type stackv4

val stackv4 :
     name:string
  -> ?gateway:Ipaddr.V4.t
  -> Ipaddr.V4.Prefix.t
  -> (stackv4 * TCPv4.state * UDPv4.state) Miou_solo5.arg

val kill : stackv4 -> unit
