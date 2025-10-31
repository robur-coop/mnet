module Ethernet = Ethernet
module ARPv4 = Arp

module Flag : sig
  type t = DF | MF
end

module Packet : sig
  type partial = Partial
  type complete = { checksum: int; length: int }
  type error = [ `Invalid_IPv4_packet | `Invalid_checksum ]

  type 'a packet = {
      src: Ipaddr.V4.t
    ; dst: Ipaddr.V4.t
    ; uid: int
    ; flags: Flag.t list
    ; off: int
    ; ttl: int
    ; protocol: int
    ; checksum_and_length: 'a
    ; opt: Slice_bstr.t
  }

  val decode :
    Slice_bstr.t -> (complete packet * Slice_bstr.t, [> error ]) result
end

type t

type packet = { src: Ipaddr.V4.t; dst: Ipaddr.V4.t; protocol: int; uid: int }
and payload = Slice of Slice_bstr.t | String of string

val create :
     ?to_expire:int
  -> Ethernet.t
  -> ARPv4.t
  -> ?gateway:Ipaddr.V4.t
  -> ?handler:(packet * payload -> unit)
  -> Ipaddr.V4.Prefix.t
  -> (t, [> `MTU_too_small ]) result

val max : t -> int
val src : t -> Ipaddr.V4.t

module Writer : sig
  type ipv4 = t
  type t

  val of_string : ipv4 -> string -> t
  val of_strings : ipv4 -> string list -> t
  val into : ipv4 -> len:int -> (Bstr.t -> unit) -> t

  type ('p, 'q, 'a) m
  type z
  type 'a s

  val ( let* ) : ('p, 'q, 'a) m -> ('a -> ('q, 'r, 'b) m) -> ('p, 'r, 'b) m
  val ( let+ ) : ('p s, 'q s, 'a) m -> (Bstr.t -> int) -> ('p, 'q s, 'a) m
  val return : 'a -> ('p, 'p, 'a) m
  val unknown : (z, 'n s, unit) m -> t
end

val write_directly :
     t
  -> ?ttl:int
  -> ?src:Ipaddr.V4.t
  -> Ipaddr.V4.t * Macaddr.t
  -> protocol:int
  -> Writer.t
  -> unit

val write :
     t
  -> ?ttl:int
  -> ?src:Ipaddr.V4.t
  -> Ipaddr.V4.t
  -> protocol:int
  -> Writer.t
  -> (unit, [> `Route_not_found ]) result
(** [write ?ttl ?src dst protocol w] writes a new IPv4 packet [w] (fragmented or
    not) to the specified destination [dst]. *)

val attempt_to_discover_destination : t -> Ipaddr.V4.t -> Macaddr.t option
val input : t -> Slice_bstr.t Ethernet.packet -> unit
val set_handler : t -> (packet * payload -> unit) -> unit
