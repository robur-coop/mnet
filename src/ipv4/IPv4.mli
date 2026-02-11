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

val tags : t -> Logs.Tag.set
(** When IPv4 sends logs, it can attach information such as the source IPv4 and
    the destination to which the logs relate. The user can obtain this
    information through the Logs API (and [tags]) and display it in order to
    better characterize the information that IPv4 can send (especially with
    regard to debugging). *)

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

val src : t -> dst:Ipaddr.V4.t -> Ipaddr.V4.t
(** It is {i morally} possible for a unikernel to have several IPv4 addresses,
    each of which can communicate with certain destinations (depending on the
    routes discovered). In this case, the user is able to determine the source
    IPv4 address required to communicate with the given destination.

    In practice, the implementation is configured to have only one IPv4 address.
    This assertion is therefore true:

    {[
      let dst0 =
        Ipaddr.V4.of_octets (Mirage_crypto_rng.generate 4) |> Result.get_ok
      in
      let src0 = Mnet.IPv4.src ipv4 ~dst:dst0 in
      let dst1 =
        Ipaddr.V4.of_octets (Mirage_crypto_rng.generate 4) |> Result.get_ok
      in
      let src1 = Mnet.IPv4.src ipv4 ~dst:dst1 in
      assert (Ipaddr.V4.compare src0 src1 = 0)
    ]} *)

val addresses : t -> Ipaddr.V4.Prefix.t list
(** [addresses t] returns the addresses on which the given state [t] is mounted.
*)

module Writer : sig
  type ipv4 = t
  type t

  val of_string : ipv4 -> string -> t
  val of_strings : ipv4 -> string list -> t
  val into : ipv4 -> len:int -> (Bstr.t -> unit) -> t
end

val write_directly :
     t
  -> ?ttl:int
  -> ?src:Ipaddr.V4.t
  -> Ipaddr.V4.t * Macaddr.t
  -> protocol:int
  -> Writer.t
  -> unit
(** [write_directly ipv4 ?ttl ?src (dst, macaddr) ~protocol w] writes a new IPv4
    packet [w] {b effectively} (without interruption) (fragmented or not) to the
    specified destination [macaddr]. *)

val write :
     t
  -> ?ttl:int
  -> ?src:Ipaddr.V4.t
  -> Ipaddr.V4.t
  -> protocol:int
  -> Writer.t
  -> (unit, [> `Route_not_found ]) result
(** [write ipv4 ?ttl ?src dst ~protocol w] writes a new IPv4 packet [w]
    (fragmented or not) to the specified destination [dst]. This function may
    have an interruption to discover the route to send the given packet to [dst]
    (an underlying cache exists for such discovery). *)

val attempt_to_discover_destination : t -> Ipaddr.V4.t -> Macaddr.t option
(** [attempt_to_discover_destination ipv4 dst] attempts to return the MAC
    address to which we would like to send a packet if we wish to send it to
    [dst]. *)

val input : t -> Slice_bstr.t Ethernet.packet -> unit
(** [input ipv4 pkt] is the function to install as an IPv4 handler for an
    Ethernet {i daemon}. It analyze incoming IPv4 packets and update the given
    state [ipv4]. *)

val set_handler : t -> (packet * payload -> unit) -> unit
(** When a packet is received (and reassembled if it has been fragmented), the
    {i handler} is called with the IPv4 information (source, destination and
    protocol, see {!type:packet}) so that the upper layer (such as TCP) can
    process it. [set_handler] allows you to modify this {i handler} in order to
    direct incoming packets to a specific process. *)
