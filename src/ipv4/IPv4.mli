(** IPv4 protocol layer.

    This module handles IPv4 packet encoding, decoding, fragmentation, and
    reassembly. It maintains a routing table (via ARPv4) to resolve destination
    IPv4 addresses to MAC addresses.

    {2 Zero-copy and payload types.}

    When an IPv4 packet arrives, it may or may not have been fragmented in
    transit. The {!type:payload} type reflects this:

    - {!constructor:Slice}: the packet was {b not} fragmented. The payload is a
      zero-copy slice pointing directly into the original Ethernet frame buffer.
      This is the "happy path" and avoids any allocation.
    - {!constructor:String}: the packet was reassembled from multiple fragments.
      Reassembly requires copying, so the result is an OCaml [string].

    Upper layers (TCP, UDP) handle both cases transparently.

    {2 Route discovery.}

    {!val:write} may need to resolve the destination's MAC address via ARPv4.
    This involves sending an ARP request and waiting for a reply, which
    constitutes an "interruption" (the current Miou task may be suspended). An
    internal cache avoids repeated lookups. If you already know the MAC address,
    use {!val:write_directly} which never interrupts. *)

module Flag : sig
  (** IPv4 header flags.
      - [DF] (Don't Fragment): the packet must not be fragmented.
      - [MF] (More Fragments): more fragments follow this one. *)
  type t = DF | MF
end

module Packet : sig
  type partial =
    | Partial
        (** Marker type for a packet whose checksum and length have not yet been
            computed (used during encoding). *)

  type complete = { checksum: int; length: int }
  (** A fully decoded packet header with verified checksum and total length. *)

  type error = [ `Invalid_IPv4_packet | `Invalid_checksum ]
  (** Decoding errors.
      - [`Invalid_IPv4_packet]: the buffer is too short or contains invalid
        header fields.
      - [`Invalid_checksum]: the IPv4 header checksum does not match. *)

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
  (** An IPv4 packet header parameterized by its checksum state (['a] is either
      {!type:partial} or {!type:complete}).
      - [uid]: the IP identification field, used for fragment reassembly.
      - [off]: the fragment offset (in 8-byte units).
      - [ttl]: Time-To-Live.
      - [protocol]: the upper-layer protocol number (6 = TCP, 17 = UDP, 1 =
        ICMP).
      - [opt]: IP options (usually empty). *)

  val decode :
    Slice_bstr.t -> (complete packet * Slice_bstr.t, [> error ]) result
  (** [decode slice] decodes an IPv4 packet header from [slice] and returns the
      header along with a sub-slice pointing to the payload. *)
end

type t
(** The IPv4 protocol state. Maintains the routing/ARP cache, fragmentation
    reassembly state, and configured addresses. *)

val tags : t -> Logs.Tag.set
(** When IPv4 sends logs, it can attach information such as the source IPv4 and
    the destination to which the logs relate. The user can obtain this
    information through the Logs API (and [tags]) and display it in order to
    better characterize the information that IPv4 can send (especially with
    regard to debugging). *)

type packet = { src: Ipaddr.V4.t; dst: Ipaddr.V4.t; protocol: int; uid: int }
(** Metadata about a received IPv4 packet, passed to upper-layer handlers.
    - [protocol]: the upper-layer protocol (6 = TCP, 17 = UDP, 1 = ICMP).
    - [uid]: the IP identification field. *)

(** The payload of a received IPv4 packet. See the module documentation for the
    distinction between {!constructor:Slice} (zero-copy, non-fragmented) and
    {!constructor:String} (reassembled from fragments). *)
and payload = Slice of Slice_bstr.t | String of string

val create :
     ?to_expire:int
  -> Ethernet.t
  -> ARPv4.t
  -> ?gateway:Ipaddr.V4.t
  -> ?handler:(packet * payload -> unit)
  -> Ipaddr.V4.Prefix.t
  -> (t, [> `MTU_too_small ]) result
(** [create ?to_expire eth arpv4 ?gateway ?handler cidr] creates a new IPv4
    protocol handler.

    - [to_expire] (nanoseconds): how long to keep fragments in the reassembly
      cache before discarding them (defaults to 10 seconds).
    - [eth]: the {!module:Ethernet} layer used for frame I/O.
    - [arpv4]: the {!module:ARPv4} state for address resolution.
    - [gateway]: the default IPv4 gateway. If absent, only On-Link destinations
      can be reached.
    - [handler]: the function called when a complete IPv4 packet is received
      (and reassembled if fragmented). Typically installed later via
      {!val:set_handler}.
    - [cidr]: the local IPv4 address and prefix (e.g. [10.0.0.2/24]).

    Returns [`MTU_too_small] if the Ethernet MTU is too small for IPv4. *)

val src : t -> dst:Ipaddr.V4.t -> Ipaddr.V4.t
(** It is {i morally} possible for a unikernel to have several IPv4 addresses,
    each of which can communicate with certain destinations (depending on the
    routes discovered). In this case, the user is able to determine the source
    IPv4 address required to communicate with the given destination.

    In practice, the implementation is configured to have only one IPv4 address.
    This assertion is therefore true:

    {[
      let open Ipaddr in
      let dst0 = V4.of_octets (Mirage_crypto_rng.generate 4) |> Result.get_ok in
      let src0 = Mnet.IPv4.src ipv4 ~dst:dst0 in
      let dst1 = V4.of_octets (Mirage_crypto_rng.generate 4) |> Result.get_ok in
      let src1 = Mnet.IPv4.src ipv4 ~dst:dst1 in
      assert (V4.compare src0 src1 = 0)
    ]} *)

val addresses : t -> Ipaddr.V4.Prefix.t list
(** [addresses t] returns the addresses on which the given state [t] is mounted.
*)

module Writer : sig
  (** Efficient IPv4 payload composition.

      A {!type:t} value represents a payload to be sent in an IPv4 packet. Three
      constructors are provided depending on whether the data is already in
      memory as a string, as multiple strings, or should be written directly
      into the outgoing buffer. The writer handles fragmentation transparently
      when the payload exceeds the path MTU. *)

  type ipv4 = t
  type t

  val of_string : ipv4 -> string -> t
  (** [of_string ipv4 str] creates a writer that sends [str] as the payload. *)

  val of_strings : ipv4 -> string list -> t
  (** [of_strings ipv4 strs] creates a writer that sends the concatenation of
      [strs] as the payload. This avoids copying the strings into a single
      buffer. *)

  val into : ipv4 -> len:int -> (Bstr.t -> unit) -> t
  (** [into ipv4 ~len fn] creates a writer that fills the payload by calling
      [fn buf], where [buf] is a buffer of size [len] positioned after the IPv4
      header. This is the zero-copy path for upper-layer protocols (like UDP's
      {!val:UDP.sendfn}) that can write directly into the outgoing frame. *)
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
