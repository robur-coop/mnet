(** IPv6 protocol layer.

    This module handles IPv6 packet encoding, decoding, fragmentation, and
    reassembly. It integrates with the Neighbor Discovery Protocol (NDP) for
    address resolution and router/prefix discovery.

    {2 Address modes.}

    IPv6 addresses can be configured in three ways via {!type:mode}:
    - {!constructor:Random}: a random Interface Identifier is generated.
    - {!constructor:EUI64}: the Interface Identifier is derived from the
      device's MAC address using the EUI-64 algorithm (the default).
    - {!constructor:Static}: a user-specified IPv6 prefix is used directly.

    Regardless of the mode, the stack always has a Link-Local address
    ([fe80::/10]) for communicating with direct neighbors. A Global address
    ([2000::/3]) is obtained via Router Advertisements (NDP).

    {2 Path MTU discovery.}

    IPv6 does not allow routers to fragment packets. The sender must discover
    the Path MTU and fragment at the source if needed. This module caches PMTU
    values discovered via ICMPv6 "Packet Too Big" messages. When the PMTU is
    unknown, fragmentation defaults to 1280 bytes (the IPv6 minimum MTU). *)

module SBstr = Slice_bstr

(** {1 Types} *)

type t
(** The IPv6 protocol state. Maintains NDP state (neighbors, routers, prefixes),
    address configuration, fragmentation reassembly cache, and PMTU cache. *)

type daemon
(** The background NDP daemon that sends Router Solicitations, processes
    advertisements, and manages neighbor reachability. Must be terminated with
    {!val:kill}. *)

type payload =
  | Slice of SBstr.t
  | String of string
      (** The payload of a received IPv6 packet. Like {!type:IPv4.payload}:
          - {!constructor:Slice}: non-fragmented, zero-copy from the Ethernet
            frame.
          - {!constructor:String}: reassembled from fragments (involves
            copying). *)

type handler = protocol:int -> Ipaddr.V6.t -> Ipaddr.V6.t -> payload -> unit
(** The type of a function that processes received IPv6 packets.
    - [~protocol]: the upper-layer protocol number (6 = TCP, 58 = ICMPv6).
    - The two [Ipaddr.V6.t] arguments are source and destination respectively.
*)

type mode =
  | Random
  | EUI64
  | Static of Ipaddr.V6.Prefix.t
      (** How to configure the IPv6 Interface Identifier.
          - [Random]: generate a random identifier (changes on each boot).
          - [EUI64]: derive the identifier from the MAC address. This is
            deterministic and is the default mode.
          - [Static prefix]: use the given IPv6 prefix directly. The address is
            the prefix combined with the Interface Identifier derived from the
            prefix. *)

(** {1 Initialization} *)

val create :
     ?handler:handler
  -> Ethernet.t
  -> mode
  -> (t * daemon, [> `MTU_too_small ]) result
(** [create ?handler eth mode] creates a new IPv6 stack and starts the NDP
    background daemon. The daemon immediately sends a Router Solicitation to
    discover routers and obtain a Global address prefix.

    - [?handler]: the function called when a complete IPv6 packet is received
      (and reassembled if fragmented). If not provided, received packets are
      silently dropped. Typically set later via {!val:set_handler} once the
      upper layers (TCP, UDP) are initialized.
    - [eth]: the {!module:Ethernet} layer.
    - [mode]: the address configuration mode (see {!type:mode}).

    Returns [`MTU_too_small] if the Ethernet MTU is insufficient for IPv6. *)

val kill : daemon -> unit
(** [kill daemon] terminates the NDP background daemon. *)

val set_handler : t -> handler -> unit
(** [set_handler t handler] installs [handler] as the function called for
    incoming IPv6 packets. Replaces any previously installed handler. *)

(** {1 Addressing} *)

val src : t -> dst:Ipaddr.V6.t -> Ipaddr.V6.t
(** [src ipv6 ~dst] returns the correct IPv6 source address for communicating
    with the given destination. In the case of a direct neighbor (a Link-Local
    destination), the Link-Local address is used ([fe80::]). Otherwise, the
    global IPv6 address ([2000::/3]) is used. *)

val addresses : t -> Ipaddr.V6.Prefix.t list
(** [addresses t] returns the addresses on which the given state [t] is mounted.

    With regard to IPv6, an IPv6 stack generally has two addresses:
    - a Link-Local address ([fe80::]) for communicating (and discovering) with
      its direct neighbors
    - a global address ([2000::/3]) for communicating with the Internet *)

(** {1 Sending packets} *)

val write_directly :
     t
  -> ?src:Ipaddr.V6.t
  -> Ipaddr.V6.t
  -> protocol:int
  -> len:int
  -> (Bstr.t -> unit)
  -> (unit, [> `Packet_too_big | `Destination_unreachable of int ]) result
(** [write_directly ipv6 ?src dst ~protocol ~len fn] sends an IPv6 packet by
    calling [fn buf], where [buf] is a buffer of size [len] that [fn] should
    fill with the packet payload.

    The function handles fragmentation automatically based on the discovered
    PMTU. If the PMTU is unknown, fragmentation defaults to 1280 bytes.

    This function has no interruptions (no Miou effects). If a route to [dst] is
    already known, the packet is sent immediately. If not, it is queued until
    NDP resolves the next-hop's link-layer address.

    - [?src] overrides the source IPv6 address.
    - [dst] is the destination IPv6 address.
    - [~protocol] is the upper-layer protocol number (6 = TCP, 17 = UDP).
    - [~len] is the exact payload size in bytes.

    Returns [`Packet_too_big] if the payload cannot be sent even with
    fragmentation. Returns [`Destination_unreachable code] if an ICMPv6
    Destination Unreachable was received for [dst]. *)

(** {1 Receiving packets} *)

val input : t -> SBstr.t Ethernet.packet -> unit
(** [input ipv6 pkt] is the function to install as an IPv6 handler for an
    Ethernet {i daemon}. It analyzes incoming IPv6 packets and updates the given
    state [ipv6]. NDP messages (Router Advertisements, Neighbor Solicitations,
    etc.) are processed internally; upper-layer packets are forwarded to the
    installed {!type:handler}. *)
