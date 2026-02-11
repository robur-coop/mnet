(** Neighbor Discovery Protocol for IPv6 (NDPv6).

    NDPv6 ({{:https://www.rfc-editor.org/rfc/rfc4861} RFC 4861}) is the IPv6
    equivalent of ARPv4. It handles:
    - {b Address resolution}: mapping IPv6 addresses to link-layer (MAC)
      addresses via Neighbor Solicitation (NS) and Neighbor Advertisement (NA).
    - {b Router discovery}: finding default routers via Router Solicitation (RS)
      and Router Advertisement (RA).
    - {b Prefix discovery}: learning which IPv6 prefixes are on-link.
    - {b Redirect}: receiving redirect messages for better next-hop selection.

    {2 Event-driven architecture.}

    The NDPv6 state machine is driven by {!type:event}s. External inputs
    (received packets, timer ticks) are decoded into events, and the {!val:tick}
    function advances the state machine, producing outgoing packets as a side
    effect. This design keeps the NDPv6 logic pure (no I/O), with the
    {!module:IPv6} module handling the actual frame I/O. *)

module SBstr = Slice_bstr

(** {1 Outgoing packets} *)

module Packet : sig
  type t = { dst: Macaddr.t; len: int; fn: Bstr.t -> unit }
  (** An outgoing NDP packet ready to be written to the Ethernet layer.
      - [dst]: the destination MAC address.
      - [len]: the payload size.
      - [fn]: a function that fills the packet buffer. *)

  type user's_packet = { len: int; fn: Bstr.t -> unit }
  (** A user's outgoing packet (without a resolved destination MAC). The NDP
      layer will determine the destination MAC via neighbor resolution. *)
end

(** {1 Router Solicitation} *)

module RS : sig
  val encode_into : mac:Macaddr.t -> (Ipaddr.V6.t -> Ipaddr.V6.t) -> Packet.t
  (** [encode_into ~mac select_src] creates a Router Solicitation packet.
      [select_src] is called with the all-routers multicast address to determine
      the source IPv6 address. *)
end

(** {1 Fragment information} *)

module Fragment : sig
  type t = { uid: int; off: int; protocol: int; payload: SBstr.t; last: bool }
  (** A fragment of an IPv6 packet, extracted from the Fragment extension
      header.
      - [uid]: the fragment identification value (groups fragments together).
      - [off]: the fragment offset in 8-byte units.
      - [protocol]: the upper-layer protocol number.
      - [payload]: the fragment data.
      - [last]: [true] if this is the last fragment. *)
end

(** {1 Address modes} *)

type mode =
  | Random
  | EUI64
  | Static of Ipaddr.V6.Prefix.t  (** See {!type:IPv6.mode}. *)

(** {1 NDP state} *)

type t
(** The NDPv6 state machine. Contains the neighbor cache, router list, prefix
    list, address configuration, and destination cache. *)

val make : now:int -> lmtu:int -> mac:Macaddr.t -> mode -> t * Packet.t list
(** [make ~now ~lmtu ~mac mode] initializes the NDPv6 state.
    - [now]: the current monotonic time in nanoseconds.
    - [lmtu]: the link MTU (Maximum Transmission Unit).
    - [mac]: the local MAC address.
    - [mode]: the address configuration mode.

    It creates an initial state and a list of packets to send. *)

val src : t -> ?src:Ipaddr.V6.t -> Ipaddr.V6.t -> Ipaddr.V6.t
(** [src t ?src dst] selects the appropriate source IPv6 address for
    communicating with [dst]. If [?src] is provided, it is returned as-is. *)

val addresses : t -> Ipaddr.V6.Prefix.t list
(** [addresses t] returns the list of configured IPv6 addresses (link-local and
    global addresses). *)

type event =
  [ `Packet of int * Ipaddr.V6.t * Ipaddr.V6.t * SBstr.t
  | `Destination_unreachable of Dsts.Unreachable.t
  | `NA of Ipaddr.V6.t * Ipaddr.V6.t * Neighbors.NA.t
  | `NS of Ipaddr.V6.t * Ipaddr.V6.t * Neighbors.NS.t
  | `Packet_too_big of Dsts.PTB.t
  | `Ping of Ipaddr.V6.t * Ipaddr.V6.t * int * int * SBstr.t
  | `Pong of SBstr.t
  | `RA of Ipaddr.V6.t * Ipaddr.V6.t * Routers.RA.t
  | `Redirect of Ipaddr.V6.t * Dsts.Redirect.t
  | `Fragment of Ipaddr.V6.t * Ipaddr.V6.t * Fragment.t
  | `Tick ]

val tick : t -> now:int -> event -> t * Packet.t list
(** [tick t ~now event] is a new NDPv6 advanced by processing [event] and
    packets to send. *)

val next_hop :
     t
  -> Ipaddr.V6.t
  -> ( t * Ipaddr.V6.t * int option
     , [> `Packet_too_big | `Destination_unreachable of int ] )
     result
(** [next_hop t dst] determines the next-hop IPv6 address and optional PMTU for
    reaching [dst]. The next-hop is either [dst] itself (if on-link) or the
    default router. *)

val send :
     t
  -> now:int
  -> dst:Ipaddr.V6.t
  -> Ipaddr.V6.t
  -> Packet.user's_packet list
  -> t * Packet.t list
(** [send t ~now ~dst next_hop packets] resolves the link-layer address of
    [next_hop] and prepares [packets] for transmission. If the neighbor's MAC
    address is not yet known, the packets are queued and a Neighbor Solicitation
    packet is sent. *)

type error =
  [ `Bad_version
  | `Drop
  | `ICMP_error of int * int * int
  | `Invalid_ICMP_checksum
  | `Msg of string
  | `Parameter_problem
  | `Invalid_option
  | `Time_exceeded
  | `Truncated
  | `Unknown_ICMP_packet of int ]

val pp_error : error Fmt.t

val decode : t -> SBstr.t -> (event, [> error ]) result
(** [decode t slice] decodes an IPv6 packet (including extension headers and
    ICMPv6) from [slice] and returns the corresponding {!type:event}. *)
