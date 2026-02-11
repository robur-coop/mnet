(** Ethernet frame handling.

    This module implements the lowest layer of the {!module:Mnet} network stack.
    It manages reading and writing Ethernet frames on a network device, decoding
    the protocol field to dispatch incoming frames to the appropriate upper-layer
    handler (ARP, IPv4, or IPv6).

    {2 Daemon model.}

    {!val:create} spawns a background daemon that continuously reads frames from
    the network device. Each incoming frame is decoded and dispatched to a
    {!type:handler} function. The handler runs synchronously within the daemon's
    task — it does {b not} run as a separate Miou task. This means the handler
    must not perform I/O that would write back to the same device (which would
    cause a deadlock). Upper-layer responses should be written from a different
    Miou task.

    {2 Handler chain.}

    Multiple handlers can be registered using {!val:set_handler} and
    {!val:extend_handler_with}. When a handler does not know how to process a
    packet, it calls {!val:uninteresting_packet} to pass control to the next
    handler in the chain. *)

(** {1 Packet decoding} *)

module Packet : sig
  type protocol = ARPv4 | IPv4 | IPv6
  (** The Ethernet protocol field (EtherType). *)

  type t = { src: Macaddr.t; dst: Macaddr.t; protocol: protocol option }
  (** A decoded Ethernet header. [protocol] is [None] if the EtherType is not
      recognized. *)

  val decode :
       Bstr.t
    -> len:int
    -> (t * Slice_bstr.t, [> `Invalid_ethernet_packet ]) result
  (** [decode buf ~len] decodes an Ethernet frame from the first [len] bytes of
      [buf]. Returns the header and a slice pointing to the payload (after the
      14-byte Ethernet header). *)

  val encode_into : t -> ?off:int -> Bstr.t -> unit
  (** [encode_into header ?off buf] writes the Ethernet header into [buf] at
      offset [off] (defaults to [0]). The caller must ensure [buf] has at least
      14 bytes available from [off]. *)
end

(** {1 Device abstraction} *)

type 'net hypercalls = {
    device: 'net
  ; swr: 'net -> ?off:int -> ?len:int -> Bstr.t -> unit
  ; srd: 'net -> ?off:int -> ?len:int -> Bstr.t -> int
}
(** Low-level I/O operations for a network device. This abstracts over the
    underlying platform (Solo5, Unikraft, or a custom backend):
    - [device]: the network device handle
    - [swr]: write (send) a frame to the device
    - [srd]: read (receive) a frame from the device, returning the number of
      bytes read *)

type extern = External : 'net hypercalls -> extern [@@unboxed]
(** An existentially-typed wrapper around {!type:hypercalls}, allowing the
    Ethernet layer to work with any device type. *)

(** {1 Types} *)

type t
(** The Ethernet layer state. Provides access to the MAC address, MTU, and
    frame-writing capabilities. *)

type daemon
(** The background task that reads frames from the device and dispatches them
    to registered handlers. Must be terminated with {!val:kill}. *)

val mac : t -> Macaddr.t
(** [mac t] returns the MAC address of the network device. *)

type protocol = Packet.protocol = ARPv4 | IPv4 | IPv6
(** Re-export of {!type:Packet.protocol}. *)

type 'a packet = {
    src: Macaddr.t option
  ; dst: Macaddr.t
  ; protocol: protocol
  ; payload: 'a
}
(** A packet ready to be dispatched to a handler. The [payload] is polymorphic:
    for incoming packets it is a {!type:Slice_bstr.t} pointing into the received
    frame. [src] is [None] for frames originating from the local device. *)

(** {1 Handlers} *)

type handler = Slice_bstr.t packet -> unit
(** The type of a function that processes incoming Ethernet frames. A handler
    receives the decoded packet (with its payload as a slice of the original
    frame) and should process it or call {!val:uninteresting_packet} to pass
    it along. *)

val set_handler : t -> handler -> unit
(** [set_handler t handler] replaces the current handler with [handler]. This
    is typically called once during initialization to install the combined
    ARP + IPv4 + IPv6 handler. *)

val extend_handler_with : t -> handler -> unit
(** [extend_handler_with t handler] adds [handler] to the handler chain. If
    [handler] calls {!val:uninteresting_packet}, the previously installed
    handler gets a chance to process the packet. *)

val uninteresting_packet : unit -> 'a
(** Call this from within a {!type:handler} when the packet is not relevant to
    the handler. This transfers control to the next handler in the chain (if
    any). This function does not return. *)

(** {1 Writing frames} *)

val write_directly_into :
     t
  -> ?len:int
  -> ?src:Macaddr.t
  -> dst:Macaddr.t
  -> protocol:protocol
  -> (Bstr.t -> int)
  -> unit
(** [write_directly_into t ~dst ~protocol fn] allocates a frame buffer,
    writes the Ethernet header (source MAC, [dst], and [protocol]), then calls
    [fn buf] where [buf] starts after the Ethernet header. [fn] should write
    the payload and return the number of payload bytes written.

    - [?len] is a hint for the total frame size (including the Ethernet header).
    - [?src] overrides the source MAC address (defaults to the device's own MAC
      address).

    This is the low-level frame writing primitive used by {!module:IPv4} and
    {!module:IPv6} to send packets. *)

(** {1 Lifecycle} *)

val create :
     ?mtu:int
  -> ?handler:(Slice_bstr.t packet -> unit)
  -> ?hypercalls:extern
  -> Macaddr.t
  -> Mkernel.Net.t
  -> (daemon * t, [> `MTU_too_small ]) result
(** [create ?mtu ?handler ?hypercalls mac net] creates an Ethernet layer for
    the given network device [net] with MAC address [mac].

    - [?mtu] overrides the device MTU. Returns [`MTU_too_small] if the MTU is
      too small to carry even the smallest valid frame.
    - [?handler] is the initial frame handler (can be set later via
      {!val:set_handler}).
    - [?hypercalls] provides custom I/O operations. If omitted, the default
      Mkernel network device operations are used.

    {b Note:} The handler runs within the daemon's read loop, not in a
    separate Miou task. It must not attempt to write frames on the same device
    or a deadlock will occur. *)

val kill : daemon -> unit
(** [kill daemon] terminates the background frame-reading task. After calling
    [kill], no more frames will be received. *)

val mtu : t -> int
(** [mtu t] returns the Maximum Transmission Unit (in bytes) of the underlying
    network device. This is the maximum payload size for a single Ethernet frame
    (typically 1500 bytes). *)

val macaddr : t -> Macaddr.t
(** [macaddr t] returns the MAC address of the underlying device. Same as
    {!val:mac}. *)

val tags : t -> Logs.Tag.set
(** [tags t] returns logging tags containing the MAC address of the device.
    Useful for structured logging output with {!module:Logs}. *)
