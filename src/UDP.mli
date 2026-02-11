(** UDP datagram transport for unikernels.

    This module provides a simple interface for sending and receiving UDP
    datagrams over IPv4 and IPv6. Unlike {!module:TCP}, UDP is connectionless
    and unreliable: datagrams may be lost, duplicated, or arrive out of order.

    {2 Usage.}

    A UDP state is created automatically by {!val:Mnet.stack}. Use the returned
    [udp_state] to send and receive datagrams:

    {[
      Mkernel.(run [ rng; Mnet.stack ~name:"service" cidr ])
      @@ fun rng (stack, _tcp, udp) () ->
      (* Receive a datagram on port 5353 *)
      let buf = Bytes.create 1500 in
      let len, (peer, src_port) = Mnet.UDP.recvfrom udp ~port:5353 buf in
      (* Send a reply *)
      let reply = "pong" in
      ignore (Mnet.UDP.sendto udp ~dst:peer ~port:src_port reply)
    ]} *)

(** {1 Types} *)

type state
(** The mutable UDP state. Maintains a table of tasks waiting for incoming
    datagrams on specific ports. Created by {!val:Mnet.stack} (or directly via
    {!val:create}). *)

type error =
  [ `Route_not_found | `Destination_unreachable of int | `Packet_too_big ]

val create : IPv4.t -> IPv6.t -> state
(** [create ipv4 ipv6] creates a new UDP state backed by the given IPv4 and IPv6
    protocol handlers. Normally called internally by {!val:Mnet.stack}. *)

val recvfrom :
     state
  -> ?src:Ipaddr.t
  -> port:int
  -> ?off:int
  -> ?len:int
  -> ?trigger:Miou.Trigger.t
  -> bytes
  -> int * (Ipaddr.t * int)
(** [recvfrom state ~port buf] blocks the current Miou task until a UDP datagram
    arrives on [port], then copies the payload into [buf] and returns
    [(length, (sender_ip, sender_port))].

    - [port] is the local port to listen on.
    - [off] is the starting offset in [buf] (defaults to [0]).
    - [len] is the maximum number of bytes to read (defaults to
      [Bytes.length buf - off]).
    - [trigger] is an optional {!type:Miou.Trigger.t} that can be used to cancel
      the wait (e.g. for implementing timeouts).

    If the datagram is larger than [len], the excess bytes are silently
    discarded.

    @raise Invalid_argument
      if [off] and [len] do not designate a valid range of [buf]. *)

val sendto :
     state
  -> dst:Ipaddr.t
  -> ?src_port:int
  -> port:int
  -> ?off:int
  -> ?len:int
  -> string
  -> (unit, [> error ]) result
(** [sendto state ~dst ~port payload] sends a UDP datagram containing [payload]
    to [dst:port].

    - [dst] is the destination IP address (IPv4 or IPv6).
    - [port] is the destination port.
    - [src_port] is the local source port (random if omitted).
    - [off] is the starting offset in [payload] (defaults to [0]).
    - [len] is the number of bytes to send (defaults to
      [String.length payload - off]).

    Returns [Ok ()] on success or [Error _] if the datagram could not be sent.

    @raise Invalid_argument
      if [off] and [len] do not designate a valid range of [payload]. *)

val sendfn :
     state
  -> dst:Ipaddr.t
  -> ?src_port:int
  -> port:int
  -> len:int
  -> (Slice_bstr.t -> unit)
  -> (unit, [> error ]) result
(** [sendfn state ~dst ~port ~len fn] sends a UDP datagram by writing directly
    into the outgoing buffer via [fn]. This avoids an extra copy compared to
    {!val:sendto}: the function [fn] receives a {!type:Slice_bstr.t} of size
    [len] and should fill it with the datagram payload.

    - [dst] is the destination IP address (IPv4 or IPv6).
    - [port] is the destination port.
    - [src_port] is the local source port (random if omitted).
    - [len] is the exact payload size in bytes.

    Returns [Ok ()] on success or [Error _] if the datagram could not be sent.
*)

(**/**)

val handler_ipv4 : state -> IPv4.packet * IPv4.payload -> unit
