(** Address Resolution Protocol (ARPv4) for IPv4.

    ARP maps IPv4 addresses to MAC (link-layer) addresses on a local network.
    When the IPv4 layer needs to send a packet to a destination, it uses ARP to
    find the destination's MAC address (or the gateway's MAC address for
    non-local destinations).

    {2 Security: DoS prevention.}

    The ARP cache distinguishes between {i trusted} entries (configured by the
    user, e.g. the local IP address) and {i disposable} entries (learned from
    the network). Disposable entries are subject to eviction under memory
    pressure, preventing an attacker from exhausting memory by flooding the
    network with ARP replies for many different addresses.

    {2 Daemon model.}

    {!val:create} spawns a background daemon that processes incoming ARP
    requests and replies. The daemon responds to ARP requests for the locally
    configured IP address and updates the cache with ARP replies. *)

module Ethernet = Ethernet

(** {1 Types} *)

type error = [ `Exn of exn | `Timeout | `Clear ]
(** Errors returned by {!val:query}.
    - [`Exn exn]: an unexpected exception occurred during ARP resolution.
    - [`Timeout]: no ARP reply was received after a number of retries.
    - [`Clear]: the ARP cache entry was cleared before resolution completed. *)

val pp_error : error Fmt.t
(** Pretty-printer for {!type:error}. *)

type t
(** The ARP state. Maintains the address cache and pending query state. *)

type daemon
(** The background ARP daemon that responds to requests and processes replies.
    Must be terminated with {!val:kill}. *)

(** {1 Initialization.} *)

val create :
     ?delay:int
  -> ?timeout:int
  -> ?retries:int
  -> ?ipaddr:Ipaddr.V4.t
  -> Ethernet.t
  -> (daemon * t, [> `MTU_too_small ]) result
(** [create ?delay ?timeout ?retries ?ipaddr eth] creates a new ARP state and
    starts the background daemon.

    - [delay] (nanoseconds): initial delay before sending the first ARP request.
    - [timeout] (nanoseconds): time to wait for an ARP reply before retrying.
    - [retries]: number of ARP request retries before giving up.
    - [ipaddr]: the local IPv4 address to announce and respond to. Can be
      updated later with {!val:set_ips}.
    - [eth]: the {!module:Ethernet} layer used for sending/receiving ARP frames.

    Returns [`MTU_too_small] if the Ethernet MTU is insufficient. *)

(** {1 Cache operations.} *)

val macaddr : t -> Macaddr.t
(** [macaddr t] returns the local MAC address (from the underlying Ethernet
    device). *)

val set_ips : t -> Ipaddr.V4.t list -> unit
(** [set_ips t ips] sets the list of IPv4 addresses that this ARP instance
    responds to. ARP requests for any of these addresses will receive a reply
    with the local MAC address. These entries are marked as {i trusted} (not
    disposable). *)

val query : t -> Ipaddr.V4.t -> (Macaddr.t, [> error ]) result
(** [query t ipv4] resolves the MAC address for the given [ipv4] address. If the
    address is already in the cache, the result is returned immediately.
    Otherwise, an ARP request is sent and the current Miou task is suspended
    until a reply is received (or timeout/retries are exhausted). *)

val ask : t -> Ipaddr.V4.t -> Macaddr.t option
(** [ask t ipv4] looks up [ipv4] in the ARP cache {b without} sending any ARP
    request. Returns [Some mac] if the address is cached, [None] otherwise.

    Unlike {!val:query}, this function never suspends the caller (no effects, no
    rescheduling). Useful when you want to check the cache speculatively without
    blocking. *)

val kill : daemon -> unit
(** [kill daemon] terminates the background ARP daemon. After calling [kill], no
    more ARP requests will be processed. *)

(**/**)

val transfer : t -> Slice_bstr.t Ethernet.packet -> unit
