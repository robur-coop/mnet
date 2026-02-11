module SBstr = Slice_bstr

type t
type daemon
type payload = Slice of SBstr.t | String of string
type handler = protocol:int -> Ipaddr.V6.t -> Ipaddr.V6.t -> payload -> unit
type mode = Random | EUI64 | Static of Ipaddr.V6.Prefix.t

val create :
     ?handler:handler
  -> Ethernet.t
  -> mode
  -> (t * daemon, [> `MTU_too_small ]) result
(** [create ~now ?handler eth mode] creates a new background task that manages
    neighbor discovery and incoming IPv6 packets. An IPv6 stack {i state} is
    returned that can be introspected and allows IPv6 packets to be written to
    the network. By default, IPv6 packet reception is ignored if the [handler]
    argument is not specified; otherwise, {b reassembled} packets can be handled
    by this function. *)

val kill : daemon -> unit
val set_handler : t -> handler -> unit

val src : t -> dst:Ipaddr.V6.t -> Ipaddr.V6.t
(** [src ipv6 ~dst] returns the correct IPv6 address for communicating with the
    given destination. In the case of a direct neighbor (a Link-Local
    destination), the Link-Local address is used ([fe80::]). Otherwise, the
    global IPv6 address ([2000::/3]) is used. *)

val addresses : t -> Ipaddr.V6.Prefix.t list
(** [addresses t] returns the addresses on which the given state [t] is mounted.

    With regard to IPv6, an IPv6 stack generally has two addresses:
    - a Link-Local address ([fe80::]) for communicating (and discovering) with
      its direct neighbors
    - a global address ([2000::/3]) for communicating with the Internet *)

val write_directly :
     t
  -> ?src:Ipaddr.V6.t
  -> Ipaddr.V6.t
  -> protocol:int
  -> len:int
  -> (Bstr.t -> unit)
  -> (unit, [> `Packet_too_big | `Destination_unreachable of int ]) result
(** [write_directly ipv6 ~now ?src dst ~protocol ~len fn] executes the fn
    function, which should write the contents of an IPv6 packet with destination
    [dst]. The function handles the possible fragmentation of what the user
    wants to send based on the given size [len] and the discovered PMTU (if the
    PMTU is unknown, we fragment to 1280 bytes to ensure that the packet is sent
    correctly).

    This function has no interruptions (no effects), meaning that the write is
    effective if a route is found, or it is cached until IPv6 finds the route.

    If an error occurs, the user can assume that {b all} previous packets were
    not received by the destination. *)

val input : t -> SBstr.t Ethernet.packet -> unit
(** [input ipv6 pkt] is the function to install as an IPv6 handler for an
    Ethernet {i daemon}. It analyze incoming IPv6 packets and update the given
    state [ipv6]. *)
