(** [mnet] is a partially complete implementation of the IPv4, IPv6, and TCP
    protocols (for the latter, mnet uses the
    {{:https://github.com/robur-coop/utcp} utcp} project).

    This implementation uses Miou as a scheduler and Mkernel as a library for
    interacting with a network device (such as the one offered by Solo5). The
    purpose of this library is to provide a TCP/IP stack whose API is very
    similar to what the Unix module offers with sockets, but in pure OCaml.

    {2 Architecture overview.}

    [mnet] organizes the network stack in layers:

    - {b Ethernet}: The lowest layer, handling MAC-level frame I/O via
      {!module:Ethernet}. A background daemon reads frames from the network
      device and dispatches them to upper-layer handlers.
    - {b IPv4 / IPv6}: {!module:IPv4} and {!module:IPv6} handle addressing,
      routing, fragmentation/reassembly, and neighbor/route discovery (ARP for
      IPv4, NDPv6 for IPv6).
    - {b TCP / UDP}: {!module:TCP} (backed by
      {{:https://github.com/robur-coop/utcp} utcp}) provides reliable streams
      with a socket-like API. {!module:UDP} provides unreliable datagrams.

    The {!val:stack} function wires all these layers together and returns the
    handles needed to use TCP and UDP.

    {2 Mnet and random number generators.}

    This library requires the initialization of a random number generator using
    [Mirage_crypto_rng]. To do this, it is possible to initialize such a
    generator upstream using Mkernel in this way:

    {[
      module RNG = Mirage_crypto_rng.Fortuna

      let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
      let rng = Mkernel.map rng Mkernel.[]

      let run _ =
        Mkernel.(run [ rng; Mnet.stack ~name:"service" cidr ])
        @@ fun rng (stack, _, _) ->
        let@ () = fun () -> Mnet.kill stack in
        let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
        ...
    ]}

    {2 Lifecycle management.}

    The stack spawns several background daemons (Ethernet reader, ARP responder,
    NDPv6 daemon, TCP timer, etc.). The caller {b must} call {!val:kill} when
    the stack is no longer needed to terminate all these daemons. A typical
    pattern uses [Fun.protect]:

    {[
      let ( let@ ) finally fn = Fun.protect ~finally fn
      let@ () = fun () -> Mnet.kill stack in
      (* use the stack ... *)
    ]}

    {2 Full example: echo server.}

    {[
      module RNG = Mirage_crypto_rng.Fortuna

      let ( let@ ) finally fn = Fun.protect ~finally fn
      let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
      let rng = Mkernel.map rng Mkernel.[]
      let cidr = Ipaddr.V4.Prefix.of_string_exn "10.0.0.2/24"

      let () =
        Mkernel.(run [ rng; Mnet.stack ~name:"service" cidr ])
        @@ fun rng (stack, tcp, _udp) () ->
        let@ () = fun () -> Mnet.kill stack in
        let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
        let listen = Mnet.TCP.listen tcp 9000 in
        let flow = Mnet.TCP.accept tcp listen in
        let buf = Bytes.create 4096 in
        let len = Mnet.TCP.read flow buf in
        Mnet.TCP.write flow (Bytes.sub_string buf 0 len);
        Mnet.TCP.close flow
    ]} *)

module IPv4 = IPv4
module IPv6 = IPv6
module TCP = TCP
module UDP = UDP

(** {1 Stack creation and management} *)

type stack
(** The type of a running network stack. A stack encompasses all protocol layers
    (Ethernet, ARP, IPv4, IPv6, ICMP, TCP, UDP) together with their background
    daemons. *)

val stack :
     name:string
  -> ?gateway:Ipaddr.V4.t
  -> ?ipv6:IPv6.mode
  -> Ipaddr.V4.Prefix.t
  -> (stack * TCP.state * UDP.state) Mkernel.arg
(** [stack ~name ?gateway ?ipv6 cidr] creates a {!type:Mkernel.arg} value that,
    when passed to {!val:Mkernel.run}, provisions a network device and
    initializes a full TCP/IP stack on top of it.

    [name] is the name of the network device given to Solo5. For instance, if
    the user defines a new TCP/IP stack as ["service"], the [solo5-hvt]
    invocation will be:

    {[
      $ solo5-hvt --net:service=tap0 -- ...
    ]}

    The user must define an IPv4 address and prefix length (e.g. [10.0.0.2/24]).
    In order for the unikernel to communicate with an external network, the user
    must also define a {i gateway}, which generally corresponds to the router
    accessible via a local-link. Finally, it is possible to define how the IPv6
    address is configured (see IPv6.mode for more information) (defaults to
    {!constructor:IPv6.EUI64}, derived from the MAC address). *)

val addresses : stack -> Ipaddr.Prefix.t list
(** [addresses stack] returns all IP addresses (both IPv4 and IPv6) currently
    configured on the stack. This includes the IPv4 address from the {i cidr}
    passed to {!val:stack} and any IPv6 addresses (link-local and global)
    obtained via negotiation (NDPv6). *)

val kill : stack -> unit
(** [kill stack] terminates all background daemons associated with the stack
    (Ethernet reader, ARP responder, IPv6 NDP daemon, TCP timer, and ICMP
    handler). After calling [kill], the stack must not be used.

    This function should be called when the unikernel is shutting down. See
    {b Lifecycle management} above for the recommended pattern. *)
