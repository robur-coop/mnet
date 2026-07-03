(** A DHCP-enabled TCP/IP stack.

    This is a thin assembly on top of {!module:Mnet}: it starts a normal stack
    {b without} an IPv4 address, runs a DHCP client on the link, and keeps the
    stack's IPv4 configuration in sync with the leases it obtains. *)

(** {2 Lease.} *)

type lease
(** A DHCP lease (the accepted [DHCPACK]), seen as a typed bag of network
    configuration. *)

val cidr : lease -> Ipaddr.V4.Prefix.t
(** [cidr lease] is the address and prefix to configure (the leased address
    combined with the subnet mask; defaults to a [/32] if the server omitted the
    mask). *)

val gateway : lease -> Ipaddr.V4.t option
(** [gateway lease] is the first router advertised by the server, if any. *)

val dns_servers : lease -> Ipaddr.V4.t list
(** [dns_servers lease] is the list of DNS resolvers advertised by the server.
*)

val domain_name : lease -> [ `host ] Domain_name.t option
(** [domain_name lease] is the domain name advertised by the server, if any. *)

val lease_time : lease -> int32 option
(** [lease_time lease] is the lease duration in seconds, if advertised. *)

val options : lease -> Dhcp_wire.dhcp_option list
(** [options lease] is the full list of DHCP options of the lease (escape
    hatch). *)

val find_raw : lease -> code:int -> string option
(** [find_raw lease ~code] returns the raw bytes of the option whose numeric
    [code] is given, if present. Use this to recover site-specific or private
    options (codes 224–254), e.g. a TLS certificate the server chose to hand
    out. *)

val pp_lease : lease Fmt.t
(** Pretty-printer for a lease, for debugging and logging. *)

(** {2 Configuration.} *)

type decision =
  | Accept  (** apply the lease to the stack *)
  | Reject  (** decline the lease and restart discovery *)

type config = {
    requests: Dhcp_wire.option_code list
        (** the options to ask the server for (e.g. [SUBNET_MASK], [ROUTERS],
            [DNS_SERVERS], or a private code carrying a certificate). An empty
            list lets [charrua] pick a sensible default set. *)
  ; on_lease: previous:lease option -> lease -> decision
        (** called for every obtained or renewed lease, with the previously
            accepted lease (if any). The return value decides whether the lease
            is applied. *)
}

val accept_all : config
(** [accept_all] requests the default set of options and accepts every lease. *)

val with_requests : Dhcp_wire.option_code list -> config -> config
(** [with_requests requests config] is [config] with its
    {!field:config.requests} replaced. Convenient to start from
    {!val:accept_all} and only add the option codes you care about. *)

(** {2 DHCP stack.} *)

type t
(** A running DHCP-enabled stack (all protocol layers together with their
    background daemons and the DHCP client driving the IPv4 configuration). *)

val stack :
     name:string
  -> ?ipv6:Mnet.IPv6.mode
  -> config
  -> (t * Mnet.TCP.state * Mnet.UDP.state) Mkernel.arg
(** [stack ~name ?ipv6 config] is like {!val:Mnet.stack} but obtains its IPv4
    configuration from DHCP according to [config]. The stack starts unconfigured
    and is configured asynchronously: the user is notified of (and may reject)
    each lease through {!field:config.on_lease}. The returned TCP and UDP
    handles only become usable once a lease has been accepted.

    [name] and [ipv6] have the same meaning as in {!val:Mnet.stack}. *)

val addresses : t -> Ipaddr.Prefix.t list
(** [addresses t] returns all IP addresses (IPv4 and IPv6) currently configured
    on the stack — including the IPv4 address obtained via DHCP, once a lease
    has been accepted. *)

val current_lease : t -> lease option
(** [current_lease t] is the most recently accepted lease, if any. Use it to
    read configuration the stack does not consume (DNS servers, domain name, or
    a TLS certificate carried in a private option). *)

exception Stack_killed

val configured : t -> lease
(** [configured t] blocks until the stack has accepted its first DHCP lease and
    returns it. Use it to delay any network activity (DNS resolution, outgoing
    connections, ...) until the stack actually has an address (otherwise early
    traffic is dropped with {i no address configured}).

    The returned lease carries everything the first configuration provided at
    once: use {!val:cidr} for the address/prefix, {!val:gateway} for the default
    gateway, and the other accessors for DNS servers, NTP servers, etc.

    If a lease has already been accepted, it returns immediately. It raises
    {!exception:Stack_killed} if {!val:kill} is called before any lease is
    obtained. *)

val kill : t -> unit
(** [kill t] terminates the DHCP daemon and all the stack's background daemons
    (Ethernet reader, ARP responder, IPv6 NDP daemon, TCP timer, and ICMP
    handler). After calling [kill], the stack must not be used.

    This function should be called when the unikernel is shutting down. *)

(**/*)

val tcp : t -> Mnet.TCP.daemon
