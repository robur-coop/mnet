(** [Mnet_cli] is a simple helper to aggregate few options which are usable for
    unikernels with [Cmdliner]. *)

open Cmdliner

val ipv4 : Ipaddr.V4.Prefix.t Term.t
(** [ipv4] defines the [--ipv4] option. This option is required and allows you
    to assign a static IPv4 address to a unikernel. *)

val ipv4_gateway : Ipaddr.V4.t option Term.t
(** [ipv4_gateway] defines the [--ipv4-gateway] option. This option is optional
    and allows you to define a {i gateway} (an {i exit} point when a packet is
    destined for a node outside the link-local network). *)

val ipv6 : Mnet.IPv6.mode Term.t
(** [ipv6] defines the [--ipv6] option. This option is optional and allows you
    to define how the static IPv6 address is generated (see {!type:IPv6.mode}).
*)

val setup : (Ipaddr.V4.Prefix.t * Ipaddr.V4.t option * Mnet.IPv6.mode) Term.t
(** [setup] aggregates {!val:ipv4}, {!val:ipv4_gateway} and {!val:ipv6} to be
    able to create a [mnet] {!type:Mnet.stack} (via {!val:Mnet.stack}). *)

type nameserver =
  [ `Tls of Tls.Config.client * Ipaddr.t * int | `Plaintext of Ipaddr.t * int ]

val nameservers :
     ?default:(Dns.proto * nameserver) list
  -> unit
  -> (Dns.proto * nameserver) list Term.t

val setup_nameservers :
     ?default:(Dns.proto * nameserver) list
  -> unit
  -> (Dns.proto * nameserver list) Term.t
(** [setup_nameservers] aggregates {!val:nameservers} and verify if all of them
    use the same protocol (see {!type:Dns.proto}) or not. It fails if one of the
    given nameserver uses a different protocol from the others. *)
