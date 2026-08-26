(** [Mnet_cli] is a simple helper to aggregate few options which are usable for
    unikernels with [Cmdliner]. *)

open Cmdliner

val s_network : Cmdliner.Manpage.section_name
val s_output : Cmdliner.Manpage.section_name
val s_logs : Cmdliner.Manpage.section_name

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

val ipv6_gateway : Ipaddr.V6.t option Term.t
(** [ipv6_gateway] defines the [--ipv6-gateway] option. This option is optional
    and allows you to define a {i gateway} (an {i exit} point when a packet is
    destined for a node outside the link-local network). *)

val setup : (Ipaddr.V4.Prefix.t * Ipaddr.V4.t option * Mnet.IPv6.mode * Ipaddr.V6.t option) Term.t
(** [setup] aggregates {!val:ipv4}, {!val:ipv4_gateway}, {!val:ipv6} and
    {!val:ipv6_gateway} to be able to create a [mnet] {!type:Mnet.stack}
    (via {!val:Mnet.stack}). *)

val setup_logs : bool Term.t
(** [setup_logs] setups logs. *)
