open Cmdliner

val ipv4 : Ipaddr.V4.Prefix.t Term.t
val ipv4_gateway : Ipaddr.V4.t option Term.t
val ipv6 : Mnet.IPv6.mode Term.t
val setup : (Ipaddr.V4.Prefix.t * Ipaddr.V4.t option * Mnet.IPv6.mode) Term.t
