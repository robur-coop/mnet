type nameserver =
  [ `Tls of Tls.Config.client * Ipaddr.t * int | `Plaintext of Ipaddr.t * int ]

val nameservers :
     ?default:(Dns.proto * nameserver) list
  -> unit
  -> (Dns.proto * nameserver) list Cmdliner.Term.t

val setup :
     ?default:(Dns.proto * nameserver) list
  -> unit
  -> (Dns.proto * nameserver list) Cmdliner.Term.t
(** [setup_nameservers] aggregates {!val:nameservers} and verify if all of them
    use the same protocol (see {!type:Dns.proto}) or not. It fails if one of the
    given nameserver uses a different protocol from the others. *)
