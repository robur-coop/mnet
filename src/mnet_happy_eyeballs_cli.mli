type setup = {
    aaaa_timeout: int64
  ; connect_delay: int64
  ; connect_timeout: int64
  ; resolve_timeout: int64
  ; resolve_retries: int
}

val setup : setup Cmdliner.Term.t
(** [setup] aggregates options to configure an Happy Eyeballs instance. *)
