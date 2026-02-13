(** Happy eyeballs connection algorithm
    ({{:https://www.rfc-editor.org/rfc/rfc8305} RFC 8305}).

    When connecting to a host that has both IPv4 and IPv6 addresses, a naive
    approach would try one address family first and fall back to the other on
    failure. This introduces latency when the preferred family is broken.

    The happy eyeballs algorithm solves this by racing connection attempts
    across address families with staggered timeouts, ensuring the user gets the
    fastest working connection.

    {2 Usage.}

    Create a happy eyeballs instance from a {!type:Mnet.TCP.state}, then use
    {!val:connect}, {!val:connect_host}, or {!val:connect_ip} to establish
    connections:

    {[
      let hed, he = Mnet_happy_eyeballs.create tcp in
      let@ () = fun () -> Mnet_happy_eyeballs.kill hed in
      match Mnet_happy_eyeballs.connect he "robur.coop" [ 443 ] with
      | Ok ((addr, port), flow) ->
          Logs.debug (fun m -> m "Connected to %a:%d" Ipaddr.pp addr port);
          (* use [flow] for communication *)
          Mnet.TCP.close flow
      | Error (`Msg msg) -> Logs.err (fun m -> m "Connection failed: %s" msg)
    ]}

    {2 DNS resolution.}

    By default, happy eyeballs has no built-in DNS resolver. You must provide a
    [getaddrinfo] callback (see {!type:getaddrinfo}) when creating the instance
    if you want to resolve hostnames via {!val:connect_host} or {!val:connect}.
    Without it, only {!val:connect_ip} (with explicit IP addresses) will work.
*)

type daemon
(** A background task that manages connection attempt scheduling. Must be
    terminated with {!val:kill} when no longer needed. *)

type t
(** The happy eyeballs state, used to initiate connections. *)

type getaddrinfo =
     [ `A | `AAAA ]
  -> [ `host ] Domain_name.t
  -> (Ipaddr.Set.t, [ `Msg of string ]) result
(** The type of a DNS resolution callback. Given a query type ([`A] for IPv4 or
    [`AAAA] for IPv6) and a hostname, it should return the set of resolved IP
    addresses or an error message.

    This callback is invoked during {!val:connect_host} and {!val:connect} to
    translate hostnames into IP addresses. *)

val create :
     ?happy_eyeballs:Happy_eyeballs.t
  -> ?timer_interval:int
  -> ?getaddrinfo:getaddrinfo
  -> Mnet.TCP.state
  -> daemon * t
(** [create ?happy_eyeballs ?timer_interval ?getaddrinfo tcp_state] creates a
    new happy eyeballs instance backed by the given TCP state.

    - [happy_eyeballs] is an optional pre-configured {!type:Happy_eyeballs.t}
      state. If omitted, a default one is created.
    - [timer_interval] controls how often the background timer fires (in
      nanoseconds). This affects how quickly stale connection attempts are
      retried or cancelled.
    - [getaddrinfo] is the DNS resolution callback. If not provided,
      {!val:connect_host} and {!val:connect} will fail when given hostnames. *)

val kill : daemon -> unit
(** [kill daemon] terminates the background timer task. After calling [kill],
    the happy eyeballs instance must not be used. *)

val connect_ip :
     ?aaaa_timeout:int64
  -> ?connect_delay:int64
  -> ?connect_timeout:int64
  -> t
  -> (Ipaddr.t * int) list
  -> ((Ipaddr.t * int) * Mnet.TCP.flow, [> `Msg of string ]) result
(** [connect_ip t addresses] attempts to connect to one of the given
    [(ipaddr, port)] pairs using the happy eyeballs algorithm. Returns the
    address that succeeded and the resulting TCP flow, or an error if all
    attempts failed.

    - [aaaa_timeout] (nanoseconds): how long to wait for an IPv6 (AAAA)
      connection attempt before starting an IPv4 (A) attempt (defaults to 50ms).
    - [connect_delay] (nanoseconds): delay between successive connection
      attempts to different addresses (defaults to 250ms).
    - [?connect_timeout] (nanoseconds): maximum time to wait for any single
      connection attempt (defaults to 10s). *)

val connect_host :
     ?aaaa_timeout:int64
  -> ?connect_delay:int64
  -> ?connect_timeout:int64
  -> ?resolve_timeout:int64
  -> ?resolve_retries:int
  -> t
  -> [ `host ] Domain_name.t
  -> int list
  -> ((Ipaddr.t * int) * Mnet.TCP.flow, [> `Msg of string ]) result
(** [connect_host t hostname ports] resolves [hostname] via the configured
    {!type:getaddrinfo} callback, then connects to one of the resolved addresses
    on one of the given [ports] using the happy eyeballs algorithm.

    In addition to the timeout parameters of {!val:connect_ip}:
    - [?resolve_timeout] (nanoseconds): maximum time to wait for DNS resolution.
    - [?resolve_retries]: number of times to retry DNS resolution on failure. *)

val connect :
     ?aaaa_timeout:int64
  -> ?connect_delay:int64
  -> ?connect_timeout:int64
  -> ?resolve_timeout:int64
  -> ?resolve_retries:int
  -> t
  -> string
  -> int list
  -> ((Ipaddr.t * int) * Mnet.TCP.flow, [> `Msg of string ]) result
(** [connect t host ports] is a convenience wrapper around {!val:connect_host}
    that accepts the hostname as a plain [string]. The string is parsed as a
    {!type:Domain_name.t} before resolution.

    See {!val:connect_host} for parameter descriptions. *)

val inject : t -> getaddrinfo -> unit
