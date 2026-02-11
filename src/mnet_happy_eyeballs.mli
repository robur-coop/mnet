type daemon
type t

type getaddrinfo =
     [ `A | `AAAA ]
  -> [ `host ] Domain_name.t
  -> (Ipaddr.Set.t, [ `Msg of string ]) result

val create :
     ?happy_eyeballs:Happy_eyeballs.t
  -> ?timer_interval:int
  -> ?getaddrinfo:getaddrinfo
  -> Mnet.TCP.state
  -> daemon * t

val kill : daemon -> unit

val connect_ip :
     ?aaaa_timeout:int64
  -> ?connect_delay:int64
  -> ?connect_timeout:int64
  -> t
  -> (Ipaddr.t * int) list
  -> ((Ipaddr.t * int) * Mnet.TCP.flow, [> `Msg of string ]) result

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
