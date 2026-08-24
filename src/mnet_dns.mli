module Key : sig
  type t = Ipaddr.t * int

  val compare : t -> t -> int
end

module UReqs : Map.S with type key = Key.t
module Reqs : Map.S with type key = int

module Transport : sig
  type context
  and +'a io = 'a
  and t = context * unit Miou.t
  and stack = Mnet.UDP.state * Mnet_happy_eyeballs.t

  and io_addr =
    [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]

  val kill : 'a * 'b Miou.t -> unit
  val bind : 'a -> ('a -> 'b) -> 'b
  val lift : 'a -> 'a
  val clock : unit -> int64
  val rng : int -> string
  val nsec_per_day : int64
  val ps_per_ns : int64
  val time : unit -> Ptime.t option
  val uncensoreddns_org : [> `Tls of Tls.Config.client * Ipaddr.t * int ]
  val nameservers : context * 'a -> [> `Tcp | `Udp ] * io_addr list

  exception Timeout

  val with_timeout : timeout:int -> (unit -> ([> `Timeout ] as 'a)) -> 'a
  val generate_port : context -> (int, [> `Msg of string ]) result

  val to_pairs :
       [ `Plaintext of Ipaddr.t * int
       | `Tls of Tls.Config.client * Ipaddr.t * int ]
       list
    -> (Ipaddr.t * int) list

  val tls_config_of_nameserver :
    [> `Tls of 'a * Ipaddr.t * 'b ] list -> Ipaddr.t * 'b -> 'a option

  val connect_to_nameservers :
       context
    -> [ `Plaintext of Ipaddr.t * int
       | `Tls of Tls.Config.client * Ipaddr.t * int ]
       list
    -> ( (Ipaddr.t * int) * [> `Plain of Mnet.TCP.flow | `TLS of Mnet_tls.t ]
       , [> `Msg of string ] )
       result

  val try_tls_connection :
       context
    -> [ `Plaintext of Ipaddr.t * int
       | `Tls of Tls.Config.client * Ipaddr.t * int ]
       list
    -> Tls.Config.client
    -> Ipaddr.t * int
    -> Mnet.TCP.flow
    -> ( (Ipaddr.t * int) * [> `Plain of Mnet.TCP.flow | `TLS of Mnet_tls.t ]
       , [> `Msg of string ] )
       result

  val process : Ke.t -> ('a * string Miou_sync.Computation.t) Reqs.t -> unit
  val read_from_tcp : context -> Ke.t -> bytes -> Mnet.TCP.flow -> unit
  val read_from_tls : context -> Ke.t -> bytes -> Mnet_tls.t -> unit

  val write_to_connection :
    context -> [< `Plain of Mnet.TCP.flow | `TLS of Mnet_tls.t ] -> 'a

  val _backoff_max : int
  val read_from_connection : context -> Ke.t -> [> `Connect_failed | `Connected ]
  val connection_loop : context -> Ke.t -> 'a
  val read_from_udp : context -> 'a
  val daemon : context -> unit

  val create :
       ?nameservers:[< `Tcp | `Udp > `Tcp ] * io_addr list
    -> timeout:int64
    -> Mnet.UDP.state * Mnet_happy_eyeballs.t
    -> context * unit Miou.t

  val connect :
    context * 'a -> ([> `Tcp | `Udp ] * context, [> `Msg of string ]) result

  val close : 'a -> unit
  val push_on_tcp : context -> string -> unit
  val push_on_udp : context -> int -> unit
  val send_recv : context -> string -> (string, [> `Msg of string ]) result
end

include module type of Dns_client.Make (Transport)

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
