(** [Mnet_dns] is a specialization of [Dns_client] with Miou and Mnet.

    It proposes a DNS client which is able to talk to nameservers via:
    - UDP
    - TCP
    - and TLS

    To be able to initiate such a client, you must prepare, at least, something
    to talk throught UDP and TCP. About the latter, we use the Happy Eyeballs
    algorithm to race multiple DNS nameservers and take the quickest one. The
    user must create a {!type:Transport.stack} from an UDP witness and an Happy
    Eyeballs witness:

    {[
      let he, hed = Mnet_happy_eyeballs.create tcp in
      Fun.protect
        ~finally:(fun () -> Mnet_happy_eyeballs.kill hed) @@ fun () ->
      let stack = Mnet_dns.Transport.stack udp he in
      let dns = Mnet_dns.create ~nameservers stack in
      ...
    ]}

    The user is able to decide the size of internal buffers used for TCP and TLS
    connections. A limit of [0x20000] of these buffers is applied by default and
    the initial size of it is [0x800] bytes. It's mainly due to we probably can
    receive truncated DNS packets but they can not be bigger than [0x10000]
    bytes. The user is able to reduce this limit and enlarge (or reduce) the
    initial size of these buffers. They are allocated per TCP or TLS
    connections.

    A daemon exists when the user create a new DNS client and it must be killed
    at the end of your application:

    {[
      let daemon = Mnet_dns.transport dns in
      Fun.protect
        ~finally:(fun () -> Mnet_dns.Transport.kill daemon) @@ fun () ->
      ...
    ]} *)

module Key : sig
  type t = Ipaddr.t * int

  val compare : t -> t -> int
end

module UReqs : Map.S with type key = Key.t
module Reqs : Map.S with type key = int

module Transport : sig
  type context
  (** Type of a network connection initialized by {!val:connect}. *)

  and +'a io = 'a
  and daemon = unit Miou.t

  and t = context * daemon
  (** The abstract state of a DNS client. *)

  and stack = private {
      limit: int
    ; length: int
    ; udp: Mnet.UDP.state
    ; happy_eyeballs: Mnet_happy_eyeballs.t
  }
  (** Type of everything needed to initiate a network connection (throught UDP
      or TCP and TLS via Happy Eyeballs). *)

  and io_addr =
    [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]
  (** An address for a given context type. *)

  and flow =
    [ `Plain of Mnet.TCP.buffer Mnet.TCP.flow | `TLS of Mnet_tls.t * Ke.t ]

  (** {3 Basic functions required by the DNS client implementation.} *)

  val bind : 'a -> ('a -> 'b) -> 'b
  val lift : 'a -> 'a
  val clock : unit -> int64
  val rng : int -> string
  val nameservers : context * daemon -> [> `Tcp | `Udp ] * io_addr list

  (** {3 Constructors and destructors.} *)

  val kill : context * daemon -> unit

  val stack :
    ?buffer:int * int -> Mnet.UDP.state -> Mnet_happy_eyeballs.t -> stack

  val create :
       ?nameservers:[< `Tcp | `Udp > `Tcp ] * io_addr list
    -> timeout:int64
    -> stack
    -> context * daemon

  (** {3 Operations to send and receive DNS packets.} *)

  val connect :
    context * daemon -> ([> `Tcp | `Udp ] * context, [> `Msg of string ]) result

  val send_recv : context -> string -> (string, [> `Msg of string ]) result
  val close : context -> unit
end

include module type of Dns_client.Make (Transport)
