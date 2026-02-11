(** TCP connections for unikernels.

    This module provides a socket-like API for TCP connections, backed by the
    pure {{:https://github.com/robur-coop/utcp} utcp} implementation. It
    supports both client (outgoing) and server (incoming) connections over IPv4
    and IPv6.

    {2 Error handling.}

    Errors are reported via exceptions rather than result types, which makes the
    API closer to {!module:Unix}. The three exceptions {!exception:Net_unreach},
    {!exception:Closed_by_peer}, and {!exception:Connection_refused} cover the
    main failure modes.

    {2 Zero-copy vs buffered reads.}

    Two reading strategies are available:
    - {!val:get} returns data directly from the Ethernet frame. This is the fast
      path when you can process data in-place.
    - {!val:read} copies data into a user-supplied buffer. An internal buffer
      handles overflow when the frame payload exceeds the buffer size.

    {2 Concurrency model.}

    TCP runs a background daemon (see {!val:create}) that processes incoming
    segments, retransmissions, and timers. Most operations ({!val:read},
    {!val:accept}, {!val:connect}) may suspend the current Miou task. Some
    operations ({!val:close}, {!val:write_without_interruption}) are
    {i uninterruptible}: they complete without yielding to the scheduler, making
    them safe for use in finalizers.

    {2 Example: echo server.}

    {[
      let listen = Mnet.TCP.listen tcp 9000 in
      let flow = Mnet.TCP.accept tcp listen in
      let buf = Bytes.create 4096 in
      let rec loop () =
        let len = Mnet.TCP.read flow buf in
        if len > 0 then begin
          Mnet.TCP.write flow (Bytes.sub_string buf 0 len);
          loop ()
        end
      in
      (try loop () with Mnet.TCP.Closed_by_peer -> ());
      Mnet.TCP.close flow
    ]}

    {2 Example: client.}

    {[
      let flow = Mnet.TCP.connect tcp (Ipaddr.V4 server, 9000) in
      Mnet.TCP.write flow "Hello!";
      Mnet.TCP.shutdown flow `write;
      let buf = Bytes.create 4096 in
      let len = Mnet.TCP.read flow buf in
      (* process response *)
      Mnet.TCP.close flow
    ]} *)

exception Net_unreach
(** Raised when the destination network is unreachable (no route found or
    ARPv4/NDPv6 resolution failed). *)

exception Closed_by_peer
(** Raised on write operations when the remote end has closed its side of the
    connection. *)

exception Connection_refused
(** Raised by {!val:connect} or write operations when the remote end actively
    refuses the connection (e.g. [RST] packet received). *)

(** {1 Types.} *)

type state
(** The mutable TCP state shared across all connections. Created by
    {!val:create} and passed to {!val:connect}, {!val:listen}, and
    {!val:accept}. *)

type flow
(** An individual TCP connection (either incoming or outgoing). Provides
    {!val:read}, {!val:write}, and {!val:close} operations. *)

type daemon
(** A background task that manages TCP timers and incoming segment processing.
    Must be terminated with {!val:kill} when no longer needed. *)

(** {1 Stack initialization.} *)

val handler : state -> Ipaddr.t -> Ipaddr.t -> Bstr.t -> unit
(** [handler state src dst payload] processes an incoming TCP segment. This
    function is installed by {!val:Mnet.stack} as the protocol handler for TCP
    segments (protocol number 6) received by the IPv4 and IPv6 layers. Users
    normally do not need to call this directly. *)

val create : name:string -> IPv4.t -> IPv6.t -> daemon * state
(** [create ~name ipv4 ipv4] creates a TCP {!type:state} and a background task
    capable of managing the state over time. It is generally agreed that the
    user then attaches the {!val:handler} to the task managing incoming IP
    packets. *)

val kill : daemon -> unit
(** [kill daemon] allows you to terminate the background task launched by
    {!val:create}. *)

val connect : state -> Ipaddr.t * int -> flow
(** [connect state ipaddr port] is a Solo5 friendly {!val:Unix.connect}. *)

val get : flow -> (string list, [> `Eof | `Refused ]) result
(** [get flow] allows reading from a given [flow] {b without} involving a
    temporary buffer. In other words, the data returned is that from the
    Ethernet frame.

    If data exists in the internal buffer, [get] flushes it and prepends this
    content to what we obtain from the Ethernet frames. *)

val read : flow -> ?off:int -> ?len:int -> bytes -> int
(** [read flow buf ~off ~len] reads up to [len] bytes (defaults to
    [Bytes.length buf - off] from the given connection [flow], storing them in
    byte sequence [buf], starting at position [off] in [buf] (defaults to [0]).
    It returns the actual number of characters read, between 0 and [len]
    (inclusive).

    {b NOTE}: In order to be able to deliver data without loss despite the fixed
    size of the given buffer [buf], an internal buffer is used to store the
    overflow and ensure that it is delivered to the next [read] call. In other
    words, [read] is {i buffered}, which involves copying. If, for performance
    reasons, you would like to avoid copying, we recommend using {!val:get}.

    @raise Net_unreach if network is unreachable.
    @raise Invalid_argument
      if [off] and [len] do not designate a valid range of [buf]. *)

val really_read : flow -> ?off:int -> ?len:int -> bytes -> unit
(** [really_read flow buf ~off ~len] reads [len] bytes (defaults to
    [Bytes.length buf - off]) from the given connection [flow], storing them in
    byte sequence [buf], starting at position [off] in [buf] (defaults to [0]).
    If [len = 0], [really_read] does nothing.

    @raise Net_unreach if network is unreachable.
    @raise End_of_file
      if {!val:Unix.read} returns [0] before [len] characters have been read.
    @raise Invalid_argument
      if [off] and [len] do not designate a valid range of [buf]. *)

val write : flow -> ?off:int -> ?len:int -> string -> unit
(** [write fd str ~off ~len] writes [len] bytes (defaults to
    [String.length str - off]) from byte sequence [buf], starting at offset
    [off] (defaults to [0]), to the given connection [flow].

    {b NOTE}: This function can potentially emit one or more effects and, by
    extension, give Miou the opportunity to reschedule. Furthermore, it is not
    advisable to use this function with finalisers such as those required by the
    [Miou.Ownership.create] function. For this, it is preferable to use
    {!val:write_directly}.

    @raise Net_unreach if network is unreachable.
    @raise Connection_refused
      if the given connection is not connected to a peer.
    @raise Closed_by_peer if the peer closed the given connection on its side.
    @raise Invalid_argument
      if [off] and [len] do not designate a valid range of [buf]. *)

val write_without_interruption : flow -> ?off:int -> ?len:int -> string -> unit
(** [write_without_interruption] writes [len] bytes (defaults to
    [String.length str - off]) from byte sequence [buf], starting at offset
    [off] (defaults to [0]), to the given connection [flow].

    {b NOTE}: This function does not perform any effects and can not be
    interrupted. If the user wants to emit something from an abnormal
    termination, this function can be useful.

    @raise Connection_refused
      if the given connection is not connected to a peer.
    @raise Closed_by_peer if the peer closed the given connection on its side
    @raise Invalid_argument
      if [off] and [len] do not designate a valid range of [buf]. *)

val close : flow -> unit
(** [close flow] closes properly the given [flow].

    {b NOTE}: [close] has the particularity of being effective and
    uninterrupted. That is to say, this function does not give Miou the
    opportunity to perform another task. Furthermore, it is possible to use
    [close] in the finalisation of a resource (with [Miou.Ownership.create]).

    {[
      let handler flow =
        let finally = Mnet.TCP.close in
        let r = Miou.Ownership.create ~finally flow in
        Miou.Ownership.own r;
        ...
        Mnet.TCP.close flow;
        Miou.Ownership.disown r
    ]} *)

val shutdown : flow -> [ `read | `write | `read_write ] -> unit
(** [shutdown flow mode] shutdowns a TCP connection. [`write] as second argument
    causes reads on the other end of the connection to return an {i end-of-file}
    condition. [`read] causes writes on the other end of the connection to
    return a {!exception:Closed_by_peer}. *)

val peers : flow -> (Ipaddr.t * int) * (Ipaddr.t * int)
(** [peers flow] returns [(local, remote)] where each element is an
    [(address, port)] pair identifying the two endpoints of the connection. This
    is analogous to {!val:Unix.getsockname} and {!val:Unix.getpeername}. *)

val tags : flow -> Logs.Tag.set
(** [tags flow] returns logging tags for the given flow. These tags contain
    connection metadata (local and remote addresses/ports) and can be attached
    to {!module:Logs} messages for structured debugging output. *)

(** {1 Server operations.} *)

type listen
(** A {i handle} representing a port configured to accept incoming connections.
*)

val listen : state -> int -> listen
(** [listen state port] prepares [port] for receiving incoming TCP connection
    requests. This is analogous to {!val:Unix.listen}. The returned {i handle}
    is passed to {!val:accept} to wait for clients. *)

val accept : state -> listen -> flow
(** [accept state listen] blocks the current Miou task until a client connects
    to the port associated with [listen], then returns a {!type:flow} connected
    to that client. This is analogous to {!val:Unix.accept}.

    To handle multiple clients concurrently, spawn each accepted flow in a
    separate Miou task:

    {[
      let clean_up orphans = match Miou.care orphans with
        | None | Some None -> ()
        | Some (Some prm) -> Miou.await_exn prm; clean_up orphans

      let listen = Mnet.TCP.listen tcp 9000 in
      let rec loop orphans =
        clean_up orphans;
        let flow = Mnet.TCP.accept tcp listen in
        let _ = Miou.async ~orphans @@ fun () -> handler flow in
        loop orphans
      in
      loop (Miou.orphans ())
    ]} *)
