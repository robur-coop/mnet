(** TLS sessions over {!module:Mnet} TCP connections.

    This module wraps {{:https://github.com/mirleft/ocaml-tls} ocaml-tls} (a
    pure OCaml TLS implementation) with the effectful I/O provided by
    {!module:Mnet.TCP}. It provides the same read/write/close interface as
    {!module:Mnet.TCP} but with transparent encryption.

    A TLS session is created from an existing {!type:Mnet.TCP.flow} using either
    {!val:client_of_fd} (for outgoing connections) or {!val:server_of_fd} (for
    incoming connections). The TLS handshake is performed during creation.

    {[
      let flow = Mnet.TCP.connect tcp (Ipaddr.V4 server, 443) in
      let tls_config = Tls.Config.client ~authenticator () in
      let tls = Mnet_tls.client_of_fd tls_config flow in
      Mnet_tls.write tls "GET / HTTP/1.1\r\n\r\n";
      let buf = Bytes.create 4096 in
      let len = Mnet_tls.read tls buf in
      Mnet_tls.close tls
    ]} *)

exception Tls_alert of Tls.Packet.alert_type
exception Tls_failure of Tls.Engine.failure
exception Closed_by_peer

type t
(** Abstract type of a session. *)

val file_descr : t -> Mnet.TCP.flow
(** [file_descr] returns the underlying file-descriptor used by the given TLS
    {i socket}. *)

val read : t -> ?off:int -> ?len:int -> bytes -> int
(** [read t buf ~off ~len] reads up to [len] bytes (defaults to
    [Bytes.length buf - off]) from the given TLS session [t], storing them in
    byte sequence [buf], starting at position [off] in [buf] (defaults to [0]).
    It returns the actual number of characters read, between 0 and [len]
    (inclusive).

    @raise Tls_alert if a TLS alert is received during the read.
    @raise Tls_failure if a TLS protocol error occurs.
    @raise Invalid_argument
      if [off] and [len] do not designate a valid range of [buf]. *)

val really_read : t -> ?off:int -> ?len:int -> bytes -> unit
(** [really_read fd buf ~off ~len] reads [len] bytes (defaults to
    [Bytes.length buf - off]) from the given TLS {i socket} [fd], storing them
    in byte sequence [buf], starting at position [off] in [buf] (defaults to
    [0]). If [len = 0], [really_read] does nothing.

    @raise End_of_file
      if {!val:Unix.read} returns [0] before [len] characters have been read.

    @raise Invalid_argument
      if [off] and [len] do not designate a valid range of [buf]. *)

val write : t -> ?off:int -> ?len:int -> string -> unit
(** [write t str ~off ~len] writes [len] bytes (defaults to
    [String.length str - off]) from byte sequence [str], starting at offset
    [off] (defaults to [0]), to the given TLS {i socket} [fd].

    @raise Closed_by_peer
      if [t] is connected to a peer whose reading end is closed. Similar to the
      {!val:EPIPE} error for pipe/socket connected.

    @raise Invalid_argument
      if [off] and [len] do not designate a valid range of [buf]. *)

val close : t -> unit
(** [close flow] closes the TLS session and the underlying file-descriptor. *)

val shutdown : t -> [ `read | `write | `read_write ] -> unit
(** [shutdown t direction] closes the direction of the TLS session [t]. If
    [`read_write] or [`write] is closed, a TLS close-notify is sent to the other
    endpoint. If this results in a fully-closed session (or an errorneous
    session), the underlying file descriptor is closed. *)

val client_of_fd :
     Tls.Config.client
  -> ?read_buffer_size:int
  -> ?host:[ `host ] Domain_name.t
  -> Mnet.TCP.flow
  -> t
(** [client_of_flow client ~host fd] is [t], after client-side TLS handshake of
    [fd] using [client] configuration and [host].

    @raise End_of_file if we are not able to complete the handshake. *)

val server_of_fd :
  Tls.Config.server -> ?read_buffer_size:int -> Mnet.TCP.flow -> t
(** [server_of_fd server fd] is [t], after server-side TLS handshake of [fd]
    using [server] configuration.

    @raise End_of_file if we are not able to complete the handshake. *)

val epoch : t -> Tls.Core.epoch_data option
(** [epoch t] returns [epoch], which contains information of the active session.
*)
