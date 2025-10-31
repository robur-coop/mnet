module Ethernet = Ethernet

type error = [ `Exn of exn | `Timeout | `Clear ]

val pp_error : error Fmt.t

type t
type daemon

val create :
     ?delay:int
  -> ?timeout:int
  -> ?retries:int
  -> ?src:Logs.Src.t
  -> ?ipaddr:Ipaddr.V4.t
  -> Ethernet.t
  -> (daemon * t, [> `MTU_too_small ]) result

val macaddr : t -> Macaddr.t
val set_ips : t -> Ipaddr.V4.t list -> unit
val query : t -> Ipaddr.V4.t -> (Macaddr.t, [> error ]) result

val ask : t -> Ipaddr.V4.t -> Macaddr.t option
(** [ask t ipv4] tries to find [ipv4] but {b does not effectfully} ask to the
    network where is [ipv4] (and returns [None]) in that case. This function
    {b does not} re-schedule. *)

(** ARPv4 daemon *)

val transfer : t -> Slice_bstr.t Ethernet.packet -> unit
val kill : daemon -> unit
