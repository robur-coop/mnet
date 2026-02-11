(** [mnet] is a partially complete implementation of the IPv4, IPv6, and TCP
    protocols (for the latter, mnet uses the
    {{:https://github.com/robur-coop/utcp} utcp} project).

    This implementation uses Miou as a scheduler and Mkernel as a library for
    interacting with a network device (such as the one offered by Solo5). The
    purpose of this library is to provide a TCP/IP stack whose API is very
    similar to what the Unix module offers with sockets, but in pure OCaml.

    {2 Mnet and random number generators.}

    This library requires the initialization of a random number generator using
    [Mirage_crypto_rng]. To do this, it is possible to initialize such a
    generator upstream using Mkernel in this way:

    {[
      module RNG = Mirage_crypto_rng.Fortuna

      let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
      let rng = Mkernel.map rng Mkernel.[]

      let run _ =
        Mkernel.(run [ rng; Mnet.stack ~name:"service" cidr ])
        @@ fun rng (stack, _, _) ->
        let@ () = fun () -> Mnet.kill stack in
        let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
        ...
    ]} *)

module IPv4 = IPv4
module IPv6 = IPv6
module TCP = TCP
module UDP = UDP

type stack

val stack :
     name:string
  -> ?gateway:Ipaddr.V4.t
  -> ?ipv6:IPv6.mode
  -> Ipaddr.V4.Prefix.t
  -> (stack * TCP.state * UDP.state) Mkernel.arg

val addresses : stack -> Ipaddr.Prefix.t list
val kill : stack -> unit
