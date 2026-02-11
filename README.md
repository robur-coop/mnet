# The network interface of a [`mkernel`][mkernel] unikernel

`mnet` is a small library that implements the IP layer needed by [`utcp`][utcp]
to obtain a TCP/IP stack for unikernels in OCaml (with [`mkernel`][mkernel],
i.e. with [Solo5][solo5] and [Unikraft][unikraft]). This library (partially)
implements what is necessary for a unikernel to "talk" to a node via IPv4, IPv6,
and TCP (it is an improved reimplementation of [mirage-tcpip][mirage-tcpip]).
The library uses [Miou][miou] as its scheduler and effects, so it offers a
"direct-style" API.

## How to use it?

It is possible to specify a network device for a unikernel and configure it to
handle TCP/IP packets. Subsequently, `mnet` provides an interface similar to
that offered by `Unix` module:

```ocaml
let ( let@ ) finally fn = Fun.protect ~finally fn
module RNG = Mirage_crypto_rng_mkernel.Fortuna
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]

let run _ cidr gateway =
  Mkernel.(run [ rng; Mnet.stack ~name:"service" ?gateway cidr ])
  @@ fun rng (daemon, tcp, udp) () ->
  let@ () = fun () -> Mnet.kill daemon in
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  ...
```

[mkernel]: https://git.robur.coop/robur/mkernel
[utcp]: https://github.com/robur-coop/utcp
[solo5]: https://github.com/solo5/solo5
[unikraft]: https://unikraft.org/
