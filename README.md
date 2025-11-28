# The network interface of a [`mkernel`][mkernel] unikernel

`mnet` is a small library that implements the IP layer needed by [`utcp`][utcp]
to obtain a TCP/IP stack for unikernels in OCaml (with [`mkernel`][mkernel],
i.e. with [Solo5][solo5] and [Unikraft][unikraft]).

## How to use it?

It is possible to specify a network device for a unikernel and configure it to
handle TCP/IP packets. Subsequently, `mnet` provides an interface similar to
that offered by `Unix` module:

```ocaml
let ( let@ ) finally fn = Fun.protect ~finally fn
module RNG = Mirage_crypto_rng_mkernel.Fortuna

let run _ cidr gateway =
  Mkernel.(run [ Mnet.stackv4 ~name:"service" ?gateway cidr ])
  @@ fun (daemon, tcpv4, udpv4) () ->
  let rng = Mirage_crypto_rng_mkernel.initialize (module RNG) in
  let@ () = fun () -> Mnet.kill daemon in
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  Fun.protect ~finally @@ fun () ->
  ...
```

[mkernel]: https://git.robur.coop/robur/mkernel
[utcp]: https://github.com/robur-coop/utcp
[solo5]: https://github.com/solo5/solo5
[unikraft]: https://unikraft.org/
