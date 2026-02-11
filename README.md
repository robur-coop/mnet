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

## End-to-end tests

`mnet` attempts to provide end-to-end testing, meaning that we try to run real
unikernels in order to test our implementation in a real deployment context.
This requires **sudo access** (in order to create the necessary tap interfaces)
as well as the ability to launch a unikernel (be part of the kvm group on a
Linux system).

Testing `mnet` also requires that `opam` take the version you are developing.
You must therefore also ensure that you _pin_ your version of mnet in order to
build the unikernels with it (otherwise, opam will take the upstream version).

Finally, these tests only run in a specific profile: the `unikernels` profile.
They can be launched as follows:
```shell
$ git clone https://github.com/robur-coop/mnet
$ opam pin add -y .
$ sudo true
$ dune runtest --profile=unikernels
```

These tests are lengthy because they attempt to compile the unikernels and
launch them.

[mkernel]: https://git.robur.coop/robur/mkernel
[utcp]: https://github.com/robur-coop/utcp
[solo5]: https://github.com/solo5/solo5
[unikraft]: https://unikraft.org/
