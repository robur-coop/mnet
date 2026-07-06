# `mnet`, a pure OCaml TCP/IP stack for unikernels

`mnet` is a library that implements certain network layers to provide a TCP/IP
stack for an application using [utcp][utcp]. The project essentially requires
the reading and writing of Ethernet frames, which is provided by [Solo5][solo5]
and [mkernel][mkernel].

This library implements:
- an IPv4 layer (with ARP)
- an IPv6 layer
- an ICMP layer
- the DNS protocol using `mnet-dns`
- the TLS protocol using `mnet-tls`
- the SSH protocol using `mnet-ssh`
- a DHCP layer using `mnet-dhcp`

The aim is to provide a ready-to-use TCP/IP stack implemented entirely in OCaml.
Here is an example of how to initialise a TCP/IP stack that configures itself
automatically based on an available DHCP server.
```ocaml
let ( let@ ) finally fn = Fun.protect ~finally fn
module RNG = Mirage_crypto_rng.Fortuna

let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]
let cfg = Mnet_dhcp.accept_all

let () =
  Mkernel.(run [ rng; Mnet_dhcp.stack ~name:"service" cfg ])
  @@ fun rng (stack, tcp, udp, lease) () ->
  let@ () = fun () -> Mnet_dhcp.kill stack in
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  ...
```

`mnet` is a replacement for [mirage-tcpip][mirage-tcpip], designed to take
advantage of effects and our [Miou][miou] scheduler.

[mkernel]: https://git.robur.coop/robur/mkernel
[utcp]: https://github.com/robur-coop/utcp
[solo5]: https://github.com/solo5/solo5
[mirage-tcpip]: https://github.com/mirage/mirage-tcpip
[miou]: https://github.com/robur-coop/miou
