# `mnet`, a pure OCaml TCP/IP stack for unikernels

`mnet` implements IPv4, IPv6, TCP, and UDP protocols for
[mkernel][mkernel]-based unikernels running on [Solo5][solo5] and
[Unikraft][unikraft]. It replaces [mirage-tcpip][mirage-tcpip] with a
direct-style API powered by [Miou][miou] and OCaml 5 effects.

The library also provides TLS (via [ocaml-tls][ocaml-tls]), DNS resolution (via
[ocaml-dns][ocaml-dns]), and the [Happy Eyeballs][rfc8305] connection algorithm
(via [happy-eyeballs][happy-eyeballs]).

## Features

- **IPv4** with ARPv4, ICMPv4, and packet fragmentation/reassembly
- **IPv6** with Neighbor Discovery (NDPv6), router discovery, and PMTU
- **TCP** via [utcp][utcp] with a Unix-socket-like API (`connect`, `listen`,
  `accept`, `read`, `write`, `close`)
- **UDP** with `sendto`/`recvfrom`
- **TLS** via [ocaml-tls][ocaml-tls] for encrypted connections
- **DNS** resolver via [ocaml-dns][ocaml-dns] with TCP and UDP transports
- **Happy Eyeballs** ([RFC 8305][rfc8305]) for fast dual-stack connections

## Installation

`mnet` requires OCaml 5. It is also necessary to launch unikernels via
virtualisation (KVM, BHyve, VMM). Your processor must therefore be configured to
allow virtualisation (VT-x, AMD-V).

```shell
opam pin add mnet https://github.com/robur-coop/mnet.git
opam install mnet mnet-tls mnet-dns mnet-happy-eyeballs
```

## Quick start

### Initializing the stack

Every unikernel starts by creating a network stack via `Mkernel.run`. The stack
needs a random number generator and an CIDRv4 (the IPv4 address of the
unikernel). It is also possible to assign an IPv6 address to the unikernel. The
DHCP protocol has not yet been implemented.

```ocaml
let ( let@ ) finally fn = Fun.protect ~finally fn
module RNG = Mirage_crypto_rng.Fortuna

let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]

let () =
  Mkernel.(run [ rng; Mnet.stack ~name:"service" ~gateway cidr ])
  @@ fun rng (stack, tcp, udp) () ->
  let@ () = fun () -> Mnet.kill stack in
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  (* use [tcp] and [udp] here *)
  ()
```

The `name` parameter corresponds to the Solo5 network device. To launch the
unikernel, you must allocate a virtual Ethernet interface (a tap interface) and
you can launch the unikernel in this way:

```shell
$ sudo ip link add name br0 type bridge
$ sudo ip addr add 10.0.0.1/24 dev br0
$ sudo ip tuntap add name tap0 mode tap
$ sudo ip link set tap0 master br0 
$ solo5-hvt --net:service=tap0 -- unikernel.hvt --ipv4=10.0.0.2/24
```

## Packages

| Package               | Description                                    |
|-----------------------|------------------------------------------------|
| `mnet`                | Core TCP/IP stack (IPv4, IPv6, TCP, UDP)       |
| `mnet-tls`            | TLS support via [ocaml-tls][ocaml-tls]         |
| `mnet-dns`            | DNS client via [ocaml-dns][ocaml-dns]          |
| `mnet-happy-eyeballs` | Happy Eyeballs connection algorithm (RFC 8305) |

## End-to-end tests

`mnet` provides end-to-end tests that compile and run real unikernels. This
requires:

- **sudo** access (to create tap interfaces)
- **KVM** access (membership in the `kvm` group on Linux)
- The development version of `mnet` pinned in opam

```shell
git clone https://github.com/robur-coop/mnet
cd mnet
opam pin add -y .
sudo true
dune runtest --profile=unikernels
```

[mkernel]: https://git.robur.coop/robur/mkernel
[utcp]: https://github.com/robur-coop/utcp
[solo5]: https://github.com/solo5/solo5
[unikraft]: https://unikraft.org/
[miou]: https://github.com/robur-coop/miou
[mirage-tcpip]: https://github.com/mirage/mirage-tcpip
[ocaml-tls]: https://github.com/mirleft/ocaml-tls
[ocaml-dns]: https://github.com/mirage/ocaml-dns
[rfc8305]: https://www.rfc-editor.org/rfc/rfc8305
