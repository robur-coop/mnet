`mnet` is a TCP/IP stack written entirely in OCaml, designed for unikernels. By
reimplementing the network stack in a memory-safe language, `mnet` benefits
from OCaml's type system and from the broader ecosystem of formal verification
tools that can produce correct-by-construction OCaml code. This means fewer
classes of bugs (no buffer overflows, no use-after-free) and a codebase that is
easier to audit and reason about than a traditional C implementation.

## A note on performance

Before going further, it is worth setting realistic expectations about
performance.

A pure OCaml TCP/IP stack will not match the raw throughput of an optimized
C implementation. The garbage collector introduces pause times, and OCaml's
memory representation adds some overhead compared to bare pointers and manual
memory management.

However, the language is only part of the story. Regardless of whether a
unikernel is written in OCaml or C, it faces an inherent I/O disadvantage
compared to an application running directly on the host. A regular process on
Linux can issue system calls that interact with the kernel's network stack
directly. A unikernel cannot: it runs inside a sandboxed environment and must
go through two layers of indirection to perform any I/O. First, the unikernel
issues a hypercall to the tender, which is the host-side process that manages
the virtual machine. Then, the tender issues a system call to the host kernel,
which actually performs the I/O. This double indirection adds latency to every
network operation. There are techniques to reduce this cost (for example,
shared-memory ring buffers between the tender and the unikernel, similar to
what `virtio` provides) but the overhead can never be fully eliminated. This is
a fundamental constraint of the isolation model, not a limitation of any
particular implementation.

If your goal is to build the fastest possible web server, a unikernel is not
the right tool. But raw throughput is rarely the only metric that matters.
Unikernels excel in other dimensions. They have a minimal attack surface
because there is no shell, no unused drivers, and no package manager, only the
code your application needs. They boot in milliseconds because there is no
operating system to initialize, and their images weigh only a few megabytes
compared to hundreds for a typical container. The per-instance cost of running
a unikernel is therefore very low.

These properties naturally lead to a different way of thinking about services.
Rather than building a single monolithic application, you can decompose your
system into small, focused unikernels, each one doing one thing, booting
quickly, and consuming minimal resources. The deployment cost per component
becomes low enough that this architecture is practical, not just theoretical.

In short, do not expect a unikernel to outperform a native application in I/O.
Instead, think of unikernels as a way to build smaller, safer, and more
composable services.

## Initialization

The TCP/IP stack depends on a source of randomness (for generating TCP sequence
numbers, IPv6 addresses, and so on). We use `mirage-crypto` with its
[Fortuna][fortuna] engine for this purpose. `mkernel` provides a mechanism to
declare the resources that a unikernel needs before it starts, including
devices (such as a network interface) and other values that require
initialization. To set up a working TCP/IP stack, we need three things: the
static IPv4 address to assign to the unikernel, an initialized random number
generator, and a network device (here named `"service"`).

```ocaml
module RNG = Mirage_crypto_rng.Fortuna

let ( let@ ) finally fn = Fun.protect ~finally fn
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]

let () =
  let ipv4 = Ipaddr.V4.Prefix.of_string_exn "10.0.0.2/24" in
  Mkernel.(run [ rng; Mnet.stack ~name:"service" ipv4 ])
  @@ fun rng (stack, _tcp, _udp) () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill stack in
  print_endline "Hello World!"
```

One important thing to notice in this code is the use of finalizers. Every
resource we create is paired with a cleanup function via the `let@` operator
(which is a shorthand for `Fun.protect ~finally`). This is not optional: Miou,
the scheduler used in our unikernels, requires that all resources be properly
released before the program exits. The random number generator, for instance,
spawns a background task that continuously feeds entropy to the Fortuna engine.
If that task is not terminated explicitly with
`Mirage_crypto_rng_mkernel.kill`, the scheduler will reject the program at
exit. You can take a look on our [Miou's tutorial][miou-task] for more
details.

The same principle applies to `mnet`. Calling `Mnet.stack` starts several
background daemons (an Ethernet frame reader, an ARP responder, TCP timers, and
others) that run for the entire lifetime of the stack. `Mnet.kill` terminates
all of them. Forgetting to call it would leave dangling tasks, which Miou
treats as an error.

This cleanup pattern is not specific to unikernels: it applies to every
application built with Miou. Whenever you create a long-lived resource, you
should attach a finalizer to ensure it is released, even if an exception
interrupts the normal control flow.

## Compilation

As explained in the introduction, cross-compiling a unikernel with `ocaml-solo5`
requires that the source code of all dependencies (including transitive ones) be
available locally in a `vendors/` directory. Our echo server depends on `mnet`
and its own transitive dependencies, so we need to vendor all of them:

```bash
$ opam source bstr --dir vendors/bstr
$ opam source mnet --dir vendors/mnet
$ opam source mirage-crypto-rng-mkernel --dir vendors/mirage-crypto-rng-mkernel
$ opam source gmp --dir vendors/gmp
$ opam source digestif --dir vendors/digestif
$ opam source kdf --dir vendors/kdf
$ opam source utcp --dir vendors/utcp
```

Next, we update the `dune` file to declare the libraries our unikernel depends
on, the Solo5 ABI we are targeting, and the C stub for the device manifest:

```dune
(executable
 (name main)
 (modules main)
 (link_flags :standard -cclib "-z solo5-abi=hvt")
 (libraries
  mkernel
  mirage-crypto-rng-mkernel
  mnet
  gmp)
 (foreign_stubs
  (language c)
  (names manifest)))
```

Finally, since our unikernel now uses a network device, we need to declare it
in `manifest.json`. The name `"service"` must match the `name` argument we
passed to `Mnet.stack` in the code above:

```json
{"type":"solo5.manifest","version":1,"devices":[{"name":"service","type":"NET_BASIC"}]}
```

> [!TIP]
> To simplify the workflow around device manifests, you can _run_ your unikernel
> as a regular executable, and it will print the manifest it expects to stdout:
> ```bash
> $ dune exec ./main.exe > manifest.json
> ```

## Network configuration

Before we can run our unikernel, we need to set up a virtual network on the
host. This step is necessary because a unikernel does not share the host's
network stack; it implements its own (that is the whole point of `mnet`). From
the unikernel's perspective, it is a machine with its own Ethernet interface,
its own IP address, and its own TCP/IP stack. It needs to be connected to a
network just like a physical machine would be plugged into a switch.

On Linux, we can create this virtual network using two standard kernel
features: [tap interfaces][tap-intf] and bridges (`bridge-utils`).

Think of a physical network in an office. Each computer has an Ethernet port
and a cable that runs to a switch (a box whose only job is to forward Ethernet
frames between the devices plugged into it). Any machine on the switch can talk
to any other machine on the same switch, because the switch delivers each frame
to the right port based on the destination MAC address. This forms what is
called a local network (or LAN).

We need to reproduce this setup virtually. A tap interface plays the role of
the Ethernet cable: it is a network device created by the Linux kernel that
behaves like a physical network card, except that no real hardware is involved.
When the tender (`solo5-hvt`) starts the unikernel, it attaches the unikernel's
network device to a tap interface. From that point on, every Ethernet frame
that the unikernel sends appears on the tap interface, and every frame written
to the tap interface is delivered to the unikernel. A bridge plays the role of
the switch: it connects several network interfaces together and forwards
Ethernet frames between them. When we attach the tap interface to a bridge, the
unikernel becomes part of the local network formed by that bridge, just as
plugging a cable into a switch makes a computer part of the office LAN.

There is one more piece to the puzzle. A local network lets machines talk to
each other, but it does not, by itself, provide access to the outside world. In
our office analogy, the switch connects the computers to each other, but there
must be a router somewhere that connects the office LAN to the internet. That
router is what we call a gateway: it is the machine that knows how to forward
packets beyond the local network. When a machine wants to reach an IP address
that is not on its local network, it sends the packet to the gateway, and the
gateway takes care of routing it further.

In our setup, the host plays the role of the gateway. We assign an IPv4 address
to the bridge, which gives the host a presence on the unikernel's local
network. The unikernel is then configured to use that address as its gateway.
When the unikernel wants to reach an address outside the local network (for
instance, a DNS server on the internet) it sends the packet to the host via the
bridge, and the host forwards it through its own network connection.

This is admittedly more of a system administration task than a development
task. The configuration we describe here is simple and generic; your network
topology may require adjustments. But it is worth understanding what these
pieces do, because a unikernel sits at the intersection of application
development and deployment. Appreciating both sides is part of what makes the
unikernel approach powerful.

Here is how to set this up on Linux:

```bash
$ sudo ip link add br0 type bridge
$ sudo ip addr add 10.0.0.1/24 dev br0
$ sudo ip tuntap add tap0 mode tap
$ sudo ip link set tap0 master br0
$ sudo ip link set br0 up
$ sudo ip link set tap0 up
```

The first command creates a bridge named `br0`. The second assigns it the
address `10.0.0.1` on the `10.0.0.0/24` subnet (this is the address the
unikernel will use as its gateway). The third command creates a tap interface
named `tap0`. The fourth attaches it to the bridge, and the last two bring both
interfaces up.

## Launching our unikernel

Now that the network is in place, we can run our unikernel. The
`--net:service=tap0` flag tells the tender to connect the unikernel's
`"service"` network device to the `tap0` interface we just created:

```bash
$ solo5-hvt --net:service=tap0 -- ./_build/solo5/main.exe --solo5:quiet
Hello World!
```

The output looks the same as before: the unikernel prints its message and
exits. But behind the scenes, something new happened. `mnet` initialized its
TCP/IP stack and connected to the virtual network. We can observe this by
capturing traffic on the bridge with `tcpdump`:

```bash
$ sudo tcpdump -i br0
listening on br0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
14:30:00.000000 ARP, Request who-has 10.0.0.2 tell 10.0.0.2, length 28
```

The ARP request you see is the unikernel announcing its presence on the local
network. It is asking _who has this IP address?_ to verify that no other
machine is already using it. This is a standard part of the IPv4 initialization
process (known as Gratuitous ARP).

## Implementing the echo server

We can now turn our "Hello World" unikernel into an actual echo server. The
idea is straightforward: we listen on a TCP port, accept incoming connections,
and for each client, read whatever they send and write it back until they
disconnect.

If you have already followed the [Miou tutorial][miou-tutorial], the
concurrency pattern will look familiar. Each client connection is handled in its
own Miou task, and we use Miou's _orphans_ mechanism to keep track of these
tasks and collect their results as they complete.

```ocaml
let handler flow =
  let finally = Mnet.TCP.close in
  let r = Miou.Ownership.create ~finally flow in
  Miou.Ownership.own r;
  let buf = Bytes.create 0x7ff in
  let rec go () =
    match Mnet.TCP.read flow buf with
    | 0 -> Miou.Ownership.release r
    | len ->
        let str = Bytes.sub_string buf 0 len in
        Mnet.TCP.write flow str;
        go () in
  go ()

let rec clean_up orphans =
  match Miou.care orphans with
  | Some None | None -> ()
  | Some (Some prm) ->
    match Miou.await prm with
    | Ok () -> clean_up orphans
    | Error exn ->
      Logs.err (fun m -> m "Unexpected exception: %s" (Printexc.to_string exn))

let () =
  let ipv4 = Ipaddr.V4.Prefix.of_string_exn "10.0.0.2/24" in
  Mkernel.(run [ rng; Mnet.stack ~name:"service" ipv4 ])
  @@ fun rng (stack, tcp, _udp) () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill stack in
  let rec go orphans listen =
    clean_up orphans;
    let flow = Mnet.TCP.accept tcp listen in
    let _ = Miou.async ~orphans @@ fun () -> handler flow in
    go orphans listen in
  go (Miou.orphans ()) (Mnet.TCP.listen tcp 9000)
```

The `handler` function is the per-client logic. It registers the TCP connection
(`flow`) with Miou's ownership system so that the connection is automatically
closed if the task is cancelled or crashes. It then enters a loop where it
reads into a buffer, writes back what was received, and repeats. When the
client closes the connection, `read` returns `0` and the handler releases the
resource.

The `clean_up` function iterates over completed tasks in the `orphans` set.
This is how Miou lets you collect the results of concurrent tasks without
blocking the accept loop. If a handler raised an unexpected exception, we log
it here rather than letting it propagate silently.

The main entry point ties everything together. It initializes the stack (as we
saw earlier), then enters an accept loop where it waits for a new client with
`Mnet.TCP.accept`, spawns a handler task with `Miou.async`, and repeats. The
`Mnet.TCP.listen` call prepares port 9000 for incoming connections, much like
the `listen` system call in the Unix socket API.

You will notice that the `mnet` API intentionally mirrors the Unix socket API.
The `listen`, `accept`, `read`, `write`, and `close` functions all work the way
you would expect. This is a deliberate design choice: rather than inventing a
new abstraction, we keep the interface familiar so that the only new concepts
you need to learn are related to the unikernel model itself, not to the
networking API.

## Testing the echo server

We can now build, launch, and test the echo server. We start the unikernel in
the background, then connect to it with `nc` (netcat) from the host:

```bash
$ solo5-hvt --net:service=tap0 -- ./_build/solo5/main.exe --solo5:quiet &
$ UNIKERNEL=$!
$ nc -q0 10.0.0.2 9000
Hello World!
Hello World!
^D
$ kill $UNIKERNEL
solo5-hvt: Exiting on signal 15
```

We type "Hello World!" and the unikernel sends it right back. Pressing `Ctrl-D`
closes the connection. The `$!` variable captures the PID of the background
process so that we can stop the unikernel cleanly with `kill` when we are done.

## Conclusion

And with that, we have a working echo server running as a unikernel. As you
have seen, the process is fairly straightforward once you know the key steps:
vendoring your dependencies, declaring your devices, and configuring the
virtual network on the host. The networking concepts (tap interfaces, bridges,
and gateways) may be new territory if you come from a pure application
development background, but they quickly become second nature with a bit of
practice.

Now that the foundations are in place, the fun really begins. In the next
chapter, we will build on what we have learned here and implement a web server.
Our [cooperative][robur] offers implementations of several protocols (such as
[ocaml-tls][ocaml-tls] or [ocaml-dns][ocaml-dns]) that you can use to provide
a wide range of services. We hope you are as excited as we are to see what you
will build next.

[miou-tutorial]: https://robur-coop.github.io/miou/echo.html
[ocaml-tls]: https://github.com/mirleft/ocaml-tls
[ocaml-dns]: https://github.com/mirage/ocaml-dns
[tap-intf]: https://en.wikipedia.org/wiki/TUN/TAP
[robur]: https://robur.coop/
[fortuna]: https://en.wikipedia.org/wiki/Fortuna_(PRNG)
[miou-task]: https://robur-coop.github.io/miou/retrospective.html#a-task-as-a-resource
