# Introduction

`mnet` is a library that provides the networking foundation for unikernels. It
enables you to build services ranging from public-facing web servers to more
specialized tools such as a DNS resolver (to circumvent censorship) or a DNS
blocker (to filter out advertising). In this short book, we will walk through
several practical examples that illustrate what unikernels in OCaml can do.

## What is a unikernel?

A unikernel is a specialized, single-purpose operating system that bundles your
application code with only the OS components it actually needs. Nothing more.
Instead of running your OCaml application on top of a general-purpose OS like
Linux (which ships with thousands of features you will never use), a unikernel
compiles your code directly with a minimal set of libraries that handle
networking, storage, and memory management.

The result is a single bootable image that runs inside a sandboxed environment.
There is no shell, no unnecessary drivers, and no multi-user support. It is just
your application and the bare minimum required to run it.

In practice, building an OCaml unikernel relies on two key components.
[Solo5][solo5] provides the sandboxed execution environment: it defines a
minimal, stable interface between your unikernel and the underlying host
(whether that host is a hypervisor such as KVM, or a sandboxed Linux process
using [seccomp][seccomp]). Solo5 handles the low-level details of how your
unikernel boots, accesses network interfaces, and reads from block devices. On
top of Solo5, [mkernel][`mkernel`] is a library that lets you write unikernels
in OCaml using the [Miou][miou] scheduler. It exposes the devices that Solo5
provides (network interfaces and block storage) and gives you a familiar OCaml
programming model for building your application.

When you compile your OCaml code with `mkernel`, the build system produces a
standalone image that can be launched using a Solo5 _tender_ (a small host-side
program such as `solo5-hvt`). The practical benefits are significant: a smaller
attack surface, faster boot times (often measured in milliseconds), a reduced
memory footprint, and simpler deployment (since the entire system is a single
artifact).

## The ecosystem for OCaml unikernels

`mnet` is part of a broader ecosystem of OCaml libraries that [our
cooperative][robur] maintains for unikernel development. The ecosystem provides
pure OCaml reimplementations of essential components (networking, cryptography,
and more) so that you can build fully self-contained applications without
relying on C bindings or system libraries. Let us introduce some of the
libraries we use throughout this tutorial.

1) At the foundation, [`mkernel`][mkernel] provides the runtime, including
   hypercalls for network and block devices, clock access, and integration with
   the Miou scheduler.
2) For networking, [`utcp`][utcp] is a pure OCaml implementation of the TCP
   protocol, used internally by `mnet`. It originated from a manual extraction
   of a [HOL4](https://hol-theorem-prover.org/) specification of the TCP state
   machine (described in detail [here][netsem]).
3) [`ocaml-solo5`](https://github.com/mirage/ocaml-solo5) is a variant of the
   OCaml compiler that targets Solo5, making cross-compilation possible.
4) On the cryptography side, [`mirage-crypto`][mirage-crypto] provides our
   cryptographic primitives, and some of its operations are derived from
   formally verified proofs in Rocq/Coq via the [fiat][fiat] project.

We will encounter many more of these libraries throughout this tutorial.

## Prerequisites

Unikernels require a different build process than standard executables. We are
actively improving the development workflow for `mkernel`, but it is still
evolving. Everything described in this tutorial is accurate and functional;
however, you can expect the process to become smoother and better documented
over time. To get started, you will need:
- OCaml version 5.0.0 or later,
- along with OPAM, the OCaml package manager (you can find installation
  instructions [here][opam-install]).
- You will also need [`ocaml-solo5`][ocaml-solo5], which lets you compile an
  OCaml project as a unikernel, as well as the Solo5 tools (`solo5-hvt` or
  `solo5-spt`) for running unikernels.
- Finally, you will need access to a hypervisor such as KVM, BHyve, or VMM.

You can install everything you need using these commands:
```bash
$ opam switch create 5.4.0
$ eval $(opam env)
$ opam install solo5
$ opam install ocaml-solo5
$ opam install mkernel
$ opam install mnet
```

To run a unikernel, you need access to a hypervisor or a sandboxing mechanism.
On Linux, the simplest option is KVM (Kernel-based Virtual Machine). You can
check whether your system supports it by running:
```bash
$ ls /dev/kvm
```

If this device exists, you are ready to go. You may need to add your user to
the `kvm` group so that you can access it without root privileges:
```bash
$ sudo usermod -aG kvm $USER
```

After running this command, log out and log back in for the change to take
effect. Once KVM is available, you can run your unikernel with the `solo5-hvt`
tender, which uses KVM to execute your image in an isolated virtual
environment.

## Your first unikernel

A unikernel is an executable that must be _cross-compiled_. This means it is
built using the `ocaml-solo5` compiler rather than the regular host compiler.
Because of this, the build configuration looks slightly different from what you
might be used to:
```bash
$ cat >dune<<EOF
(executable
 (name main)
 (modules main)
 (link_flags :standard -cclib "-z solo5-abi=hvt")
 (libraries mkernel)
 (foreign_stubs
  (language c)
  (names manifest)))

(rule
 (targets manifest.c)
 (deps manifest.json)
 (enabled_if
  (= %{context_name} "solo5"))
 (action
  (run solo5-elftool gen-manifest manifest.json manifest.c)))

(rule
 (targets manifest.c)
 (enabled_if
  (= %{context_name} "default"))
 (action
  (write-file manifest.c "")))

(vendored_dirs vendors)
EOF
```

To boot as quickly as possible, a unikernel does not perform _device
discovery_: it never asks the tender which devices are available. Instead, it
contains a **static** list of the devices it requires. This list is written as
a JSON file, which is then compiled into the `manifest.c` file that becomes
part of your unikernel:
```bash
$ cat >manifest.json<<EOF
{"type":"solo5.manifest","version":1,"devices":[]}
EOF
```

To cross-compile your executable with `ocaml-solo5`, you need to define a new
build context in the `dune-workspace` file:
```bash
$ cat >dune-workspace<<EOF
(lang dune 3.0)
(context (default))
(context (default
 (name solo5)
 (host default)
 (toolchain solo5)
 (disable_dynamically_linked_foreign_archives true)))
EOF
```

Cross-compilation requires that the source code of your dependencies (in this
case, `mkernel`) is available locally. You can fetch it with `opam source`:
```bash
$ mkdir vendors
$ opam source mkernel --dir vendors/mkernel
```

You can now create your unikernel:
```bash
$ cat >dune-project<<EOF
(lang dune 3.0)
EOF
$ cat >main.ml<<EOF
let () = Mkernel.(run []) @@ fun () ->
  print_endline "Hello World!"
EOF
$ dune build ./main.exe
```

Launching a unikernel is different from launching a regular executable, because
it runs as a virtual machine. You need to use a _tender_ to start it. Here, we
use `solo5-hvt`:
```bash
$ solo5-hvt -- _build/solo5/main.exe --solo5:quiet
Hello World!
```

Congratulations, you have just created your first unikernel! In the next
chapter, we will build a small `echo` server using `mnet` and set up networking
for your unikernel. Unikernels come with their own set of concepts and
constraints that are important to understand. The `mkernel`
[documentation][mkernel-doc] covers these fundamentals in depth, explaining how
Solo5 and OCaml fit together.

## Important constraints

There are two essential things to keep in mind when building unikernels.

The first is that the `Unix` module is not available. The `ocaml-solo5`
compiler does not provide the `unix.cmxa` library. Since there is no underlying
operating system, system calls like `Unix.openfile` or `Unix.socket` simply do
not exist. This means that any library, including transitive dependencies, that
relies on the `Unix` module cannot be used in a unikernel. In practice, this is
why our ecosystem relies on pure OCaml reimplementations of protocols and
services (networking, DNS, TLS, and so on) rather than wrappers around C system
libraries.

The second is that dependencies must be vendored. Nearly all of your
dependencies need to have their source code present locally in a `vendors/`
directory. This is because cross-compilation with `ocaml-solo5` requires
compiling C stubs (if any) with the Solo5 toolchain, which is only possible
when `dune` has direct access to the source files. You can vendor a dependency
with `opam source`:
```bash
$ opam source <package> --dir vendors/<package>
```
This must be done for every dependency that your unikernel uses, not just your
direct dependencies, but their transitive dependencies as well.

[netsem]: https://www.cl.cam.ac.uk/~pes20/Netsem/paper3.pdf
[opam-install]: https://opam.ocaml.org/doc/Install.html
[ocaml-solo5]: https://github.com/mirage/ocaml-solo5
[solo5]: https://github.com/solo5/solo5
[seccomp]: https://en.wikipedia.org/wiki/Seccomp
[mkernel]: https://github.com/robur-coop/mkernel
[mkernel-doc]: https://robur-coop.github.io/mkernel/local/mkernel/Mkernel/index.html
[miou]: https://github.com/robur-coop/miou
[mirage-crypto]: https://github.com/mirage/mirage-crypto
[robur]: https://robur.coop
[utcp]: https://github.com/robur-coop/utcp
[fiat]: https://github.com/mit-plv/fiat-crypto
