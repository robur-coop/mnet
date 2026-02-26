# Web server

In the previous chapter, we built an echo server: a unikernel that accepts TCP
connections and sends back whatever it receives. Now we will take a bigger step
and implement an HTTP web server.

Between the raw Ethernet frames we started with and the HTTP protocol lies a
whole stack of intermediate layers (TCP, IP, TLS), each of which is interesting
in its own right. Later chapters may explore some of those layers. For now, we
jump straight to HTTP because it demonstrates something important: even though
a unikernel is a minimal, single-purpose system, it can host a fully featured
web service.

This chapter assumes you have already completed the [echo server][echo]
chapter. You should have a working build setup (`dune`, `dune-workspace`,
`manifest.json`) and a configured network (a tap interface `tap0` and a bridge
`br0`) on your host.

## Vendoring the dependencies

Building an HTTP server requires more libraries than a simple echo server. The
HTTP protocol is layered on top of several components: a parser, a serializer,
content-type handling, and a framework to tie them all together. We need to
vendor all of them into our project:

```shell
$ opam source flux --dir vendors/flux
$ opam source h1 --dir vendors/h1
$ opam source httpcats --dir vendors/httpcats
$ opam source mhttp --dir vendors/mhttp
$ opam source multipart_form-miou --dir vendors/multipart_form-miou
$ opam source prettym --dir vendors/prettym
$ opam source tls --dir vendors/tls
$ opam source x509 --dir vendors/x509
$ opam source vifu --dir vendors/vifu
```

That is quite a few packages, so let us walk through what each one does.

- The library we will interact with most directly is `vifu`. It is a web
  framework for OCaml 5 designed specifically for unikernels (the _u_ in `vifu`
  stands for _unikernel_). It provides routing, request handling, and response
  building: everything we need to define HTTP endpoints. `vifu` is the unikernel
  variant of [vif][vif], a web framework that [our cooperative][robur] uses in
  production for [builds.robur.coop][builds-robur]. If you are familiar with web
  frameworks such as Express (JavaScript) or Sinatra (Ruby), `vifu` fills the
  same role. We also recommend [this tutorial][vif-tutorial] on implementing a
  chatroom with websockets using Vif.
- Under the hood, `mhttp`, `h1`, and `httpcats` together implement the HTTP
  protocol for unikernels. They handle parsing of incoming HTTP requests and
  serialization of outgoing HTTP responses, so we do not have to deal with the
  wire format ourselves.
- `flux` is a streaming library used internally by the HTTP stack to process
  request and response bodies without buffering them entirely in memory. If you
  are interested in handling streams with Miou, we have written a
  [tutorial][flux-tutorial] on the subject.
- For file uploads, `multipart_form-miou` handles `multipart/form-data`
  parsing, which is the encoding that web browsers use when uploading files
  through an HTML form.
- Finally, `tls` and `x509` provide TLS encryption and X.509 certificate
  handling. Even though our example uses plain HTTP (no encryption), `vifu`
  depends on these libraries because it supports HTTPS out of the box.

> [!NOTE]
> As with the echo server, these dependencies must be vendored because
> cross-compilation with `ocaml-solo5` requires local access to all source
> code. See the [introduction](./introduction.md) for a reminder of why.

## A minimal web server

The only change to the build configuration compared to the echo server is
adding `vifu` (and its dependency `gmp`) to the library list in the `dune`
file. The `dune-workspace`, `dune-project`, and `manifest.json` files remain
the same:

```diff
- (libraries mkernel mirage-crypto-rng-mkernel mnet)
+ (libraries mkernel mirage-crypto-rng-mkernel mnet vifu gmp)
```

Here is the complete web server:

```ocaml
module RNG = Mirage_crypto_rng.Fortuna

let ( let@ ) finally fn = Fun.protect ~finally fn
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]

let index req _server () =
  let open Vifu.Response.Syntax in
  let* () = Vifu.Response.with_text req "Hello World!\n" in
  Vifu.Response.respond `OK

let () =
  let ipv4 = Ipaddr.V4.Prefix.of_string_exn "10.0.0.2/24" in
  Mkernel.(run [ rng; Mnet.stack ~name:"service" ipv4 ])
  @@ fun rng (stack, tcp, _udp) () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill stack in
  let cfg = Vifu.Config.v 80 in
  let routes =
    let open Vifu.Uri in
    let open Vifu.Route in
    [ get (rel /?? any) --> index ] in
  Vifu.run ~cfg tcp routes ()
```

The first half is the same initialization and cleanup boilerplate from the echo
server. The new part is the `index` handler and the route table.

The `index` handler receives an HTTP request, sets the response body to
`"Hello World!\n"` using `with_text`, and responds with HTTP status 200
(`OK`). The `let*` syntax, provided by `Vifu.Response.Syntax`, sequences these
response-building operations.

The route table maps URL patterns to handlers. Here we define a single route.
- The `get` combinator matches HTTP GET requests.
- The `rel` part starts a URL pattern relative to the root `/`.
- Adding `/?? any` tells the route to accept any query string on that path.
- Finally, `-->` connects the pattern to the `index` handler.

So this route matches `GET /` (with or without query parameters) and calls
`index`. The [vif tutorial][vif-route] covers the routing DSL in more
detail, including how to capture path segments and query parameters.

The last two lines tie everything together. `Vifu.Config.v 80` configures the
server to listen on port 80. `Vifu.run` takes the TCP state from our network
stack and the route table, then starts serving HTTP requests. Unlike the echo
server, where we wrote the accept loop ourselves, `vifu` handles connection
management, HTTP parsing, and request dispatching for us.

## Building and running

The build and launch steps are identical to the echo server. If you have not
set up the network yet, the [echo chapter](./echo.md) walks you through it.

```shell
$ dune build ./main.exe
$ solo5-hvt --net:service=tap0 -- ./_build/solo5/main.exe --solo5:quiet &
$ UNIKERNEL=$!
$ curl http://10.0.0.2/
Hello World!
$ kill $UNIKERNEL
solo5-hvt: Exiting on signal 15
```

With just a few lines of OCaml, we have a working HTTP server running as a
unikernel. You can also point a web browser at `http://10.0.0.2/` and see the
same result.

## Crunch & Zip!

A plain-text "Hello World" is nice, but a real web service needs to serve HTML
pages, stylesheets, and other assets. To show what `vifu` can do, we are going
to build a small but practical service: a web page where users can upload files
and receive a zip archive in return. This raises two questions. First, how do
we serve static files (such as `index.html`) from a unikernel that has no file
system? And second, how do we receive uploaded files from the user and zip
them? Let us tackle the first question now.

### How to open a file?

A unikernel has access to a block device (essentially a raw disk), but there is
no file system built on top of it. We _could_ implement one, but that would add
significant complexity for what is actually a simple need: serving files whose
content is known at build time and never changes at runtime.

Instead of reading files from disk, we can _embed_ them directly into the
unikernel binary. The idea is straightforward: a tool reads our files at build
time and generates an OCaml module where each file's content is available as a
plain value. That module is compiled and linked into the unikernel like any
other code. At runtime, serving a file is just reading an OCaml value. No I/O,
no file system, no overhead.

The tool for this job is `mcrunch`. You can install it with:
```shell
$ opam install mcrunch
```

This is a great example of one of the most powerful advantages of the unikernel
approach: we get to rethink what our application truly needs instead of
carrying along assumptions from traditional operating systems. In a
conventional server, we would reach for a file system without a second thought.
But a file system is a remarkably complex piece of software: it handles
permissions, directories, concurrent writes, journaling, and much more. Do we
actually need all of that here? For our web service, the answer is clearly no.
Our HTML and CSS files are known at build time, they never change at runtime,
and we only need to read them. There is no need for write access, no need for a
directory hierarchy, and we are only dealing with a couple of small files.

Once we recognize this, we can choose a much simpler solution: embed the file
contents directly into our binary. This is what we mean by reifying the
building blocks of our application. Instead of pulling in a general-purpose
abstraction such as a file system, we pick the simplest tool that actually
solves our problem. The unikernel philosophy encourages this kind of thoughtful
minimalism, and `mcrunch` is a perfect example of it in practice.

Let us create a small upload page. Save the following as `index.html`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Upload</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <h3>File selection</h3>
    <form action="/upload" method="POST" enctype="multipart/form-data">
        <div id="file-list">
            <div class="file-group">
                <input type="file" name="files[]" required>
            </div>
        </div>

        <div class="controls">
            <button type="button" onclick="addFileField()">+ Add a field</button>
        </div>

        <div class="submit-area">
            <button type="submit" class="btn-submit">Start archiving</button>
        </div>
    </form>
    <script>
        function addFileField() {
            const container = document.getElementById('file-list');
            const group = document.createElement('div');
            group.className = 'file-group';

            group.innerHTML = `
                <input type="file" name="files[]" required>
                <button type="button" class="btn-remove" onclick="this.parentElement.remove()">Remove</button>
            `;

            container.appendChild(group);
        }
    </script>
</body>
</html>
```

And the accompanying `style.css`:
```css
body {
    font-family: ui-sans-serif, system-ui, sans-serif;
    color: #1a1a1a;
    margin: 40px;
    line-height: 1.5;
}

form { max-width: 500px; }

.file-group {
    display: flex;
    align-items: center;
    margin-bottom: 8px;
    gap: 12px;
}

input[type="file"] {
    font-size: 13px;
    border: 1px solid #ddd;
    padding: 4px;
    flex-grow: 1;
}

button {
    background: none;
    border: 1px solid #1a1a1a;
    color: #1a1a1a;
    padding: 4px 12px;
    font-size: 13px;
    cursor: pointer;
    transition: all 0.2s;
}

button:hover {
    background: #1a1a1a;
    color: white;
}

.btn-remove {
    border-color: #ccc;
    color: #666;
}

.controls {
    margin-top: 20px;
    display: flex;
    gap: 10px;
    border-top: 1px solid #eee;
    padding-top: 20px;
}

.submit-area { margin-top: 10px; }
.btn-submit { background: #1a1a1a; color: white; width: 100%; padding: 8px; }
```

The page displays a form that lets users select one or more files and submit
them via a POST request to `/upload`. The JavaScript function `addFileField()`
adds extra file inputs dynamically so that users can upload multiple files at
once. We will implement the `/upload` handler later; for now, let us focus on
serving these two files.

Then, to embed `index.html` and `style.css` into the unikernel, we update the
`dune` file with two changes: we add the `documents` module to the executable,
and we add a rule that generates it at build time using `mcrunch`.
```dune
(executable
 (name main)
 (modules main documents)
 (link_flags :standard -cclib "-z solo5-abi=hvt")
 (libraries mkernel mirage-crypto-rng-mkernel mnet vifu gmp)
 (foreign_stubs
  (language c)
  (names manifest)))

(rule
 (targets documents.ml)
 (deps index.html style.css)
 (action
  (run mcrunch --list --file index:index.html --file style:style.css -o documents.ml)))
```

The `mcrunch` command reads our two files and generates a `documents.ml` file
containing two OCaml values: `Documents.index` and `Documents.style`. Each
value holds the file's content as a `string list`.

A couple of details are worth noting about this command. The
`--file index:index.html` syntax maps an OCaml value name (`index`) to a
source file on disk (`index.html`); the colon separates the two. The `--list`
flag tells `mcrunch` to produce `string list` values rather than an array. This
matters because it works naturally with the streaming API we will use next: the
content can be sent to the client incrementally, without first concatenating
everything into a single buffer.

Now we replace our plain-text handler `index` with two handlers that serve the
embedded files:
```ocaml
let index req _server () =
  let open Vifu.Response.Syntax in
  let from = Flux.Source.list Documents.index in
  let* () = Vifu.Response.with_source req from in
  Vifu.Response.respond `OK

let style req _server () =
  let open Vifu.Response.Syntax in
  let from = Flux.Source.list Documents.style in
  let* () = Vifu.Response.with_source req from in
  Vifu.Response.respond `OK
```

Instead of `with_text` (which takes a plain string), we now use `with_source`,
which takes a _flux source_ (a stream of data). `Flux.Source.list` creates a
source from the `string list` that `mcrunch` generated. The response body is
then sent to the client piece by piece, which is more memory-efficient than
building the entire response as a single string.

Finally, we add a route for the stylesheet:
```ocaml
let routes =
  let open Vifu.Uri in
  let open Vifu.Route in
  [ get (rel /?? any) --> index
  ; get (rel / "style.css" /?? any) --> style ]
```

The first route matches `GET /` and serves the HTML page. The second route
matches `GET /style.css`. When the browser loads `index.html` and encounters
the `<link rel="stylesheet" href="style.css">` tag, it makes a second request
for `/style.css`, which is handled by the `style` handler.

### Zip on the fly

Let us continue building our service by adding a handler for the `POST /upload`
endpoint. When a user submits the upload form, the browser sends the selected
files as a `multipart/form-data` request. Our handler will read those files,
pack them into a zip archive, and send the archive back as the response.

This is where we need to talk about memory. A unikernel has a fixed memory
budget (512 megabytes by default). That is far less than a typical server
application running on a machine with tens of gigabytes of RAM. If your
application tries to hold too much data in memory at once, it will not slow
down gracefully: it will crash with an `Out_of_memory` exception. This means
you need to think carefully about how your code consumes memory. In particular,
you want to avoid loading entire files into memory when you do not have to.

The solution here is streaming. Instead of reading all the uploaded files into
memory, building the zip archive in memory, and then sending it to the client,
we process the data incrementally: we read a piece of input, compress it, write
it to the output, and move on to the next piece. At no point does the full
content of any file need to exist in memory all at once.

The library that makes this possible is `flux`. It lets you describe data
transformations as pipelines of streams, where each stage produces and consumes
data in small chunks. If you want to understand streaming in more depth, the
[flux tutorial][flux-tutorial] covers the concepts in detail. On top of `flux`,
the `flux_zip` library knows how to produce zip archives from a stream of
files.

Here is the upload handler:

```ocaml
let nsec_per_day = Int64.mul 86_400L 1_000_000_000L
let ps_per_ns = 1_000L

let now_d_ps () =
  let nsec = Mkernel.clock_wall () in
  let nsec = Int64.of_int nsec in
  let days = Int64.div nsec nsec_per_day in
  let rem_ns = Int64.rem nsec nsec_per_day in
  let rem_ps = Int64.mul rem_ns ps_per_ns in
  (Int64.to_int days, rem_ps)

let now () = Ptime.v (now_d_ps ())

let gen =
  let tmp = Bytes.create 8 in
  fun () ->
    Mirage_crypto_rng.generate_into tmp 8;
    let bits = Bytes.get_int64_le tmp 0 in
    Fmt.str "%08Lx" bits

let into_queue q =
  let open Flux in
  let init = Fun.const q
  and push q x = Bqueue.put q x; q
  and full = Fun.const false
  and stop = Bqueue.close in
  Sink { init; push; full; stop }

let zip req _server _ =
  let open Vifu.Response.Syntax in
  match Vifu.Request.of_multipart_form req with
  | Error _ ->
      let* () = Vifu.Response.with_text req "Invalid multipart/form-data request" in
      Vifu.Response.respond `Bad_request
  | Ok stream ->
      let mtime = now () in
      let src = Flux.Source.with_task ~size:0x7ff @@ fun q ->
        let fn (part, orig) =
          let filename = Vifu.Multipart_form.filename part in
          let filename = Option.value ~default:(gen ()) filename in
          let src = Flux.Source.with_task ~size:0x7ff @@ fun q ->
            Flux.Stream.into (into_queue q) (Flux.Stream.from orig) in
          Flux_zip.of_filepath ~mtime filename src in
        let stream = Flux.Stream.map fn stream in
        Flux.Stream.into (into_queue q) stream in
      let stream = Flux.Stream.from src in
      let stream = Flux.Stream.via Flux_zip.zip stream in
      let* () = Vifu.Response.add ~field:"Content-Type" "application/zip" in
      let* () = Vifu.Response.with_stream req stream in
      Vifu.Response.respond `OK
```

The `zip` handler starts by asking `vifu` to parse the incoming request as
`multipart/form-data`. If the request is malformed, the handler responds with a
400 Bad Request error. If parsing succeeds, `vifu` gives us a stream of parts,
where each part represents one uploaded file.

The core of the handler builds a pipeline in several stages. The outer
`Flux.Source.with_task` creates a task that iterates over the uploaded parts.
For each part, it extracts the filename (or generates one with `gen` if the
browser did not provide one), then wraps the part's content into a flux source
using an inner `Flux.Source.with_task`. That source is passed to
`Flux_zip.of_filepath`, which produces a zip entry: a value that `flux_zip`
knows how to turn into the bytes of a zip archive. All these entries are
collected into a single stream, which is then piped through `Flux_zip.zip` to
produce the final zip output. The handler sets the response's `Content-Type` to
`application/zip` and sends the stream to the client with `with_stream`.

There is a subtle but important point here. When we write this code, nothing
actually happens yet. We are describing a transformation pipeline, not
executing it. The data only starts flowing when the client begins reading the
response. This is what makes the approach memory-efficient: the unikernel never
needs to hold the entire archive in memory. Each `Flux.Source.with_task`
creates a bounded queue (the `~size:0x7ff` parameter sets the upper bound), so
the amount of data in memory at any given moment is limited, regardless of how
large the uploaded files are. A user could upload a one-gigabyte file and the
unikernel would process it using only a few kilobytes of buffer space.

Finally, we need to add the new route to our route table:
```ocaml
let routes =
  let open Vifu.Uri in
  let open Vifu.Route in
  [ get (rel /?? any) --> index
  ; get (rel / "style.css" /?? any) --> style
  ; post Vifu.Type.multipart_form (rel / "upload" /?? any) --> zip ]
```

The `post` combinator matches HTTP POST requests, so this route handles
`POST /upload`, which is exactly what our HTML form submits to.

Build and launch the unikernel the same way as before. Open `http://10.0.0.2/`
in your browser, select a few files, click "Start archiving", and your browser
will download a zip file containing the uploaded files. You can test it also
with `curl`:
```shell
$ solo5-hvt --net:service=tap0 -- ./_build/solo5/main.exe --solo5:quiet &
$ UNIKERNEL=$!
$ curl -F file=@foo.txt -X POST http://10.0.0.2/upload -o foo.zip
$ unzip foo.zip
Archive:  foo.zip
  inflating: foo.txt
$ kill $UNIKERNEL
solo5-hvt: Exiting on signal 15
```

## Conclusion

We started this chapter with a three-line "Hello World" handler and ended with
a unikernel that accepts file uploads and produces zip archives on the fly.
Along the way, we saw how `vifu` provides a familiar web-framework experience
(handlers, routes, responses) even though there is no operating system
underneath, how `mcrunch` solves the static-file problem by embedding content
directly into the binary at build time, and how `flux` enables memory-efficient
streaming so that even a unikernel with a small memory budget can process large
files comfortably.

[vif]: https://github.com/robur-coop/vif
[vif-tutorial]: https://robur-coop.github.io/vif/
[robur]: https://robur.coop/
[builds-robur]: https://builds.robur.coop/
[echo]: ./echo.md
[flux-tutorial]: https://robur-coop.github.io/flux/local/flux/flux.html
[vif-route]: https://robur-coop.github.io/vif/my_first_vif_application.html#routes
