module RNG = Mirage_crypto_rng.Fortuna
module Hash = Digestif.SHA1
let ( let@ ) finally fn = Fun.protect ~finally fn

let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]

let source_of_flow ?(close= ignore) flow =
  let init () = (flow, Bytes.create 0x7ff)
  and pull (flow, buf) =
    match Mnet.TCP.read flow buf with
    | exception _ | 0 -> None
    | len ->
        let str = Bytes.sub_string buf 0 len in
        Some (str, (flow, buf))
  and stop (flow, _) = close flow in
  Flux.Source { init; pull; stop }

let sink_of_flow ?(close= ignore) flow =
  let init () = flow
  and push flow str = Mnet.TCP.write flow str; Miou.yield (); flow
  and full = Fun.const false
  and stop flow = close flow in
  Flux.Sink { init; push; full; stop }

let handler flow =
  let from = source_of_flow flow in
  let via = Flux.Flow.identity in
  let into = sink_of_flow flow in
  let (), src = Flux.Stream.run ~from ~via ~into in
  Option.iter Flux.Source.dispose src;
  Mnet.TCP.close flow

let rec clean_up orphans = match Miou.care orphans with
  | None | Some None -> ()
  | Some (Some prm) ->
      let result = Miou.await prm in
      let fn err = Logs.err (fun m -> m "Unexpected error: %S" (Printexc.to_string err)) in
      Result.iter_error fn result;
      clean_up orphans

let rec terminate orphans = match Miou.care orphans with
  | None -> ()
  | Some None -> Mkernel.sleep 100_000_000; terminate orphans
  | Some (Some prm) ->
      let result = Miou.await prm in
      let fn err = Logs.err (fun m -> m "Unexpected error: %S" (Printexc.to_string err)) in
      Result.iter_error fn result;
      terminate orphans

let run _quiet cidrv4 gateway cidrv6 mode =
  Mkernel.(run [ rng; Mnet.stack ~name:"service" ?gateway ~ipv6:cidrv6 cidrv4 ])
  @@ fun rng (daemon, tcp, _udp) () ->
  let hed, he = Mnet_happy_eyeballs.create tcp in
  let@ () = fun () -> Mnet_happy_eyeballs.kill hed in
  let@ () = fun () -> Mnet.kill daemon in
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  match mode with
  | `Server (port, limit) ->
      let rec go orphans listen limit =
        clean_up orphans;
        match limit with
        | Some limit when limit <= 0 -> ()
        | None | Some _ ->
          let flow = Mnet.TCP.accept tcp listen in
          let _ = Miou.async ~orphans @@ fun () -> handler flow in
          let limit = Option.map pred limit in
          go orphans listen limit in
      let orphans = Miou.orphans () in
      go orphans (Mnet.TCP.listen tcp port) limit;
      terminate orphans
  | `Client (edn, length) ->
      let result = match edn with
        | `Ipaddr edn -> Mnet_happy_eyeballs.connect_ip he [ edn ]
        | `Domain domain_name -> Mnet_happy_eyeballs.connect_host he domain_name [ 9000 ] in
      let flow = match result with
        | Ok (_, flow) -> flow
        | Error (`Msg msg) -> failwith msg in
      let@ () = fun () -> Mnet.TCP.close flow in
      let buf = Bytes.create 0x7ff in
      let rec go ctx0 ctx1 rem0 rem1  =
        let len = Int.min rem0 (Bytes.length buf) in
        Mirage_crypto_rng.generate_into buf len;
        Mnet.TCP.write flow (Bytes.to_string buf) ~off:0 ~len;
        let ctx0 = Digestif.SHA1.feed_bytes ctx0 buf ~off:0 ~len in
        let rem0 = rem0 - len in
        let len = Mnet.TCP.read flow buf in
        let ctx1 = Digestif.SHA1.feed_bytes ctx1 buf ~off:0 ~len in
        let rem1 = rem1 - len in
        if rem0 <= 0 && rem1 <= 0
        then Digestif.SHA1.(get ctx0, get ctx1)
        else if rem0 > 0 then go ctx0 ctx1 rem0 rem1
        else (* if rem1 > 0 *)
          let () = Mnet.TCP.shutdown flow `write in
          remaining (Digestif.SHA1.get ctx0) ctx1 rem1 
      and remaining hash0 ctx1 rem1 =
        match Mnet.TCP.read flow buf with
        | 0 -> hash0, Digestif.SHA1.get ctx1
        | len ->
            let ctx1 = Digestif.SHA1.feed_bytes ctx1 buf ~off:0 ~len in
            let rem1 = rem1 - len in
            if rem1 > 0 then remaining hash0 ctx1 rem1
            else hash0, Digestif.SHA1.get ctx1
      in
      let hash0, hash1 = go Digestif.SHA1.empty Digestif.SHA1.empty length length in
      if not (Digestif.SHA1.equal hash0 hash1) then exit 1

let run_client _quiet cidrv4 gateway cidrv6 edn length =
  run _quiet cidrv4 gateway cidrv6 (`Client (edn, length))

let run_server _quiet cidrv4 gateway cidrv6 port limit =
  run _quiet cidrv4 gateway cidrv6 (`Server (port, limit))

open Cmdliner

let output_options = "OUTPUT OPTIONS"
let verbosity = Logs_cli.level ~docs:output_options ()
let renderer = Fmt_cli.style_renderer ~docs:output_options ()

let utf_8 =
  let doc = "Allow binaries to emit UTF-8 characters." in
  Arg.(value & opt bool true & info [ "with-utf-8" ] ~doc)

let t0 = Mkernel.clock_monotonic ()
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let neg fn = fun x -> not (fn x)

let reporter sources ppf =
  let re = Option.map Re.compile sources in
  let print src =
    let some re = (neg List.is_empty) (Re.matches re (Logs.Src.name src)) in
    Option.fold ~none:true ~some re
  in
  let report src level ~over k msgf =
    let k _ = over (); k () in
    let pp header _tags k ppf fmt =
      let t1 = Mkernel.clock_monotonic () in
      let delta = Float.of_int (t1 - t0) in
      let delta = delta /. 1_000_000_000. in
      Fmt.kpf k ppf
        ("[+%a][%a]%a[%a]: " ^^ fmt ^^ "\n%!")
        Fmt.(styled `Blue (fmt "%04.04f"))
        delta
        Fmt.(styled `Cyan int)
        (Stdlib.Domain.self () :> int)
        Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src)
    in
    match (level, print src) with
    | Logs.Debug, false -> k ()
    | _, true | _ -> msgf @@ fun ?header ?tags fmt -> pp header tags k ppf fmt
  in
  { Logs.report }

let regexp =
  let parser str =
    match Re.Pcre.re str with
    | re -> Ok (str, `Re re)
    | exception _ -> error_msgf "Invalid PCRegexp: %S" str
  in
  let pp ppf (str, _) = Fmt.string ppf str in
  Arg.conv (parser, pp)

let sources =
  let doc = "A regexp (PCRE syntax) to identify which log we print." in
  let open Arg in
  value & opt_all regexp [ ("", `None) ] & info [ "l" ] ~doc ~docv:"REGEXP"

let setup_sources = function
  | [ (_, `None) ] -> None
  | res ->
      let res = List.map snd res in
      let res =
        List.fold_left
          (fun acc -> function `Re re -> re :: acc | _ -> acc)
          [] res
      in
      Some (Re.alt res)

let setup_sources = Term.(const setup_sources $ sources)

let setup_logs utf_8 style_renderer sources level =
  Option.iter (Fmt.set_style_renderer Fmt.stdout) style_renderer;
  Fmt.set_utf_8 Fmt.stdout utf_8;
  Logs.set_level level;
  Logs.set_reporter (reporter sources Fmt.stdout);
  Option.is_none level

let setup_logs =
  Term.(const setup_logs $ utf_8 $ renderer $ setup_sources $ verbosity)

let ipv4 =
  let doc = "The IPv4 address of the unikernel." in
  let ipaddr = Arg.conv (Ipaddr.V4.Prefix.of_string, Ipaddr.V4.Prefix.pp) in
  let open Arg in
  required & opt (some ipaddr) None & info [ "ipv4" ] ~doc ~docv:"IPv4"

let ipv6 =
  let doc = "The IPv6 address of the unikernel." in
  let parser str = match Ipaddr.V6.Prefix.of_string str with
    | Ok cidrv6 -> Ok (Mnet.IPv6.Static cidrv6)
    | Error _ as err -> err in
  let pp ppf = function
    | Mnet.IPv6.Static cidrv6 -> Ipaddr.V6.Prefix.pp ppf cidrv6
    | Mnet.IPv6.EUI64 -> Fmt.string ppf "eui64"
    | Mnet.IPv6.Random -> Fmt.string ppf "random" in
  let ipaddr = Arg.conv (parser, pp) in
  let open Arg in
  value & opt ipaddr Mnet.IPv6.EUI64 & info [ "ipv6" ] ~doc ~docv:"IPv6"

let ipv4_gateway =
  let doc = "The IPv4 gateway." in
  let ipaddr = Arg.conv (Ipaddr.V4.of_string, Ipaddr.V4.pp) in
  let open Arg in
  value & opt (some ipaddr) None & info [ "ipv4-gateway" ] ~doc ~docv:"IPv4"

let port =
  let doc = "The echo server port." in
  let open Arg in
  value & opt int 9000 & info [ "p"; "port" ] ~doc ~docv:"PORT"

let length =
  let doc = "Number of bytes we would like to send." in
  let open Arg in
  value & pos 1 int 4096 & info [] ~doc ~docv:"NUMBER"

let limit =
  let doc = "Number of clients that the server can handle. Then, it terminates." in
  let open Arg in
  value & opt (some int) None & info [ "limit" ] ~doc ~docv:"NUMBER"

let addr =
  let doc = "The address of the echo server." in
  let parser str = match Ipaddr.with_port_of_string ~default:9000 str with
    | Ok (ipaddr, port) -> Ok (`Ipaddr (ipaddr, port))
    | Error _ -> begin
        match Result.bind (Domain_name.of_string str) Domain_name.host with
        | Ok domain_name -> Ok (`Domain domain_name)
        | Error _ -> error_msgf "Invalid echo server: %S" str end in
  let pp ppf = function
    | `Ipaddr (ipaddr, port) -> Fmt.pf ppf "%a:%d" Ipaddr.pp ipaddr port
    | `Domain domain_name -> Domain_name.pp ppf domain_name in
  let ipaddr_and_port = Arg.conv (parser, pp) in
  let open Arg in
  required & pos 0 (some ipaddr_and_port) None & info [] ~doc ~docv:"IP:PORT"

let term_server =
  let open Term in
  const run_server
  $ setup_logs
  $ ipv4
  $ ipv4_gateway
  $ ipv6
  $ port
  $ limit

let cmd_server =
  let info = Cmd.info "server" in
  Cmd.v info term_server

let term_client =
  let open Term in
  const run_client
  $ setup_logs
  $ ipv4
  $ ipv4_gateway
  $ ipv6
  $ addr
  $ length

let cmd_client =
  let info = Cmd.info "client" in
  Cmd.v info term_client

let default =
  let open Term in
  ret (const (`Help (`Pager, None)))

let () =
  let doc = "A simple echo client/server as an unikernel" in
  let info = Cmd.info "echo" ~doc in
  let cmd = Cmd.group ~default info [ cmd_server; cmd_client ] in
  Cmd.(exit (eval cmd))
