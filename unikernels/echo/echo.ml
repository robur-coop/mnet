module RNG = Mirage_crypto_rng.Fortuna
module Hash = Digestif.SHA1

let ( let@ ) finally fn = Fun.protect ~finally fn
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]

let source_of_flow ?(close = ignore) flow =
  let init () = (flow, Bytes.create 0x7ff)
  and pull (flow, buf) =
    match Mnet.TCP.input flow buf with
    | (exception _) | 0 -> None
    | len ->
        let str = Bytes.sub_string buf 0 len in
        Some (str, (flow, buf))
  and stop (flow, _) = close flow in
  Flux.Source { init; pull; stop }

let sink_of_flow ?(close = ignore) flow =
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

let rec clean_up orphans =
  match Miou.care orphans with
  | None | Some None -> ()
  | Some (Some prm) ->
      let result = Miou.await prm in
      let fn err =
        Logs.err (fun m -> m "Unexpected error: %S" (Printexc.to_string err))
      in
      Result.iter_error fn result;
      clean_up orphans

let rec terminate orphans =
  match Miou.care orphans with
  | None -> ()
  | Some None -> Mkernel.sleep 100_000_000; terminate orphans
  | Some (Some prm) ->
      let result = Miou.await prm in
      let fn err =
        Logs.err (fun m -> m "Unexpected error: %S" (Printexc.to_string err))
      in
      Result.iter_error fn result;
      terminate orphans

let buffer = Mnet.TCP.buffer ~limit:(Some 0x4000) 0x2000

let run _quiet stack mode =
  Mkernel.(run [ rng; stack ])
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
            let flow = Mnet.TCP.accept ~kind:buffer tcp listen in
            let _ = Miou.async ~orphans @@ fun () -> handler flow in
            let limit = Option.map pred limit in
            go orphans listen limit
      in
      let orphans = Miou.orphans () in
      go orphans (Mnet.TCP.listen tcp port) limit;
      terminate orphans
  | `Client (edn, length) ->
      let result =
        match edn with
        | `Ipaddr edn -> Mnet_happy_eyeballs.connect_ip ~kind:buffer he [ edn ]
        | `Domain domain_name ->
            Mnet_happy_eyeballs.connect_host ~kind:buffer he domain_name
              [ 9000 ]
      in
      let flow =
        match result with
        | Ok (_, flow) -> flow
        | Error (`Msg msg) -> failwith msg
      in
      let@ () = fun () -> Mnet.TCP.close flow in
      let buf = Bytes.create 0x7ff in
      let rec go ctx0 ctx1 rem0 rem1 =
        let len = Int.min rem0 (Bytes.length buf) in
        Mirage_crypto_rng.generate_into buf len;
        Mnet.TCP.write flow (Bytes.to_string buf) ~off:0 ~len;
        let ctx0 = Digestif.SHA1.feed_bytes ctx0 buf ~off:0 ~len in
        let rem0 = rem0 - len in
        let len = Mnet.TCP.input flow buf in
        let ctx1 = Digestif.SHA1.feed_bytes ctx1 buf ~off:0 ~len in
        let rem1 = rem1 - len in
        if rem0 <= 0 && rem1 <= 0 then Digestif.SHA1.(get ctx0, get ctx1)
        else if rem0 > 0 then go ctx0 ctx1 rem0 rem1
        else (* if rem1 > 0 *)
          let () = Mnet.TCP.shutdown flow `write in
          remaining (Digestif.SHA1.get ctx0) ctx1 rem1
      and remaining hash0 ctx1 rem1 =
        match Mnet.TCP.input flow buf with
        | 0 -> (hash0, Digestif.SHA1.get ctx1)
        | len ->
            let ctx1 = Digestif.SHA1.feed_bytes ctx1 buf ~off:0 ~len in
            let rem1 = rem1 - len in
            if rem1 > 0 then remaining hash0 ctx1 rem1
            else (hash0, Digestif.SHA1.get ctx1)
      in
      let hash0, hash1 =
        go Digestif.SHA1.empty Digestif.SHA1.empty length length
      in
      if not (Digestif.SHA1.equal hash0 hash1) then exit 1

let run_client _quiet mnet edn length = run _quiet mnet (`Client (edn, length))
let run_server _quiet mnet port limit = run _quiet mnet (`Server (port, limit))

open Cmdliner

let port =
  let doc = "The echo server port." in
  let open Arg in
  value & opt int 9000 & info [ "p"; "port" ] ~doc ~docv:"PORT"

let length =
  let doc = "Number of bytes we would like to send." in
  let open Arg in
  value & pos 1 int 4096 & info [] ~doc ~docv:"NUMBER"

let limit =
  let doc =
    "Number of clients that the server can handle. Then, it terminates."
  in
  let open Arg in
  value & opt (some int) None & info [ "limit" ] ~doc ~docv:"NUMBER"

let addr =
  let doc = "The address of the echo server." in
  let parser str =
    match Ipaddr.with_port_of_string ~default:9000 str with
    | Ok (ipaddr, port) -> Ok (`Ipaddr (ipaddr, port))
    | Error _ ->
        begin match
          Result.bind (Domain_name.of_string str) Domain_name.host
        with
        | Ok domain_name -> Ok (`Domain domain_name)
        | Error _ -> error_msgf "Invalid echo server: %S" str
        end
  in
  let pp ppf = function
    | `Ipaddr (ipaddr, port) -> Fmt.pf ppf "%a:%d" Ipaddr.pp ipaddr port
    | `Domain domain_name -> Domain_name.pp ppf domain_name
  in
  let ipaddr_and_port = Arg.conv (parser, pp) in
  let open Arg in
  required & pos 0 (some ipaddr_and_port) None & info [] ~doc ~docv:"IP:PORT"

let term_server =
  let open Term in
  const run_server $ Mnet_cli.setup_logs $ Mnet_cli.setup "service" $ port $ limit

let cmd_server =
  let info = Cmd.info "server" in
  Cmd.v info term_server

let term_client =
  let open Term in
  const run_client $ Mnet_cli.setup_logs $ Mnet_cli.setup "service" $ addr $ length

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
