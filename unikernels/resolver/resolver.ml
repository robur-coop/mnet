module RNG = Mirage_crypto_rng.Fortuna
module Hash = Digestif.SHA1

let ( let@ ) finally fn = Fun.protect ~finally fn
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]
let _5s = Duration.of_sec 5

let run _quiet stack nameservers host =
  Mkernel.(run [ rng; stack ])
  @@ fun rng (daemon, tcp, udp) () ->
  let@ () = fun () -> Mnet.kill daemon in
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let hed, he = Mnet_happy_eyeballs.create tcp in
  let@ () = fun () -> Mnet_happy_eyeballs.kill hed in
  let stack = Mnet_dns.Transport.stack udp he in
  let dns = Mnet_dns.create ~nameservers stack in
  let t = Mnet_dns.transport dns in
  let@ () = fun () -> Mnet_dns.Transport.kill t in
  match Mnet_dns.gethostbyname dns host with
  | Ok ipv4 -> Fmt.pr "%a: %a\n%!" Domain_name.pp host Ipaddr.V4.pp ipv4
  | Error (`Msg msg) -> Fmt.epr "%s\n%!" msg

open Cmdliner

let host =
  let doc = "Hostname to query for." in
  let parser s = Result.bind (Domain_name.of_string s) Domain_name.host in
  let robur_coop = Domain_name.(host_exn (of_string_exn "robur.coop")) in
  let open Arg in
  value
  & opt (conv (parser, Domain_name.pp)) robur_coop
  & info [ "host" ] ~doc ~docv:"HOST"

let term =
  let open Term in
  const run $ Mnet_cli.setup_logs $ Mnet_cli.setup "service" $ Mnet_dns_cli.setup () $ host

let cmd =
  let info = Cmd.info "dns" in
  Cmd.v info term

let () = Cmd.(exit (eval cmd))
