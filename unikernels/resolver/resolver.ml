module RNG = Mirage_crypto_rng.Fortuna
module Hash = Digestif.SHA1
let ( let@ ) finally fn = Fun.protect ~finally fn

let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]
let _5s = Duration.of_sec 5
let robur_coop = Domain_name.(host_exn (of_string_exn "robur.coop"))

let run _quiet (cidrv4, gateway, ipv6) nameservers =
  Mkernel.(run [ rng; Mnet.stack ~name:"service" ?gateway ~ipv6 cidrv4 ])
  @@ fun rng (daemon, tcp, udp) () ->
  let@ () = fun () -> Mnet.kill daemon in
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let hed, he = Mnet_happy_eyeballs.create tcp in
  let@ () = fun () -> Mnet_happy_eyeballs.kill hed in
  let dns = Mnet_dns.create ~nameservers (udp, he) in
  let t = Mnet_dns.transport dns in
  let@ () = fun () -> Mnet_dns.Transport.kill t in
  match Mnet_dns.gethostbyname dns robur_coop with
  | Ok ipv4 -> Fmt.pr "%a: %a\n%!" Domain_name.pp robur_coop Ipaddr.V4.pp ipv4
  | Error (`Msg msg) -> Fmt.epr "%s\n%!" msg

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

let nameserver_of_string str =
  let ( let* ) = Result.bind in
  begin match String.split_on_char ':' str with
    | "tls" :: rest ->
      let str = String.concat ":" rest in
      ( match String.split_on_char '!' str with
        | [ nameserver ] ->
          let* ipaddr, port = Ipaddr.with_port_of_string ~default:853 nameserver in
          let* authenticator = Ca_certs_nss.authenticator () in
          let* tls = Tls.Config.client ~authenticator () in
          Ok (`Tcp, `Tls (tls, ipaddr, port))
        | nameserver :: opt_hostname :: authenticator ->
          let* ipaddr, port = Ipaddr.with_port_of_string ~default:853 nameserver in
          let peer_name, data =
            match
              let* dn = Domain_name.of_string opt_hostname in
              Domain_name.host dn
            with
            | Ok hostname -> Some hostname, String.concat "!" authenticator
            | Error _ -> None, String.concat "!" (opt_hostname :: authenticator)
          in
          let* authenticator = match data with
            | "" -> Ca_certs_nss.authenticator ()
            | data ->
              let* a = X509.Authenticator.of_string data in
              Ok (a (fun () -> Some (Mirage_ptime.now ())))
          in
          let* tls = Tls.Config.client ~authenticator ?peer_name () in
          Ok (`Tcp, `Tls (tls, ipaddr, port))
        | [] -> assert false )
    | "tcp" :: nameserver ->
      let str = String.concat ":" nameserver in
      let* ipaddr, port = Ipaddr.with_port_of_string ~default:53 str in
      Ok (`Tcp, `Plaintext (ipaddr, port))
    | "udp" :: nameserver ->
      let str = String.concat ":" nameserver in
      let* ipaddr, port = Ipaddr.with_port_of_string ~default:53 str in
      Ok (`Udp, `Plaintext (ipaddr, port))
    | _ ->
      Error (`Msg ("Unable to decode nameserver " ^ str))
  end

let nsec_per_day = Int64.mul 86_400L 1_000_000_000L
let ps_per_ns = 1_000L

let time () =
  let nsec = Int64.of_int (Mkernel.clock_wall ()) in
  let days = Int64.div nsec nsec_per_day in
  let rem_ns = Int64.rem nsec nsec_per_day in
  let rem_ps = Int64.mul rem_ns ps_per_ns in
  Some (Ptime.v (Int64.to_int days, rem_ps))

let _8_8_8_8 = `Udp, `Plaintext (Ipaddr.of_string_exn "8.8.8.8", 53)

let uncensoreddns_org =
  let ipaddr = Ipaddr.of_string_exn "89.233.43.71" in
  let authenticator =
    X509.Authenticator.of_string
      "key-fp:SHA256:INSZEZpDoWKiavosV2/xVT8O83vk/RRwS+LTiL+IpHs="
  in
  let authenticator = Result.get_ok authenticator in
  let authenticator = authenticator time in
  let cfg = Tls.Config.client ~authenticator () in
  let cfg = Result.get_ok cfg in
  (`Tcp, `Tls (cfg, ipaddr, 853))

let nameservers =
  let doc = "A DNS nameserver." in
  let parser = nameserver_of_string in
  let pp ppf (proto, nameserver) =
    match proto, nameserver with
    | `Udp, `Plaintext (ipaddr, port) -> Fmt.pf ppf "udp:%a:%d" Ipaddr.pp ipaddr port
    | `Tcp, `Plaintext (ipaddr, port) -> Fmt.pf ppf "tcp:%a:%d" Ipaddr.pp ipaddr port
    | `Tcp, `Tls (_, ipaddr, port) -> Fmt.pf ppf "tls:%a:%d" Ipaddr.pp ipaddr port
    | `Udp, _ -> assert false in
  let open Arg in
  value & opt_all (conv (parser, pp)) [ uncensoreddns_org ] & info [ "n"; "nameserver" ] ~doc ~docv:"NAMESERVER"

let setup_nameservers nameservers =
  let fn = function
    | `Udp, ns -> Either.Left ns
    | `Tcp, ns -> Either.Right ns in
  match List.partition_map fn nameservers with
  | [], nss -> `Tcp, nss
  | nss, [] -> `Udp, nss
  | _ -> Fmt.failwith "It is impossible to mix multiple nameservers over TCP and UDP"

let setup_nameservers =
  let open Term in
  const setup_nameservers $ nameservers

let term =
  let open Term in
  const run
  $ setup_logs
  $ Mnet_cli.setup
  $ setup_nameservers

let cmd =
  let info = Cmd.info "dns" in
  Cmd.v info term

let () = Cmd.(exit (eval cmd))
