open Cmdliner

let s_network = "NETWORK"

let ipv4 =
  let doc = "The IPv4 address of the unikernel." in
  let ipaddr = Arg.conv (Ipaddr.V4.Prefix.of_string, Ipaddr.V4.Prefix.pp) in
  let open Arg in
  required
  & opt (some ipaddr) None
  & info [ "ipv4" ] ~doc ~docs:s_network ~docv:"IPv4"

let ipv6 =
  let doc = "The IPv6 address of the unikernel." in
  let parser str =
    match Ipaddr.V6.Prefix.of_string str with
    | Ok cidrv6 -> Ok (Mnet.IPv6.Static cidrv6)
    | Error _ as err -> err
  in
  let pp ppf = function
    | Mnet.IPv6.Static cidrv6 -> Ipaddr.V6.Prefix.pp ppf cidrv6
    | Mnet.IPv6.EUI64 -> Fmt.string ppf "eui64"
    | Mnet.IPv6.Random -> Fmt.string ppf "random"
  in
  let ipaddr = Arg.conv (parser, pp) in
  let open Arg in
  value
  & opt ipaddr Mnet.IPv6.EUI64
  & info [ "ipv6" ] ~doc ~docs:s_network ~docv:"IPv6"

let ipv4_gateway =
  let doc = "The IPv4 gateway." in
  let ipaddr = Arg.conv (Ipaddr.V4.of_string, Ipaddr.V4.pp) in
  let open Arg in
  value
  & opt (some ipaddr) None
  & info [ "ipv4-gateway" ] ~doc ~docs:s_network ~docv:"IPv4"

let setup ipv4 ipv4_gateway ipv6 = (ipv4, ipv4_gateway, ipv6)

let setup =
  let open Term in
  const setup $ ipv4 $ ipv4_gateway $ ipv6

let s_output = "OUTPUT OPTIONS"
let s_logs = "LOGS OPTIONS"
let verbosity = Logs_cli.level ~docs:s_logs ()
let renderer = Fmt_cli.style_renderer ~docs:s_output ()

let utf_8 =
  let doc = "Allow binaries to emit UTF-8 characters." in
  let open Arg in
  value & opt bool true & info [ "with-utf-8" ] ~doc ~docs:s_output

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
  value
  & opt_all regexp [ ("", `None) ]
  & info [ "l" ] ~doc ~docs:s_logs ~docv:"REGEXP"

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
