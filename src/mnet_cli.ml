(*
 * For the level part:
 *
 * Copyright (c) 2014 David Sheets <sheets@alum.mit.edu>
 * Copyright (c) 2023 Thomas Gazagnaire <thomas@gazagnaire.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

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

let ipv6_gateway =
  let doc = "The IPv6 gateway." in
  let ipaddr = Arg.conv (Ipaddr.V6.of_string, Ipaddr.V6.pp) in
  let open Arg in
  value
  & opt (some ipaddr) None
  & info [ "ipv6-gateway" ] ~doc ~docs:s_network ~docv:"IPv6"

let setup ~name ?max ipv4 gateway ipv6 ipv6_gateway =
  Mnet.stack ~name ?max ?gateway ~ipv6 ?ipv6_gateway ipv4

let setup ?max name =
  let open Term in
  const (setup ~name ?max) $ ipv4 $ ipv4_gateway $ ipv6 $ ipv6_gateway

let s_output = "OUTPUT OPTIONS"
let s_logs = "LOGS OPTIONS"
let renderer = Fmt_cli.style_renderer ~docs:s_output ()

let utf_8 =
  let doc = "Allow binaries to emit UTF-8 characters." in
  let open Arg in
  value & opt bool true & info [ "with-utf-8" ] ~doc ~docs:s_output

let t0 = Mkernel.clock_monotonic ()
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

type threshold = [ `All | `Src of string ] * Logs.level option

let threshold : threshold Arg.conv =
  let parser str =
    let source = function "*" -> `All | s -> `Src s in
    let level src s =
      match Logs.level_of_string s with
      | Ok s -> Ok (src, s)
      | Error _ as e -> e
    in
    match String.split_on_char ':' str with
    | [ src; "-" ] -> Ok (source src, None)
    | [ src; lvl ] -> level (source src) lvl
    | _ -> error_msgf "Invalid threshold: %s" str
  in
  let serialize ppf = function
    | `All, l -> Format.pp_print_string ppf (Logs.level_to_string l)
    | `Src s, l -> Format.fprintf ppf "%s:%s" s (Logs.level_to_string l)
  in
  Arg.conv (parser, serialize)

let setup_levels ~default l =
  let srcs = Logs.Src.list () in
  let default =
    try snd @@ List.find (function `All, _ -> true | _ -> false) l
    with Not_found -> default
  in
  Logs.set_level default;
  let fn = function
    | `All, _ -> ()
    | `Src src, level ->
        begin try
          let s = List.find (fun s -> Logs.Src.name s = src) srcs in
          Logs.Src.set_level s level
        with Not_found ->
          Logs.warn (fun m -> m "%s is not a valid log source" src)
        end
  in
  List.iter fn l; default

let levels ?(docs = s_logs) () =
  let logs = Arg.list threshold in
  let env = Cmd.Env.info "LOGS_LEVELS" in
  let doc =
    "Be more or less verbose. $(docv) must be of the form \
     $(b,'*:info,foo:debug') means that that the log threshold is set to \
     $(b,'info') for every log sources but the $(b,'foo') which is set to \
     $(b,'debug'). Use $(b,'quiet') or $(b,'-') to disable a souce. And \
     $(b,'*') to consider all sources. For instance $(b, '*-,foo:debug') \
     disable all sources but $(b,foo) which is set to $(b, debug).'"
  in
  let doc = Arg.info ~env ~docv:"LEVEL" ~doc ~docs [ "l"; "logging-levels" ] in
  Arg.(value & opt logs [] doc)

let setup_levels =
  let open Term in
  const (fun default levels -> setup_levels ~default levels)
  $ Logs_cli.level ~docs:s_logs ()
  $ levels ~docs:s_logs ()

let reporter ppf =
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
    msgf @@ fun ?header ?tags fmt -> pp header tags k ppf fmt
  in
  { Logs.report }

let setup_logs utf_8 style_renderer level =
  Option.iter (Fmt.set_style_renderer Fmt.stdout) style_renderer;
  Fmt.set_utf_8 Fmt.stdout utf_8;
  Logs.set_reporter (reporter Fmt.stdout);
  Option.is_none level

let setup_logs = Term.(const setup_logs $ utf_8 $ renderer $ setup_levels)
