let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

open Cmdliner

let s_happy_eyeballs = "HAPPY EYEBALLS"

let timeout =
  let is_digit = function '0' .. '9' -> true | _ -> false in
  let parser str =
    let len =
      let len = ref 0 in
      while !len < String.length str && is_digit str.[!len] do
        incr len
      done;
      !len
    in
    let meter = String.sub str len (String.length str - len) in
    let value = String.sub str 0 len in
    match meter with
    | "ns" -> Ok (Int64.of_string value)
    | "us" -> Ok (Duration.of_us (int_of_string value))
    | "ms" -> Ok (Duration.of_ms (int_of_string value))
    | "sec" | "s" -> Ok (Duration.of_sec (int_of_string value))
    | "min" | "m" -> Ok (Duration.of_min (int_of_string value))
    | "hour" | "h" -> Ok (Duration.of_hour (int_of_string value))
    | _ -> error_msgf "Invalid time: %S" str
  in
  let parser str =
    try parser str with _exn -> error_msgf "Invalid time: %S" str
  in
  Arg.conv ~docv:"TIME" (parser, Duration.pp)

let aaaa_timeout =
  let doc = "The timeout applied to the IPv6 resolution." in
  let open Arg in
  value
  & opt timeout (Duration.of_ms 50)
  & info [ "aaaa-timeout" ] ~doc ~docv:"TIME" ~docs:s_happy_eyeballs

let connect_delay =
  let doc =
    "Time to repeat another connection attempt if the others don't respond."
  in
  let open Arg in
  value
  & opt timeout (Duration.of_ms 50)
  & info [ "connect-delay" ] ~doc ~docv:"TIME" ~docs:s_happy_eyeballs

let connect_timeout =
  let doc = "The timeout applied top $(b,connect())." in
  let open Arg in
  value
  & opt timeout (Duration.of_sec 10)
  & info [ "connect-timeout" ] ~doc ~docv:"TIME" ~docs:s_happy_eyeballs

let resolve_timeout =
  let doc = "The timeout applied to the domain-name resolution." in
  let open Arg in
  value
  & opt timeout (Duration.of_sec 1)
  & info [ "resolve-timeout" ] ~doc ~docv:"TIME" ~docs:s_happy_eyeballs

let resolve_retries =
  let doc = "The number $(i,N) of attempts to make a connection." in
  let open Arg in
  value
  & opt int 3
  & info [ "resolve-retries" ] ~doc ~docv:"NUMBER" ~docs:s_happy_eyeballs

type setup = {
    aaaa_timeout: int64
  ; connect_delay: int64
  ; connect_timeout: int64
  ; resolve_timeout: int64
  ; resolve_retries: int
}

let setup aaaa_timeout connect_delay connect_timeout resolve_timeout
    resolve_retries =
  {
    aaaa_timeout
  ; connect_delay
  ; connect_timeout
  ; resolve_timeout
  ; resolve_retries
  }

let setup =
  let open Term in
  const setup
  $ aaaa_timeout
  $ connect_delay
  $ connect_timeout
  $ resolve_timeout
  $ resolve_retries
