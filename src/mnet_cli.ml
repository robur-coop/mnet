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

let s_dns = "DOMAIN NAME SYSTEM"

type nameserver =
  [ `Tls of Tls.Config.client * Ipaddr.t * int | `Plaintext of Ipaddr.t * int ]

let nameserver_of_string str =
  let ( let* ) = Result.bind in
  begin match String.split_on_char ':' str with
  | "tls" :: rest -> (
      let str = String.concat ":" rest in
      match String.split_on_char '!' str with
      | [ nameserver ] ->
          let* ipaddr, port =
            Ipaddr.with_port_of_string ~default:853 nameserver
          in
          let* authenticator = Ca_certs_nss.authenticator () in
          let* tls = Tls.Config.client ~authenticator () in
          Ok (`Tcp, `Tls (tls, ipaddr, port))
      | nameserver :: opt_hostname :: authenticator ->
          let* ipaddr, port =
            Ipaddr.with_port_of_string ~default:853 nameserver
          in
          let peer_name, data =
            match
              let* dn = Domain_name.of_string opt_hostname in
              Domain_name.host dn
            with
            | Ok hostname -> (Some hostname, String.concat "!" authenticator)
            | Error _ ->
                (None, String.concat "!" (opt_hostname :: authenticator))
          in
          let* authenticator =
            match data with
            | "" -> Ca_certs_nss.authenticator ()
            | data ->
                let* a = X509.Authenticator.of_string data in
                Ok (a (fun () -> Some (Mirage_ptime.now ())))
          in
          let* tls = Tls.Config.client ~authenticator ?peer_name () in
          Ok (`Tcp, `Tls (tls, ipaddr, port))
      | [] -> assert false)
  | "tcp" :: nameserver ->
      let str = String.concat ":" nameserver in
      let* ipaddr, port = Ipaddr.with_port_of_string ~default:53 str in
      Ok (`Tcp, `Plaintext (ipaddr, port))
  | "udp" :: nameserver ->
      let str = String.concat ":" nameserver in
      let* ipaddr, port = Ipaddr.with_port_of_string ~default:53 str in
      Ok (`Udp, `Plaintext (ipaddr, port))
  | _ -> Error (`Msg ("Unable to decode nameserver " ^ str))
  end

let nsec_per_day = Int64.mul 86_400L 1_000_000_000L
let ps_per_ns = 1_000L

let time () =
  let nsec = Int64.of_int (Mkernel.clock_wall ()) in
  let days = Int64.div nsec nsec_per_day in
  let rem_ns = Int64.rem nsec nsec_per_day in
  let rem_ps = Int64.mul rem_ns ps_per_ns in
  Some (Ptime.v (Int64.to_int days, rem_ps))

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

let nameservers ?(default = [ uncensoreddns_org ]) () =
  let doc = "A DNS nameserver." in
  let parser = nameserver_of_string in
  let pp ppf (proto, nameserver) =
    match (proto, nameserver) with
    | `Udp, `Plaintext (ipaddr, port) ->
        Fmt.pf ppf "udp:%a:%d" Ipaddr.pp ipaddr port
    | `Tcp, `Plaintext (ipaddr, port) ->
        Fmt.pf ppf "tcp:%a:%d" Ipaddr.pp ipaddr port
    | `Tcp, `Tls (_, ipaddr, port) ->
        Fmt.pf ppf "tls:%a:%d" Ipaddr.pp ipaddr port
    | `Udp, _ -> assert false
  in
  let open Arg in
  value
  & opt_all (conv (parser, pp)) default
  & info [ "n"; "nameserver" ] ~doc ~docs:s_dns ~docv:"NAMESERVER"

let setup_nameservers nameservers =
  let fn = function
    | `Udp, ns -> Either.Left ns
    | `Tcp, ns -> Either.Right ns
  in
  match List.partition_map fn nameservers with
  | nss, [] -> (`Udp, nss)
  | [], nss -> (`Tcp, nss)
  | _ ->
      Fmt.failwith
        "It is impossible to mix multiple nameservers over TCP and UDP"

let setup_nameservers ?default () =
  let open Term in
  const setup_nameservers $ nameservers ?default ()

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

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

let s_happy_eyeballs = "HAPPY EYEBALLS"

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

type happy_eyeballs = {
    aaaa_timeout: int64
  ; connect_delay: int64
  ; connect_timeout: int64
  ; resolve_timeout: int64
  ; resolve_retries: int
}

let setup_happy_eyeballs aaaa_timeout connect_delay connect_timeout
    resolve_timeout resolve_retries =
  {
    aaaa_timeout
  ; connect_delay
  ; connect_timeout
  ; resolve_timeout
  ; resolve_retries
  }

let setup_happy_eyeballs =
  let open Term in
  const setup_happy_eyeballs
  $ aaaa_timeout
  $ connect_delay
  $ connect_timeout
  $ resolve_timeout
  $ resolve_retries
