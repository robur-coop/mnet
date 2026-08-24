let s_dns = "DOMAIN NAME SYSTEM"

open Cmdliner

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
                Ok (a (fun () -> Some (Mkernel.now ())))
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

let uncensoreddns_org =
  let ipaddr = Ipaddr.of_string_exn "89.233.43.71" in
  let authenticator =
    X509.Authenticator.of_string
      "key-fp:SHA256:INSZEZpDoWKiavosV2/xVT8O83vk/RRwS+LTiL+IpHs="
  in
  let authenticator = Result.get_ok authenticator in
  let authenticator = authenticator (fun () -> Some (Mkernel.now ())) in
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

let setup nameservers =
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

let setup ?default () =
  let open Term in
  const setup $ nameservers ?default ()
