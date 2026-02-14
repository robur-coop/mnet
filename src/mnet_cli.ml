open Cmdliner

let ipv4 =
  let doc = "The IPv4 address of the unikernel." in
  let ipaddr = Arg.conv (Ipaddr.V4.Prefix.of_string, Ipaddr.V4.Prefix.pp) in
  let open Arg in
  required & opt (some ipaddr) None & info [ "ipv4" ] ~doc ~docv:"IPv4"

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
  value & opt ipaddr Mnet.IPv6.EUI64 & info [ "ipv6" ] ~doc ~docv:"IPv6"

let ipv4_gateway =
  let doc = "The IPv4 gateway." in
  let ipaddr = Arg.conv (Ipaddr.V4.of_string, Ipaddr.V4.pp) in
  let open Arg in
  value & opt (some ipaddr) None & info [ "ipv4-gateway" ] ~doc ~docv:"IPv4"

let setup ipv4 ipv4_gateway ipv6 = (ipv4, ipv4_gateway, ipv6)

let setup =
  let open Term in
  const setup $ ipv4 $ ipv4_gateway $ ipv6
