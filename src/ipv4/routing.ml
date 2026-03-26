type r = Mac of Macaddr.t | Arp of Ipaddr.V4.t

let routing network gateway ~src ~dst =
  if Ipaddr.V4.Prefix.(mem dst loopback) || Ipaddr.V4.Prefix.(mem src loopback)
  then
    (* avoid packets to or from 127.0.0.0/8 *)
    Error `Loopback
  else if
    Ipaddr.V4.(compare broadcast) dst == 0
    || Ipaddr.V4.(compare (Prefix.broadcast network)) dst == 0
  then
    (* use broadcast mac *)
    Ok (Mac Macaddr.broadcast)
  else if Ipaddr.V4.is_multicast dst then
    (* filter multicast *)
    Ok (Mac (Ipaddr.V4.multicast_to_mac dst))
  else if Ipaddr.V4.Prefix.mem dst network then
    (* direct to this network *)
    Ok (Arp dst)
  else
    (* send to gateway *)
    match gateway with
    | None -> Error `Gateway
    | Some gateway -> Ok (Arp gateway)

let ( let* ) = Result.bind

let destination_macaddr network gateway arp ~src ~dst =
  let* it = routing network gateway ~src ~dst in
  match it with Mac x -> Ok x | Arp ip -> ARPv4.query arp ip

let destination_macaddr_without_interruption network gateway arp ~src ~dst =
  match routing network gateway ~src ~dst with
  | Error _ -> None
  | Ok (Mac x) -> Some x
  | Ok (Arp ip) -> ARPv4.ask arp ip
