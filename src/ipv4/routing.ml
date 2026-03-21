type r = Mac of Macaddr.t | Arp of Ipaddr.V4.t

let routing network gateway ~src ~dst =
  (* avoid packets to 0.0.0.0/8 *)
  if Ipaddr.V4.Prefix.(mem dst relative) then Error `Any
    (* avoid packets to 127.0.0.0/8 *)
  else if Ipaddr.V4.Prefix.(mem dst loopback) then Error `Loopback
    (* avoid packets from 127.0.0.0/8 *)
  else if Ipaddr.V4.Prefix.(mem src loopback) then Error `Loopback
    (* avoid packet from broadcast address *)
  else if
    Ipaddr.V4.(compare broadcast) src == 0
    || Ipaddr.V4.(compare (Prefix.broadcast network)) src == 0
  then Error `Broadcast (* use broadcast mac *)
  else if
    Ipaddr.V4.(compare broadcast) dst == 0
    || Ipaddr.V4.(compare (Prefix.broadcast network)) dst == 0
  then Ok (Mac Macaddr.broadcast) (* filter multicast *)
  else if Ipaddr.V4.is_multicast dst then
    Ok (Mac (Ipaddr.V4.multicast_to_mac dst)) (* direct to this network *)
  else if Ipaddr.V4.Prefix.mem dst network then Ok (Arp dst)
  (* go through gateway *)
    else
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
