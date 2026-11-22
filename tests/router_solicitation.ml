module NDP = IPv6.NDPv6
open Test

let mac = Macaddr.of_string_exn "02:00:00:00:00:01"
let router = Ipaddr.V6.of_string_exn "fe80::1"
let s = 1_000_000_000

(* Router Solicitations of [pkts]: they go to all routers. *)
let rs pkts =
  let dst = Ipaddr.V6.multicast_to_mac Ipaddr.V6.link_routers in
  let fn (pkt : NDP.Packet.t) = Macaddr.compare pkt.dst dst = 0 in
  List.length (List.filter fn pkts)

(* One [`Tick] per second, from [from] to [until]: the solicitations sent. *)
let ticks t ~from ~until =
  let rec go t acc now =
    if now > until then (t, acc)
    else
      let t, pkts = NDP.tick t ~now:(now * s) `Tick in
      go t (acc + rs pkts) (succ now)
  in
  go t 0 from

let ra ~router_lifetime : NDP.event =
  `RA
    ( router
    , Ipaddr.V6.link_nodes
    , {
        current_hop_limit= 64
      ; preference= 0
      ; router_lifetime
      ; reachable_time= None
      ; retrans_timer= None
      ; slla= None
      ; lmtu= None
      ; prefix= []
      } )

let test00 =
  let description = {text|Router Solicitations are retransmitted|text} in
  Test.test ~title:"test00" ~description @@ fun () ->
  let t, pkts = NDP.make ~now:0 ~lmtu:1500 ~mac NDP.EUI64 in
  check (rs pkts = 1);
  (* RTR_SOLICITATION_INTERVAL *)
  let t, n = ticks t ~from:1 ~until:3 in
  check (n = 0);
  let t, n = ticks t ~from:4 ~until:7 in
  check (n = 1);
  let t, n = ticks t ~from:8 ~until:11 in
  check (n = 1);
  (* MAX_RTR_SOLICITATIONS *)
  let _, n = ticks t ~from:12 ~until:60 in
  check (n = 0)

let test01 =
  let description = {text|A Router Advertisement stops them|text} in
  Test.test ~title:"test01" ~description @@ fun () ->
  let t, _ = NDP.make ~now:0 ~lmtu:1500 ~mac NDP.EUI64 in
  (* not a default router: we still look for one *)
  let t, _ = NDP.tick t ~now:s (ra ~router_lifetime:0) in
  let t, n = ticks t ~from:2 ~until:5 in
  check (n = 1);
  let t, pkts = NDP.tick t ~now:(6 * s) (ra ~router_lifetime:1800) in
  check (rs pkts = 0);
  let _, n = ticks t ~from:7 ~until:60 in
  check (n = 0)

let () =
  let tests = [ test00; test01 ] in
  let ({ Test.directory } as runner) =
    Test.runner (Filename.concat (Sys.getcwd ()) "_tests")
  in
  let run idx test =
    let idx = succ idx in
    Format.printf "test%02d: %!" idx;
    Test.run runner test;
    Format.printf "ok\n%!"
  in
  Format.printf "Run tests into %s\n%!" directory;
  List.iteri run tests
