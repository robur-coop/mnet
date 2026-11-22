module NDP = IPv6.NDPv6
module N = IPv6.Neighbors
open Test

let mac = Macaddr.of_string_exn "02:00:00:00:00:01"
let router = Ipaddr.V6.of_string_exn "fe80::1"
let router_mac = Macaddr.of_string_exn "02:00:00:00:00:fe"
let remote = Ipaddr.V6.of_string_exn "2001:db8::1"
let s = 1_000_000_000

let make () =
  let t, _ = NDP.make ~now:0 ~lmtu:1500 ~mac NDP.EUI64 in
  t

let na ~src ~dst ~tlla =
  let na =
    {
      N.NA.router= false
    ; solicited= true
    ; override= true
    ; target= src
    ; tlla= Some tlla
    }
  in
  `NA (src, dst, na)

(* A user's packet that we recognize by its length. *)
let user's_packet len = { NDP.Packet.len; fn= ignore }

let sent ~len ~dst pkts =
  let fn (pkt : NDP.Packet.t) =
    pkt.len = len && Macaddr.compare pkt.dst dst = 0
  in
  List.length (List.filter fn pkts)

let test00 =
  let description = {text|Packets wait for their next hop|text} in
  Test.test ~title:"test00" ~description @@ fun () ->
  let t = make () in
  (* our link-local address is no more tentative *)
  let now = 2 * s in
  let t, _ = NDP.tick t ~now `Tick in
  let me = NDP.src t router in
  check (Ipaddr.V6.compare me Ipaddr.V6.unspecified <> 0);
  (* off-link: [remote] is reached through [router] *)
  let t, pkts = NDP.send t ~now ~dst:remote router [ user's_packet 1234 ] in
  check (sent ~len:1234 ~dst:router_mac pkts = 0);
  let t, pkts = NDP.tick t ~now (na ~src:router ~dst:me ~tlla:router_mac) in
  check (sent ~len:1234 ~dst:router_mac pkts = 1);
  (* sent once *)
  let _, pkts = NDP.tick t ~now:(now + s) `Tick in
  check (sent ~len:1234 ~dst:router_mac pkts = 0)

let () =
  let tests = [ test00 ] in
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
