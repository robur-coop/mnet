module N = IPv6.Neighbors
open Test

let mac = Macaddr.of_string_exn "02:00:00:00:00:01"
let router = Ipaddr.V6.of_string_exn "fe80::1"
let router_mac = Macaddr.of_string_exn "02:00:00:00:00:fe"
let host = Ipaddr.V6.of_string_exn "fe80::2"
let host_mac = Macaddr.of_string_exn "02:00:00:00:00:02"
let other = Ipaddr.V6.of_string_exn "fe80::3"
let other_mac = Macaddr.of_string_exn "02:00:00:00:00:03"
let me = Ipaddr.V6.of_string_exn "fe80::10"
let s = 1_000_000_000

let query t ~now addr =
  let t, _, _ = N.query t ~mac ~now addr in
  t

let na ~target ~tlla =
  let na =
    {
      N.NA.router= false
    ; solicited= true
    ; override= true
    ; target
    ; tlla= Some tlla
    }
  in
  `NA (target, me, na)

let tick t ~now event = N.tick t ~mac ~now event

let cancels actions =
  List.length (List.filter (function N.Cancel _ -> true | _ -> false) actions)

let test00 =
  let description = {text|An NA only resolves the entry of its range|text} in
  Test.test ~title:"test00" ~description @@ fun () ->
  let t = query (N.make 16) ~now:0 router in
  let t = query t ~now:0 host in
  let _, t = tick t ~now:0 (na ~target:router ~tlla:router_mac) in
  check (N.lladdr t router = Some router_mac);
  check (N.lladdr t host = None)

(* An NS only updates the entry of its source. *)
let test01 =
  let description = {text|An NS only updates the entry of its source|text} in
  Test.test ~title:"test01" ~description @@ fun () ->
  let t = query (N.make 16) ~now:0 host in
  let _, t = tick t ~now:0 (na ~target:host ~tlla:host_mac) in
  let ns = { N.NS.target= me; slla= Some other_mac } in
  let _, t = tick t ~now:0 (`NS (other, me, ns)) in
  check (N.lladdr t host = Some host_mac)

let test02 =
  let description = {text|No transition from a known source's NS|text} in
  Test.test ~title:"test02" ~description @@ fun () ->
  let t = query (N.make 16) ~now:0 router in
  let _, t = tick t ~now:0 (na ~target:router ~tlla:router_mac) in
  let is_router =
    {
      N.NA.router= true
    ; solicited= false
    ; override= false
    ; target= router
    ; tlla= None
    }
  in
  let _, t = tick t ~now:0 (`NA (router, me, is_router)) in
  let ns = { N.NS.target= me; slla= Some router_mac } in
  let _, t = tick t ~now:0 (`NS (router, me, ns)) in
  check (N.is_router t router = Some true);
  let t, _, _ = N.query t ~mac ~now:0 router in
  let actions, _ = tick t ~now:(5 * s) `Tick in
  check (not (List.exists (function N.Packet _ -> true | _ -> false) actions))

let test03 =
  let description = {text|Drop only once an entry|text} in
  Test.test ~title:"test03" ~description @@ fun () ->
  let t = query (N.make 16) ~now:0 other in
  let fn t n = snd (tick t ~now:(n * s) `Tick) in
  let t = List.fold_left fn t [ 1; 2; 3 ] in
  let t = query t ~now:((3 * s) + (s / 2)) host in
  let actions, t = tick t ~now:(4 * s) (na ~target:host ~tlla:host_mac) in
  check (cancels actions = 1);
  check (N.lladdr t host = Some host_mac);
  let actions, _ = tick t ~now:(4 * s) `Tick in
  check (cancels actions = 0)

let () =
  let tests = [ test00; test01; test02; test03 ] in
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
