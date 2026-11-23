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

let packets actions =
  List.length (List.filter (function N.Packet _ -> true | _ -> false) actions)

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

(* Resolves [addr] at [now], then lets its entry go from REACHABLE to PROBE:
   returns the cache and the time of the first unicast probe. *)
let probe t ~now addr ~tlla =
  let t = query t ~now addr in
  let _, t = tick t ~now (na ~target:addr ~tlla) in
  let now = now + (30 * s) in
  let _, t =
    tick t ~now `Tick
    (* REACHABLE -> STALE *)
  in
  let t =
    query t ~now addr
    (* STALE -> DELAY *)
  in
  let now = now + (5 * s) in
  let actions, t =
    tick t ~now `Tick
    (* DELAY -> PROBE *)
  in
  check (packets actions = 1);
  (t, now)

let test04 =
  let description =
    {text|A solicited NA without TLLA confirms the entry|text}
  in
  Test.test ~title:"test04" ~description @@ fun () ->
  let t, now = probe (N.make 16) ~now:0 router ~tlla:router_mac in
  let confirmation =
    {
      N.NA.router= true
    ; solicited= true
    ; override= false
    ; target= router
    ; tlla= None
    }
  in
  let _, t = tick t ~now (`NA (router, me, confirmation)) in
  (* No more probe, and the entry outlives MAX_UNICAST_SOLICIT probes. *)
  let fn t n =
    let actions, t = tick t ~now:(now + (n * s)) `Tick in
    check (packets actions = 0);
    t
  in
  let t = List.fold_left fn t [ 1; 2; 3; 4 ] in
  check (N.lladdr t router = Some router_mac);
  check (N.is_router t router = Some true)

let releases actions =
  let fn = function N.Release_with _ -> true | _ -> false in
  List.length (List.filter fn actions)

let test05 =
  let description = {text|An NA wins over the timeout of the last probe|text} in
  Test.test ~title:"test05" ~description @@ fun () ->
  (* INCOMPLETE: the NA comes when the last multicast NS times out. *)
  let t = query (N.make 16) ~now:0 host in
  let fn t n = snd (tick t ~now:(n * s) `Tick) in
  let t = List.fold_left fn t [ 1; 2; 3 ] in
  let actions, t = tick t ~now:(4 * s) (na ~target:host ~tlla:host_mac) in
  check (cancels actions = 0);
  check (releases actions = 1);
  check (N.lladdr t host = Some host_mac);
  (* PROBE: the NA comes when the last unicast NS times out. *)
  let t, now = probe (N.make 16) ~now:0 router ~tlla:router_mac in
  let fn t n = snd (tick t ~now:(now + (n * s)) `Tick) in
  let t = List.fold_left fn t [ 1; 2 ] in
  let now = now + (3 * s) in
  let _, t = tick t ~now (na ~target:router ~tlla:router_mac) in
  check (N.lladdr t router = Some router_mac);
  let actions, t = tick t ~now `Tick in
  check (packets actions = 0);
  check (N.lladdr t router = Some router_mac)

let solicited ~override ~target ~tlla =
  let na =
    { N.NA.router= false; solicited= true; override; target; tlla= Some tlla }
  in
  `NA (target, me, na)

let test06 =
  let description = {text|The Override flag on a REACHABLE entry|text} in
  Test.test ~title:"test06" ~description @@ fun () ->
  let t = query (N.make 16) ~now:0 host in
  let _, t = tick t ~now:0 (na ~target:host ~tlla:host_mac) in
  (* without it, another link-layer address is not recorded *)
  let na = solicited ~override:false ~target:host ~tlla:other_mac in
  let _, t' = tick t ~now:s na in
  check (N.lladdr t' host = Some host_mac);
  (* with it, it is *)
  let na = solicited ~override:true ~target:host ~tlla:other_mac in
  let _, t' = tick t ~now:s na in
  check (N.lladdr t' host = Some other_mac)

let test07 =
  let description = {text|A solicited NA confirms a REACHABLE entry|text} in
  Test.test ~title:"test07" ~description @@ fun () ->
  let t = query (N.make 16) ~now:0 host in
  let _, t = tick t ~now:0 (na ~target:host ~tlla:host_mac) in
  (* confirmed again at 20 s: still REACHABLE at 40 s, so that sending a packet
     does not start the DELAY timer, nor the probe that follows it. *)
  let na = solicited ~override:false ~target:host ~tlla:host_mac in
  let _, t = tick t ~now:(20 * s) na in
  let _, t = tick t ~now:(40 * s) `Tick in
  let t = query t ~now:(40 * s) host in
  let actions, t = tick t ~now:(45 * s) `Tick in
  check (packets actions = 0);
  check (N.lladdr t host = Some host_mac)

let () =
  let tests =
    [ test00; test01; test02; test03; test04; test05; test06; test07 ]
  in
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
