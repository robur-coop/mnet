module N = IPv6__Neighbors

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
  `NA
    ( target
    , me
    , {
        N.NA.router= false
      ; solicited= true
      ; override= true
      ; target
      ; tlla= Some tlla
      } )

let tick t ~now event = N.tick t ~mac ~now event

let cancels actions =
  List.length (List.filter (function N.Cancel _ -> true | _ -> false) actions)

let check name ok =
  if not ok then (
    Printf.printf "FAIL: %s\n" name;
    exit 1)

(* An NA only resolves the entry of its target. *)
let () =
  let t = query (N.make 16) ~now:0 router in
  let t = query t ~now:0 host in
  let _, t = tick t ~now:0 (na ~target:router ~tlla:router_mac) in
  check "router resolved" (N.lladdr t router = Some router_mac);
  check "host still unresolved" (N.lladdr t host = None)

(* An NS only updates the entry of its source. *)
let () =
  let t = query (N.make 16) ~now:0 host in
  let _, t = tick t ~now:0 (na ~target:host ~tlla:host_mac) in
  let ns = { N.NS.target= me; slla= Some other_mac } in
  let _, t = tick t ~now:0 (`NS (other, me, ns)) in
  check "host keeps its MAC" (N.lladdr t host = Some host_mac)

(* An NS from a known source with the same link-layer address leaves its
   entry unchanged: still REACHABLE (no NUD probe 5s later) and still a
   router. *)
let () =
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
  check "router keeps its router flag" (N.is_router t router = Some true);
  let t, _, _ = N.query t ~mac ~now:0 router in
  let actions, _ = tick t ~now:(5 * s) `Tick in
  check "router still reachable"
    (not (List.exists (function N.Packet _ -> true | _ -> false) actions))

(* A dropped entry is dropped once, and the other updates are kept. *)
let () =
  let t = query (N.make 16) ~now:0 other in
  let t =
    List.fold_left (fun t n -> snd (tick t ~now:(n * s) `Tick)) t [ 1; 2; 3 ]
  in
  let t = query t ~now:((3 * s) + (s / 2)) host in
  let actions, t = tick t ~now:(4 * s) (na ~target:host ~tlla:host_mac) in
  check "unanswered entry cancelled" (cancels actions = 1);
  check "host resolved in the same tick" (N.lladdr t host = Some host_mac);
  let actions, _ = tick t ~now:(4 * s) `Tick in
  check "cancelled only once" (cancels actions = 0)
