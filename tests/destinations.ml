module NDP = IPv6.NDPv6
open Test

let mac = Macaddr.of_string_exn "02:00:00:00:00:01"
let remote = Ipaddr.V6.of_string_exn "2001:db8::1"
let s = 1_000_000_000
let make () = fst (NDP.make ~now:0 ~lmtu:1500 ~mac NDP.EUI64)

let unreachable ~code destination : NDP.event =
  `Destination_unreachable { code; destination }

let ticks t ~from ~until =
  let rec go t now =
    if now > until then t
    else go (fst (NDP.tick t ~now:(now * s) `Tick)) (now + 1)
  in
  go t from

let is_unreachable t addr =
  match NDP.next_hop t addr with
  | Error (`Destination_unreachable _) -> true
  | Ok _ | Error `Packet_too_big -> false

let test00 =
  let description = {text|An unreachable destination is tried again|text} in
  Test.test ~title:"test00" ~description @@ fun () ->
  let t = make () in
  check (not (is_unreachable t remote));
  let t, _ = NDP.tick t ~now:(2 * s) (unreachable ~code:0 remote) in
  check (is_unreachable t remote);
  let t = ticks t ~from:3 ~until:11 in
  check (is_unreachable t remote);
  let t = ticks t ~from:12 ~until:13 in
  check (not (is_unreachable t remote))

let test01 =
  let description = {text|Only some codes are about the destination|text} in
  Test.test ~title:"test01" ~description @@ fun () ->
  let after code =
    let t, _ = NDP.tick (make ()) ~now:(2 * s) (unreachable ~code remote) in
    is_unreachable t remote
  in
  (* no route, address unreachable, reject route *)
  check (List.for_all after [ 0; 3; 6 ]);
  (* prohibited, scope of the source, port, policy on the source *)
  check (not (List.exists after [ 1; 2; 4; 5 ]))

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
