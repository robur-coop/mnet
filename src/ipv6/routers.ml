(* Router Advertisement *)
module RA = struct
  type t = {
      current_hop_limit: int
    ; preference: int
    ; router_lifetime: int
    ; reachable_time: int option
    ; retrans_timer: int option
    ; slla: Macaddr.t option
    ; lmtu: int option
    ; prefix: Prefixes.Pfx.t list
  }

  let pp ppf t =
    Fmt.pf ppf
      "{ @[<hov>current_hop_limit=@ %d;@ preference=@ %d;@ router_lifetime=@ \
       %d;@ reachable_time=@ %a;@ retrans_timer=@ %a;@ slla=@ %a;@ lmtu=@ %a;@ \
       prefix=@ @[<hov>%a@];@] }"
      t.current_hop_limit t.preference t.router_lifetime
      Fmt.(Dump.option int)
      t.reachable_time
      Fmt.(Dump.option int)
      t.retrans_timer
      Fmt.(Dump.option Macaddr.pp)
      t.slla
      Fmt.(Dump.option int)
      t.lmtu
      Fmt.(Dump.list Prefixes.Pfx.pp)
      t.prefix
end

(* NOTE(dinosaure): RFC 4191 defines a priority for routers. *)

module Router = struct
  type t = { expire_at: int; preference: int; lmtu: int option }

  let weight (_t : t) = 1
end

module Routers = Lru.F.Make (Ipaddr.V6) (Router)

type t = Routers.t

let make capacity = Routers.empty capacity
let mem t addr = Routers.mem addr t
let _1s = 1_000_000_000
let _9000s = 9000 * _1s

let rec trim acc routers =
  if Routers.weight routers > Routers.capacity routers then
    match Routers.pop_lru routers with
    | Some ((addr, _), routers) -> trim (addr :: acc) routers
    | None -> (acc, routers)
  else (acc, routers)

(* Remove expired routers and return the list of removed addresses *)
let expire_routers ~now t =
  let capacity = Routers.capacity t in
  let fn addr { Router.expire_at; _ } (expired, t') =
    if expire_at <= now then (addr :: expired, t')
    else (expired, Routers.add addr (Routers.find addr t |> Option.get) t')
  in
  Routers.fold_k fn ([], Routers.empty capacity) t

let tick t ~now = function
  | `RA (src, _dst, { RA.router_lifetime= 0; _ }) ->
      trim [ src ] (Routers.remove src t)
  | `RA (src, _dst, ra) ->
      let lifetime = Int.min (ra.RA.router_lifetime * _1s) _9000s in
      let preference = ra.RA.preference in
      let lmtu = ra.RA.lmtu in
      let expire_at = now + lifetime in
      let t' =
        if Routers.mem src t then
          Routers.remove src t
          |> Routers.add src { expire_at; preference; lmtu }
        else Routers.add src { expire_at; preference; lmtu } t
      in
      (* Also remove expired routers *)
      let expired, t' = expire_routers ~now t' in
      let deleted, t' = trim [] t' in
      (List.rev_append expired deleted, t')
  | _ ->
      (* Remove expired routers on every tick *)
      let expired, t = expire_routers ~now t in
      let deleted, t = trim [] t in
      (List.rev_append expired deleted, t)

let select t ~is_reachable ipaddr =
  let fn key { Router.preference; lmtu; _ } acc =
    if is_reachable key then (key, preference, lmtu) :: acc else acc
  in
  match Routers.fold_k fn [] t with
  | [] when Routers.is_empty t -> (ipaddr, None, t)
  | [] ->
      (* NOTE(dinosaure): round-robin choice of routers. *)
      let[@warning "-8"] (Some (ipaddr, _)) = Routers.lru t in
      (ipaddr, None, Routers.promote ipaddr t)
  | routers ->
      let fn (_, a, _) (_, b, _) = Int.compare b a in
      let routers = List.sort fn routers in
      let ipaddr, _, lmtu = List.hd routers in
      (ipaddr, lmtu, Routers.promote ipaddr t)
