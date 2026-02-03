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
end

(* NOTE(dinosaure): RFC 4191 defines a priority for routers. *)

module Router = struct
  type t = { expire_at: int; preference: int; lmtu: int option }

  let weight (_t : t) = 1
end

module Routers = Lru.F.Make (Ipaddr.V6) (Router)

type t = Routers.t

let make capacity = Routers.empty capacity
let _1s = 1_000_000_000
let _9000s = 9000 * _1s

let rec trim acc routers =
  if Routers.weight routers > Routers.capacity routers then
    match Routers.pop_lru routers with
    | Some ((addr, _), routers) -> trim (addr :: acc) routers
    | None -> (acc, routers)
  else (acc, routers)

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
      trim [] t'
  | _ -> trim [] t

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
