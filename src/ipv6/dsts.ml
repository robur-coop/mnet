module Redirect = struct
  type t = { target: Ipaddr.V6.t; destination: Ipaddr.V6.t }
end

type error = [ `Packet_too_big ]

module Dst = struct
  type t = { pmtu: int; next_hop: Ipaddr.V6.t; errored: error option }

  let weight (_t : t) = 1
end

module Dsts = Lru.F.Make (Ipaddr.V6) (Dst)

type t = { cache: Dsts.t; lmtu: int }

let make ~lmtu capacity = { cache= Dsts.empty capacity; lmtu }

let next_hop addr t =
  match Dsts.find addr t.cache with
  | Some { pmtu; next_hop; errored= None } ->
      Ok (next_hop, pmtu, { t with cache= Dsts.promote addr t.cache })
  | Some { errored= Some err; _ } -> Error (err :> [ `Not_found | error ])
  | None -> Error `Not_found

(* NOTE(dinosaure): by default, we use the Link-MTU for any [addr]. *)

let add t ?mtu:(pmtu = t.lmtu) addr next_hop =
  let value = { Dst.pmtu; next_hop; errored= None } in
  let cache = Dsts.add addr value t.cache in
  { t with cache= Dsts.trim cache }

let clean_old_routers routers t =
  let capacity = Dsts.capacity t.cache in
  let fn addr ({ Dst.next_hop; _ } as value) t =
    if List.mem next_hop routers then t else Dsts.add addr value t
  in
  let cache = Dsts.fold_k fn (Dsts.empty capacity) t.cache in
  { t with cache }

let tick t ~now:_ = function
  | `Redirect r -> begin
      match Dsts.find r.Redirect.target t.cache with
      | Some { Dst.pmtu; _ } ->
          let next_hop = r.Redirect.destination in
          let errored = None in
          let value = { Dst.pmtu; next_hop; errored } in
          let cache = Dsts.add r.Redirect.target value t.cache in
          { t with cache= Dsts.trim cache }
      | None ->
          let next_hop = r.Redirect.destination in
          let errored = None in
          let value = { Dst.pmtu= t.lmtu; next_hop; errored } in
          let cache = Dsts.add r.Redirect.target value t.cache in
          { t with cache= Dsts.trim cache }
    end
  | _ -> t
