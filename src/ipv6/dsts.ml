module Redirect = struct
  type t = { target: Ipaddr.V6.t; destination: Ipaddr.V6.t }

  let pp ppf t =
    Fmt.pf ppf "{ @[<hov>target=@ %a;@ destination=@ %a;@] }" Ipaddr.V6.pp
      t.target Ipaddr.V6.pp t.destination
end

module Unreachable = struct
  type t = { code: int; destination: Ipaddr.V6.t }

  let pp ppf { code; destination } =
    Fmt.pf ppf "Destination %a unreachable (%d)" Ipaddr.V6.pp destination code
end

module PTB = struct
  type t = { mtu: int; destination: Ipaddr.V6.t }

  let pp ppf t =
    Fmt.pf ppf "Packet too big (mtu:%d, addr:%a)" t.mtu Ipaddr.V6.pp
      t.destination
end

type error = [ `Packet_too_big | `Destination_unreachable of int ]

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
  | `Redirect (_src, r) -> begin
      match Dsts.find r.Redirect.destination t.cache with
      | Some { Dst.pmtu; _ } ->
          let next_hop = r.Redirect.target in
          let errored = None in
          let value = { Dst.pmtu; next_hop; errored } in
          let cache = Dsts.add r.Redirect.destination value t.cache in
          { t with cache= Dsts.trim cache }
      | None ->
          let next_hop = r.Redirect.target in
          let errored = None in
          let value = { Dst.pmtu= t.lmtu; next_hop; errored } in
          let cache = Dsts.add r.Redirect.destination value t.cache in
          { t with cache= Dsts.trim cache }
    end
  | `Destination_unreachable u -> begin
      (* RFC 4443: Mark the destination as errored in the cache.
         This prevents further attempts to send to this destination
         until the entry expires or is cleared. *)
      match Dsts.find u.Unreachable.destination t.cache with
      | Some { Dst.pmtu; next_hop; _ } ->
          let errored = Some (`Destination_unreachable u.Unreachable.code) in
          let value = { Dst.pmtu; next_hop; errored } in
          let cache = Dsts.add u.Unreachable.destination value t.cache in
          { t with cache= Dsts.trim cache }
      | None ->
          (* No cached entry, create one with the error *)
          let errored = Some (`Destination_unreachable u.Unreachable.code) in
          let value =
            { Dst.pmtu= t.lmtu; next_hop= u.Unreachable.destination; errored }
          in
          let cache = Dsts.add u.Unreachable.destination value t.cache in
          { t with cache= Dsts.trim cache }
    end
  | `Packet_too_big ptb -> begin
      (* RFC 8201: Path MTU Discovery for IPv6
         Update the PMTU for the destination. The new PMTU should be
         at least 1280 (minimum IPv6 MTU) and at most the current PMTU. *)
      let new_pmtu = Int.max 1280 ptb.PTB.mtu in
      match Dsts.find ptb.PTB.destination t.cache with
      | Some { Dst.pmtu; next_hop; errored } ->
          (* Only reduce PMTU, never increase from PTB *)
          let pmtu = Int.min pmtu new_pmtu in
          let value = { Dst.pmtu; next_hop; errored } in
          let cache = Dsts.add ptb.PTB.destination value t.cache in
          { t with cache= Dsts.trim cache }
      | None ->
          (* No cached entry, create one with the new PMTU *)
          let value =
            { Dst.pmtu= new_pmtu; next_hop= ptb.PTB.destination; errored= None }
          in
          let cache = Dsts.add ptb.PTB.destination value t.cache in
          { t with cache= Dsts.trim cache }
    end
  | _ -> t
