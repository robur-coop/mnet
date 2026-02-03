module Pfx = struct
  type t = {
      on_link: bool
    ; autonomous: bool
    ; valid_lifetime: int option
    ; preferred_lifetime: int option
    ; prefix: Ipaddr.V6.Prefix.t
  }
end

module Prefix = struct
  type t = { expire_at: int option }

  let weight (_t : t) = 1
end

module Prefixes = Lru.F.Make (Ipaddr.V6.Prefix) (Prefix)

type t = Prefixes.t

let make capacity = Prefixes.empty capacity

(* NOTE(dinosaure): From RFC 4861, 5.3:

   When removing an entry from the Prefix List, there is no need to
   purge any entries from the Destination or Neighbor Caches.
 *)

let _1s = 1_000_000_000

(* NOTE(dinosaure): RFC 4861, 6.2.5 — only prefixes with [on_link] set are
   added to our list. Link-local prefixes are ignored. *)
let fn ~now t pfx =
  if Ipaddr.V6.Prefix.link = pfx.Pfx.prefix || not pfx.Pfx.on_link then t
  else
    match pfx.Pfx.valid_lifetime with
    | Some 0 -> Prefixes.remove pfx.Pfx.prefix t
    | Some lifetime ->
        let t = Prefixes.remove pfx.Pfx.prefix t in
        let expire_at = Some (now + lifetime * _1s) in
        (* TODO(dinosaure): cap? RFC 4862, 5.5.3 *)
        Prefixes.add pfx.Pfx.prefix { Prefix.expire_at } t
    | None ->
        let t = Prefixes.remove pfx.Pfx.prefix t in
        Prefixes.add pfx.Pfx.prefix { Prefix.expire_at= None } t

let tick t ~now pfxs =
  let t = List.fold_left (fn ~now) t pfxs in
  let fn prefix ({ Prefix.expire_at } as value) t =
    match expire_at with
    | Some expire_at when expire_at < now -> t
    | _ -> Prefixes.add prefix value t
  in
  let capacity = Prefixes.capacity t in
  let t = Prefixes.fold fn (Prefixes.empty capacity) t in
  Prefixes.trim t

exception Yes

let is_local t addr =
  let fn prefix _ =
    if Ipaddr.V6.Prefix.mem addr prefix then raise_notrace Yes
  in
  match Prefixes.iter_k fn t with exception Yes -> true | _ -> false
