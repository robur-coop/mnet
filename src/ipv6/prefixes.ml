module Pfx = struct
  type t = {
      on_link: bool
    ; autonomous: bool
    ; valid_lifetime: int option
    ; preferred_lifetime: int option
    ; prefix: Ipaddr.V6.Prefix.t
  }

  let pp ppf t =
    Fmt.pf ppf
      "{ @[<hov>on_link=@ %b;@ autonomous=@ %b;@ valid_lifetime=@ %a;@ \
       preferred_lifetime=@ %a;@ prefix=@ %a;@] }"
      t.on_link t.autonomous
      Fmt.(Dump.option int)
      t.valid_lifetime
      Fmt.(Dump.option int)
      t.preferred_lifetime Ipaddr.V6.Prefix.pp t.prefix
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
let _2h = 2 * 60 * 60 (* 2 hours in seconds *)

(* RFC 4862 Section 5.5.3: Rules for updating valid lifetime to prevent DoS
   attacks where an attacker sends RAs with very short lifetimes.
   1. If advertised_lifetime > 2 hours, accept it
   2. If advertised_lifetime > remaining_lifetime, accept it
   3. If remaining_lifetime <= 2 hours, ignore (keep current)
   4. Otherwise, set to 2 hours

   NOTE(dinosaure):
   - [expire_at] is in nanoseconds
   - [advertised] is in seconds
   - [rem] is in seconds *)
let expire_at ~now ~advertised existing =
  match existing with
  | None -> Some (now + (advertised * _1s))
  | Some { Prefix.expire_at= None } -> Some (now + (advertised * _1s))
  | Some { Prefix.expire_at= Some expire_at } ->
      let rem = (expire_at - now) / _1s in
      if advertised > _2h then Some (now + (advertised * _1s))
      else if advertised > rem then Some (now + (advertised * _1s))
      else if rem <= _2h then Some expire_at
      else Some (now + (_2h * _1s))

let fn ~now t pfx =
  (* NOTE(dinosaure): RFC 4861, 6.2.5 — only prefixes with [on_link] set are
     added to our list. Link-local prefixes are ignored. *)
  if Ipaddr.V6.Prefix.link = pfx.Pfx.prefix || not pfx.Pfx.on_link then t
  else
    match pfx.Pfx.valid_lifetime with
    | Some 0 -> Prefixes.remove pfx.Pfx.prefix t
    | Some lifetime ->
        let existing = Prefixes.find pfx.Pfx.prefix t in
        let expire_at = expire_at ~now ~advertised:lifetime existing in
        let t = Prefixes.remove pfx.Pfx.prefix t in
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
