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

(* NOTE(dinosaure): From RFC4861, 5.3:

   When removing an entry from the Prefix List, there is no need to
   purge any entries from the Destination or Neighbor Caches.
 *)

let tick t ~now = function
  | `Prefix pfx ->
      let t =
        if Ipaddr.V6.Prefix.link <> pfx.Pfx.prefix then
          match (pfx.Pfx.valid_lifetime, Prefixes.mem pfx.Pfx.prefix t) with
          | Some 0, _ -> Prefixes.remove pfx.Pfx.prefix t
          | Some lifetime, true ->
              let t = Prefixes.remove pfx.Pfx.prefix t in
              let expire_at = Some (now + lifetime) in
              (* TODO(dinosaure): cap? *)
              let value = { Prefix.expire_at } in
              Prefixes.add pfx.Pfx.prefix value t
          | Some lifetime, false ->
              let expire_at = Some (now + lifetime) in
              let value = { Prefix.expire_at } in
              Prefixes.add pfx.Pfx.prefix value t
          | None, true ->
              let t = Prefixes.remove pfx.Pfx.prefix t in
              let value = { Prefix.expire_at= None } in
              Prefixes.add pfx.Pfx.prefix value t
          | None, false ->
              let value = { Prefix.expire_at= None } in
              Prefixes.add pfx.Pfx.prefix value t
        else t
      in
      Prefixes.trim t
  | _ ->
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
