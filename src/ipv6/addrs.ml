let src = Logs.Src.create "mnet.ipv6.addrs"

module Addr = struct
  type lifetime = { preferred: int; valid: int option }
  (* NOTE(dinosaure): these values are **relatives**. *)

  type t =
    | Tentative of { lifetime: lifetime option; expire_at: int; dad_sent: int }
    | Preferred of { expire_at: int option; valid_lifetime: int option }
    | Deprecated of { expire_at: int option }

  let weight (_t : t) = 1
end

module Log = (val Logs.src_log src : Logs.LOG)
module Addrs = Lru.F.Make (Ipaddr.V6.Prefix) (Addr)

type t = Addrs.t

exception Yes

let is_my_addr t ipaddr =
  let fn prefix state =
    match state with
    | Addr.Preferred _ | Addr.Deprecated _ ->
        if Ipaddr.V6.(compare (Prefix.address prefix) ipaddr) = 0 then
          raise_notrace Yes
    | _ -> ()
  in
  match Addrs.iter_k fn t with exception Yes -> true | _ -> false

let solicited_node_prefix = Ipaddr.V6.Prefix.of_string_exn "ff02::1:ff00:0/104"
let _1s = 1_000_000_000

let tick t ~now ~iid event =
  let pfxs =
    match event with `RA (_, _, ra) -> ra.Routers.RA.prefix | _ -> []
  in
  (* RFC 4862 5.5.2, RFC 7217 *)
  let fn t (pfx : Prefixes.Pfx.t) =
    if
      (not pfx.autonomous)
      || Ipaddr.V6.Prefix.bits pfx.prefix <> 64
      || pfx.valid_lifetime = Some 0
    then t
    else
      let network = Ipaddr.V6.to_octets (Ipaddr.V6.Prefix.address pfx.prefix) in
      let buf = Bytes.create 16 in
      Bytes.blit_string network 0 buf 0 8;
      Bytes.blit_string iid 0 buf 8 8;
      let addr = Ipaddr.V6.of_octets_exn (Bytes.unsafe_to_string buf) in
      let prefix = Ipaddr.V6.Prefix.make 128 addr in
      if Addrs.mem prefix t then t
      else
        let lifetime =
          match pfx.preferred_lifetime with
          | None -> None
          | Some preferred -> Some { Addr.preferred; valid= pfx.valid_lifetime }
        in
        let state =
          Addr.Tentative { lifetime; expire_at= now + _1s; dad_sent= 0 }
        in
        Addrs.add prefix state t
  in
  let t = List.fold_left fn t pfxs in
  match event with
  | `NA (_src, _dst, { Neighbors.NA.target; _ }) ->
      let fn prefix state t =
        if Ipaddr.V6.Prefix.mem target prefix then
          match state with
          | Addr.Tentative _ -> t
          | state -> Addrs.add prefix state t
        else Addrs.add prefix state t
      in
      let capacity = Addrs.capacity t in
      (Addrs.fold_k fn (Addrs.empty capacity) t, [])
  | _ ->
      let fn prefix state (t, pkts) =
        match state with
        | Addr.Tentative { lifetime; expire_at; dad_sent } when expire_at < now
          ->
            if dad_sent >= 1 (* DupAddrDetectTransmits *) then begin
              (* Tentative -> Preferred *)
              let expire_at =
                match lifetime with
                | None -> None
                | Some { Addr.preferred; _ } -> Some (now + (preferred * _1s))
              in
              let valid_lifetime =
                match lifetime with
                | None -> None
                | Some { Addr.valid; _ } -> valid
              in
              Log.debug (fun m -> m "%a preferred" Ipaddr.V6.Prefix.pp prefix);
              let state = Addr.Preferred { expire_at; valid_lifetime } in
              (Addrs.add prefix state t, pkts)
            end
            else begin
              let addr = Ipaddr.V6.Prefix.address prefix in
              let dst =
                Ipaddr.V6.Prefix.network_address solicited_node_prefix addr
              in
              assert (Ipaddr.V6.is_multicast dst);
              let expire_at = now + _1s in
              let dad_sent = dad_sent + 1 in
              let state = Addr.Tentative { lifetime; expire_at; dad_sent } in
              let t = Addrs.add prefix state t in
              let lladdr = Ipaddr.V6.multicast_to_mac dst in
              let ns = { Neighbors.NS.target= addr; slla= None } in
              let pkt = Neighbors.NS.encode_into ~lladdr ~dst ns in
              (t, pkt :: pkts)
            end
        | Preferred { expire_at= Some expire_at; valid_lifetime }
          when expire_at < now ->
            (* Preferred -> Deprecated *)
            let expire_at =
              match valid_lifetime with
              | None -> None
              | Some valid -> Some (now + (valid * _1s))
            in
            let state = Addr.Deprecated { expire_at } in
            let t = Addrs.add prefix state t in
            (t, pkts)
        | Deprecated { expire_at= Some expire_at; _ } when expire_at < now ->
            (t, pkts)
        | state -> (Addrs.add prefix state t, pkts)
      in
      let capacity = Addrs.capacity t in
      Addrs.fold_k fn (Addrs.empty capacity, []) t

let make ~now ~iid ?addr capacity =
  let addrs = Addrs.empty capacity in
  (* Create link-local address from IID *)
  let on_link_addr =
    let buf = Bytes.make 16 '\x00' in
    Bytes.set buf 0 '\xfe';
    Bytes.set buf 1 '\x80';
    Bytes.blit_string iid 0 buf 8 8;
    Ipaddr.V6.of_octets_exn (Bytes.to_string buf)
  in
  let expire_at = now + _1s in
  let entry = Addr.Tentative { lifetime= None; expire_at; dad_sent= 1 } in
  let dst =
    Ipaddr.V6.Prefix.network_address solicited_node_prefix on_link_addr
  in
  let lladdr = Ipaddr.V6.multicast_to_mac dst in
  let ns = { Neighbors.NS.target= on_link_addr; slla= None } in
  let pkt = Neighbors.NS.encode_into ~lladdr ~dst ns in
  let addrs = Addrs.add (Ipaddr.V6.Prefix.make 64 on_link_addr) entry addrs in
  (* If static address provided, add it directly as Preferred (no DAD needed
     since it's manually configured) *)
  let addrs =
    match addr with
    | None -> addrs
    | Some prefix ->
        let state = Addr.Preferred { expire_at= None; valid_lifetime= None } in
        Addrs.add prefix state addrs
  in
  (addrs, pkt)

let select t dst =
  let dst_is_ll = Ipaddr.V6.Prefix.(mem dst link) in
  let fn prefix state (best, best_score) =
    match state with
    | Addr.Tentative _ -> (best, best_score)
    | _ ->
        let addr = Ipaddr.V6.Prefix.address prefix in
        (* NOTE(dinosaure): prefer Link-Local source if [dst] is Link-Local. *)
        let score =
          if Ipaddr.V6.Prefix.(mem addr link) = dst_is_ll then 2 else 0
        in
        (* NOTE(dinosaure): Avoid deprecated addresses. *)
        let score =
          match state with Addr.Preferred _ -> 1 + score | _ -> 0 + score
        in
        if score > best_score then (Some prefix, score) else (best, best_score)
  in
  let best, _ = Addrs.fold_k fn (None, -1) t in
  match best with
  | Some prefix -> Ipaddr.V6.Prefix.address prefix
  | None -> Ipaddr.V6.unspecified
