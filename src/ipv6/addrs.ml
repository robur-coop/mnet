module Addr = struct
  type lifetime = { preferred: int; valid: int option }
  (* NOTE(dinosaure): these values are **relatives**. *)

  type t =
    | Tentative of { lifetime: lifetime option; expire_at: int; dad_sent: int }
    | Preferred of { expire_at: int option; valid_lifetime: int option }
    | Deprecated of { expire_at: int option }

  let weight (_t : t) = 1
end

module Addrs = Lru.F.Make (Ipaddr.V6.Prefix) (Addr)

type t = Addrs.t

let make capacity = Addrs.empty capacity

type action =
  [ `Send_NS of [ `Unspecified | `Specified ] * Ipaddr.V6.t * Ipaddr.V6.t ]

let solicited_node_prefix = Ipaddr.V6.Prefix.of_string_exn "ff02::1:ff00:0/104"
let _1s = 0

let tick t ~now = function
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
            if dad_sent + 1 >= 1 (* DupAddrDetectTransmits *) then
              (* Tentative -> Preferred *)
              let expire_at =
                match lifetime with
                | None -> None
                | Some { Addr.preferred; _ } -> Some (now + preferred)
              in
              let valid_lifetime =
                match lifetime with
                | None -> None
                | Some { Addr.valid; _ } -> valid
              in
              let state = Addr.Preferred { expire_at; valid_lifetime } in
              (Addrs.add prefix state t, pkts)
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
              | Some valid -> Some (now + valid)
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

exception Choose of Ipaddr.V6.Prefix.t

let select t _dst =
  let fn addr = function
    | Addr.Tentative _ -> ()
    | _ -> raise_notrace (Choose addr)
  in
  match Addrs.iter_k fn t with
  | exception Choose addr ->
      Ipaddr.V6.Prefix.address addr (* TODO(dinosaure): ??? *)
  | () -> Ipaddr.V6.unspecified
