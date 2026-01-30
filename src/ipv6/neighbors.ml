(* Neighbor Advertisement *)
module NA = struct
  type t = {
      router: bool
    ; solicited: bool
    ; override: bool
    ; target: Ipaddr.V6.t
    ; tlla: Macaddr.t option
  }
end

module NS = struct
  type t = { target: Ipaddr.V6.t; slla: Macaddr.t option }
end

module Neighbor = struct
  type state =
    | Incomplete of { expire_at: int; sent_probes: int }
    | Reachable of { lladdr: Macaddr.t; expire_at: int }
    | Stale of Macaddr.t
    | Delay of { lladdr: Macaddr.t; expire_at: int }
    | Probe of { lladdr: Macaddr.t; expire_at: int; sent_probes: int }

  type t = state * bool

  let lladdr = function
    | Reachable { lladdr; _ }
    | Stale lladdr
    | Delay { lladdr; _ }
    | Probe { lladdr; _ } ->
        Some lladdr
    | Incomplete _ -> None

  let weight (_t : t) = 1
end

module Neighbors = Lru.F.Make (Ipaddr.V6) (Neighbor)

type t = Neighbors.t

let solicited_node_prefix = Ipaddr.V6.Prefix.of_string_exn "ff02::1:ff00:0/104"

(* Appendix C: State Machine for the Reachability State

   This appendix contains a summary of the rules specified in Sections
   7.2 and 7.3.  This document does not mandate that implementations
   adhere to this model as long as their external behavior is consistent
   with that described in this document.

   When performing address resolution and Neighbor Unreachability
   Detection the following state transitions apply using the conceptual
   model:

   State           Event                   Action             New state

   -               Packet to send.        Create entry.       INCOMPLETE
                                          Send multicast NS.
                                          Start retransmit timer



    -              NS, RS, Redirect             -                 -
                   No link-layer address


   !INCOMPLETE     upper-layer reachability  -                 REACHABLE
                   confirmation

  *)

let _1s = 0
let _5s = 0
let _30s = 0

type action =
  [ `Send_ICMPv6_neighbor_unreachable
  | `Send_NS of [ `Unspecified | `Specified ] * Ipaddr.V6.t * Ipaddr.V6.t
  | `Send_queued_packets of Ipaddr.V6.t
  | `Cancel of Ipaddr.V6.t ]

let transition key (state, is_router) now event =
  let open Neighbor in
  match (state, event) with
  (* | INCOMPLETE | Retransmit timeout, | Retransmit NS    | INCOMPLETE
     |            | less than N         | Start retransmit |
     |            | retransmissions.    | timer            |
     |            |                     |                  |
     | INCOMPLETE | Retransmit timeout, | Discard entry    | -
     |            | N or more           | Send ICMP error  |
     |            | retransmissions.    |                  |
   *)
  | Incomplete { expire_at: int; sent_probes; _ }, _ when expire_at <= now ->
      if sent_probes >= 3 (* MAX_MULTICAST_SOLICIT *) then
        (None, [ `Send_ICMPv6_neighbor_unreachable; `Cancel key ])
      else
        let expire_at = now + _1s in
        let sent_probes = sent_probes + 1 in
        let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix key in
        let actions = [ `Send_NS (`Specified, dst, key) ] in
        (Some (Incomplete { expire_at; sent_probes }, is_router), actions)
  (* | REACHABLE | timeout, more than    | - | STALE
     |           | N seconds since       |   |
     |           | reachability confirm. |   |
   *)
  | Reachable { expire_at; lladdr }, _ when expire_at <= now ->
      (Some (Stale lladdr, is_router), [])
  (* | DELAY | Delay timeout | Send unicast NS probe  | PROBE
     |       |               | Start retransmit timer |
   *)
  | Delay { lladdr; expire_at }, _ when expire_at <= now ->
      let expire_at = now + _1s in
      let sent_probes = 1 in
      let actions = [ `Send_NS (`Specified, key, key) ] in
      (Some (Probe { lladdr; expire_at; sent_probes }, is_router), actions)
  (* | PROBE | Retransmit timeout, | Retransmit NS | PROBE
     |       | less than N         |               |
     |       | retransmissions.    |               |
     |       |                     |               |
     | PROBE | Retransmit timeout, | Discard entry | -
     |       | N or more           |               |
     |       | retransmissions.    |               |
   *)
  | Probe { lladdr; expire_at; sent_probes }, _ when expire_at <= now ->
      if sent_probes >= 3 (* MAX_UNICAST_SOLICIT *) then (None, [])
      else
        let expire_at = now + _1s in
        let sent_probes = sent_probes + 1 in
        let actions = [ `Send_NS (`Specified, key, key) ] in
        (Some (Probe { lladdr; expire_at; sent_probes }, is_router), actions)
  (* | INCOMPLETE | NA, Solicited=1, | Record link-layer    | REACHABLE
     |            | Override=any     | address. Send queued |
     |            |                  | packets.             |
   *)
  | Incomplete _, `NA (_src, _dst, { NA.solicited= true; tlla= Some lladdr; _ })
    ->
      let expire_at = now + _30s in
      (Some (Reachable { lladdr; expire_at }, is_router), [])
  (* | INCOMPLETE | NA, Solicited=0, | Record link-layer    | STALE
     |            | Override=any     | address. Send queued |
     |            |                  | packets.             |
   *)
  | Incomplete _, `NA (_src, _dst, { NA.solicited= false; tlla= Some lladdr; _ })
    ->
      (Some (Stale lladdr, is_router), [ `Send_queued_packets key ])
  (* | INCOMPLETE | NA, Solicited=any, | Update content of | unchanged
     |            | Override=any, No   | IsRouter flag     |
     |            | Link-layer address |                   |
   *)
  | Incomplete _, `NA (_src, _dst, { NA.tlla= None; _ }) ->
      (Some (state, true), [])
  (* |  REACHABLE | NA, Solicited=1,     | - | STALE
     |            | Override=0           |   |
     |            | Different link-layer |   |
     |            | address than cached. |   |
   *)
  | ( Reachable { lladdr; _ }
    , `NA (_src, _dst, { NA.solicited= true; tlla= Some lladdr'; _ }) ) ->
      if Macaddr.compare lladdr lladdr' != 0 then
        (Some (Stale lladdr', is_router), [])
      else (Some (state, is_router), [])
  (* | !INCOMPLETE  | NA, Solicited=1,     | - | REACHABLE
     |              | Override=0           |   |
     |              | Same link-layer      |   |
     |              | address as cached.   |   |
     |              |                      |   |
     | STALE, PROBE | NA, Solicited=1,     | - | unchanged
     | Or DELAY     | Override=0           |   |
     |              | Different link-layer |   |

   *)
  | ( (Stale _ | Probe _ | Delay _)
    , `NA
        ( _src
        , _dst
        , { NA.solicited= true; tlla= Some lladdr; override= false; _ } ) ) ->
      let lladdr' = Neighbor.lladdr state in
      let lladdr' = Option.get lladdr' in
      if Macaddr.compare lladdr lladdr' = 0 then
        let expire_at = now + _30s in
        (Some (Reachable { lladdr; expire_at }, is_router), [])
      else (Some (state, is_router), [])
  (* | !INCOMPLETE | NA, Solicited=0,     | -                 | unchanged
     |             | Override=1           |                   |
     |             | Same link-layer      |                   |
     |             | address as cached.   |                   |
     |             |                      |                   |
     | !INCOMPLETE | NA, Solicited=1,     | Record link-layer | REACHABLE
     |             | Override=1           | address (if       |
     |             |                      | different).       |
     |             |                      |                   |
     | !INCOMPLETE | NA, Solicited=0,     | Record link-layer | STALE
     |             | Override=1           | address.          |
     |             | Different link-layer |                   |
     |             | address than cached. |                   |
   *)
  | ( (Stale _ | Probe _ | Delay _ | Reachable _)
    , `NA (_src, _dst, { NA.solicited; override= true; tlla= Some lladdr; _ }) )
    ->
      let lladdr' = Neighbor.lladdr state in
      let lladdr' = Option.get lladdr' in
      if (not solicited) && Macaddr.compare lladdr lladdr' = 0 then
        (Some (state, is_router), [])
      else if solicited then
        let expire_at = now + _30s in
        (Some (Reachable { lladdr; expire_at }, is_router), [])
      else (* not solicited && Macaddr.compare lladdr lladdr' <> 0 *)
        let () = assert (not solicited) in
        let () = assert (Macaddr.compare lladdr lladdr' <> 0) in
        (Some (Stale lladdr, is_router), [])
  (* | !INCOMPLETE | NA, Solicited=any, | Update content of | unchanged
     |             | Override=any, No   | IsRouter flag.    |
     |             | link-layer address |                   |
   *)
  | ( (Stale _ | Probe _ | Delay _ | Reachable _)
    , `NA (_src, _dst, { NA.tlla= None; _ }) ) ->
      (Some (state, true), [])
  (* | !INCOMPLETE | NA, Solicited=0, | - | unchanged
     |             | Override=0       |   |
   *)
  | ( (Stale _ | Probe _ | Delay _ | Reachable _)
    , `NA (_src, _dst, { NA.solicited= false; override= false; _ }) ) ->
      (Some (state, is_router), [])
  (* 7.2.3.  Receipt of Neighbor Solicitations

     ... the recipient SHOULD create or update the Neighbor Cache entry for the
     IP Source Address of the solicitation. If an entry does not already exist,
     the node SHOULD create a new one and set its reachability state to STALE as
     specified in Section 7.3.3. If an entry already exists, and the cached
     link-layer address differs from the one in the received Source Link-Layer
     option, the cached address should be replaced by the received address, and
     the entry's reachability state MUST be set to STALE. *)
  | Incomplete _, `NS (src, _dst, { NS.slla= Some lladdr; _ }) ->
      if Ipaddr.V6.compare key src = 0 then
        let state = Stale lladdr in
        (Some (state, is_router), [ `Send_queued_packets key ])
      else
        let state = Stale lladdr in
        (Some (state, false), [])
  | ( (Stale _ | Probe _ | Delay _ | Reachable _)
    , `NS (src, _dst, { NS.slla= Some lladdr; _ }) ) ->
      let lladdr' = Neighbor.lladdr state in
      let lladdr' = Option.get lladdr' in
      if Ipaddr.V6.compare key src = 0 && Macaddr.compare lladdr lladdr' <> 0
      then
        let state = Stale lladdr in
        (Some (state, is_router), [])
      else
        let state = Stale lladdr in
        (Some (state, false), [])
  | (Incomplete _ | Reachable _ | Delay _ | Probe _ | Stale _), _ ->
      (Some (state, is_router), [])

let tick t ~now event =
  let fn key value (actions, t') =
    match transition key value now event with
    | Some value', actions' ->
        let actions = List.rev_append actions' actions in
        let t' = Neighbors.add key value' t' in
        (actions, t')
    | None, actions' ->
        let actions = List.rev_append actions' actions in
        (actions, t)
  in
  (* NOTE(dinosaure): even if we can [fold_k] here (which performs better), we
     would like to keep the usage order to clean up then. *)
  let actions, t' = Neighbors.fold fn ([], Neighbors.empty 0x7ff) t in
  (actions, Neighbors.trim t')

let lladdr t addr =
  match Option.map fst (Neighbors.find addr t) with
  | None | Some (Neighbor.Incomplete _) -> None
  | Some
      ( Stale lladdr
      | Reachable { lladdr; _ }
      | Delay { lladdr; _ }
      | Probe { lladdr; _ } ) ->
      Some lladdr

let is_reachable t addr =
  match Option.map fst (Neighbors.find addr t) with
  | Some (Neighbor.Incomplete _) | None -> false
  | _ -> true

let is_router t addr = Option.map snd (Neighbors.find addr t)

let query t ~now addr =
  match Neighbors.find addr t with
  | None ->
      let expire_at = now + _1s in
      let sent_probes = 0 in
      let state = Neighbor.Incomplete { expire_at; sent_probes } in
      let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix addr in
      let actions = [ `Send_NS (`Specified, dst, addr) ] in
      let t = Neighbors.add addr (state, false) t in
      let t = Neighbors.trim t in
      (t, None, actions)
  | Some Neighbor.(Incomplete _, _) -> (t, None, [])
  | Some
      ( ( Neighbor.Reachable { lladdr; _ }
        | Delay { lladdr; _ }
        | Probe { lladdr; _ } )
      , _ ) ->
      (t, Some lladdr, [])
  (* | STALE | Sending packet | Start delay timer | DELAY *)
  | Some (Neighbor.Stale lladdr, is_router) ->
      let expire_at = now + _5s in
      let state = Neighbor.Delay { lladdr; expire_at } in
      let t = Neighbors.remove addr t in
      let t = Neighbors.add addr (state, is_router) t in
      (t, Some lladdr, [])
