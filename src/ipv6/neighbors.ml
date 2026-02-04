module Packet = struct
  type t = {
      lladdr: Macaddr.t
    ; dst: Ipaddr.V6.t
    ; len: int
    ; fn: src:Ipaddr.V6.t -> Bstr.t -> unit
  }
end

(* NOTE(dinosaure): There are two things to keep in mind regarding NDPv6: the
   algorithm can (and will) send packets whose destination is always On-Link,
   meaning that we do not have to resolve the "next hop" as soon as NDPv6 wants
   to send packets: we should always have the destination MAC address.

   The packets we are trying to send are always less than 1280 bytes, which is
   the minimum MTU according to IPv6. We should therefore not worry about the
   [`Packet_too_big] error that destinations may send us.

   Finally, at this point, we still do not know the source MAC address or the
   source IPv6 address. The packets are therefore encoded so that they wait for
   the IPv6 address we want to use and, through currying, produce a function
   that fully writes the IPv6 packet that our algorithm wants to send. *)

(* Neighbor Advertisement *)
module NA = struct
  type t = {
      router: bool
    ; solicited: bool
    ; override: bool
    ; target: Ipaddr.V6.t
    ; tlla: Macaddr.t option
  }

  let pp ppf t =
    Fmt.pf ppf
      "{ @[<hov>router=@ %b;@ solicited=@ %b;@ override=@ %b;@ target=@ %a;@ \
       tlla=@ %a;@] }"
      t.router t.solicited t.override Ipaddr.V6.pp t.target
      Fmt.(Dump.option Macaddr.pp)
      t.tlla
end

let cs_of_len_and_protocol =
  let tmp = Cstruct.create 8 in
  fun ~len ~protocol ->
    Cstruct.BE.set_uint32 tmp 0 (Int32.of_int len);
    Cstruct.BE.set_uint32 tmp 4 (Int32.of_int protocol);
    tmp

module NS = struct
  type t = { target: Ipaddr.V6.t; slla: Macaddr.t option }

  let pp ppf t =
    Fmt.pf ppf "{ @[<hov>target=@ %a;@ slla=@ %a;@] }" Ipaddr.V6.pp t.target
      Fmt.(Dump.option Macaddr.pp)
      t.slla

  let encode_into ~lladdr ~dst t =
    let payload_len = match t.slla with None -> 24 | Some _ -> 32 in
    let len = payload_len + 40 in
    let fn ~src bstr =
      Bstr.set_int32_be bstr 0 0x60000000l;
      Bstr.set_uint16_be bstr 4 payload_len;
      Bstr.set_uint8 bstr 6 58 (* ICMPv6 *);
      Bstr.set_uint8 bstr 7 255 (* HOP limit *);
      let src = Ipaddr.V6.to_octets src in
      Bstr.blit_from_string src ~src_off:0 bstr ~dst_off:8 ~len:16;
      let dst = Ipaddr.V6.to_octets dst in
      Bstr.blit_from_string dst ~src_off:0 bstr ~dst_off:24 ~len:16;
      Bstr.set_uint8 bstr 40 135 (* NS *);
      Bstr.set_uint8 bstr 41 0;
      Bstr.set_uint16_be bstr 42 0;
      Bstr.set_int32_be bstr 44 0l;
      let target = Ipaddr.V6.to_octets t.target in
      Bstr.blit_from_string target ~src_off:0 bstr ~dst_off:48 ~len:16;
      begin match t.slla with
      | None -> ()
      | Some lladdr ->
          Bstr.set_uint8 bstr 64 1;
          Bstr.set_uint8 bstr 65 1;
          let lladdr = Macaddr.to_octets lladdr in
          Bstr.blit_from_string lladdr ~src_off:0 bstr ~dst_off:66 ~len:6
      end;
      let cs0 = Cstruct.of_bigarray bstr ~off:8 ~len:32 in
      let cs1 = cs_of_len_and_protocol ~len:payload_len ~protocol:58 in
      let cs2 = Cstruct.of_bigarray bstr ~off:40 ~len:payload_len in
      let chk = 0 in
      let chk = Utcp.Checksum.feed_cstruct chk cs0 in
      let chk = Utcp.Checksum.feed_cstruct chk cs1 in
      let chk = Utcp.Checksum.feed_cstruct chk cs2 in
      let chk = Utcp.Checksum.finally chk in
      Bstr.set_uint16_be bstr 42 chk
    in
    { Packet.lladdr; dst; len; fn }
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

let make capacity = Neighbors.empty capacity
let solicited_node_prefix = Ipaddr.V6.Prefix.of_string_exn "ff02::1:ff00:0/104"
let _1s = 1_000_000_000
let _5s = 5_000_000_000
let _30s = 30_000_000_000

type action =
  | Packet of Packet.t
  | Cancel of Ipaddr.V6.t
  | Release_with of Ipaddr.V6.t * Macaddr.t

(* NOTE(dinosaure): For simplicity's sake, the transition produces at most a
   single action. This action can be "expanded" to send multiple packets, but
   this expansion is done later (outside of NDPv6). For now, this is sufficient,
   and we can use the [List.cons]/[List.rev] pair rather than [List.rev_append]
   when aggregating all actions for all our entries. *)

let transition ~mac key (state, is_router) now event =
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
        (None, Some (Cancel key))
      else begin
        let expire_at = now + _1s in
        let sent_probes = sent_probes + 1 in
        let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix key in
        assert (Ipaddr.V6.is_multicast dst);
        let lladdr = Ipaddr.V6.multicast_to_mac dst in
        (* RFC 4861: SLLA must be the sender's link-layer address *)
        let ns = { NS.target= key; slla= Some mac } in
        let pkt = NS.encode_into ~lladdr ~dst ns in
        let action = Some (Packet pkt) in
        (Some (Incomplete { expire_at; sent_probes }, is_router), action)
      end
  (* | REACHABLE | timeout, more than    | - | STALE
     |           | N seconds since       |   |
     |           | reachability confirm. |   |
   *)
  | Reachable { expire_at; lladdr }, _ when expire_at <= now ->
      (Some (Stale lladdr, is_router), None)
  (* | DELAY | Delay timeout | Send unicast NS probe  | PROBE
     |       |               | Start retransmit timer |
   *)
  | Delay { lladdr; expire_at }, _ when expire_at <= now ->
      let expire_at = now + _1s in
      let sent_probes = 1 in
      (* RFC 4861: SLLA must be the sender's link-layer address *)
      let ns = { NS.target= key; slla= Some mac } in
      let pkt = NS.encode_into ~lladdr ~dst:key ns in
      let action = Some (Packet pkt) in
      (Some (Probe { lladdr; expire_at; sent_probes }, is_router), action)
  (* | PROBE | Retransmit timeout, | Retransmit NS | PROBE
     |       | less than N         |               |
     |       | retransmissions.    |               |
     |       |                     |               |
     | PROBE | Retransmit timeout, | Discard entry | -
     |       | N or more           |               |
     |       | retransmissions.    |               |
   *)
  | Probe { lladdr; expire_at; sent_probes }, _ when expire_at <= now ->
      if sent_probes >= 3 (* MAX_UNICAST_SOLICIT *) then (None, None)
      else begin
        let expire_at = now + _1s in
        let sent_probes = sent_probes + 1 in
        (* RFC 4861: SLLA must be the sender's link-layer address *)
        let ns = { NS.target= key; slla= Some mac } in
        let pkt = NS.encode_into ~lladdr ~dst:key ns in
        let action = Some (Packet pkt) in
        (Some (Probe { lladdr; expire_at; sent_probes }, is_router), action)
      end
  (* | INCOMPLETE | NA, Solicited=1, | Record link-layer    | REACHABLE
     |            | Override=any     | address. Send queued |
     |            |                  | packets.             |
   *)
  | Incomplete _, `NA (_src, _dst, { NA.solicited= true; tlla= Some lladdr; _ })
    ->
      let expire_at = now + _30s in
      (Some (Reachable { lladdr; expire_at }, is_router), None)
  (* | INCOMPLETE | NA, Solicited=0, | Record link-layer    | STALE
     |            | Override=any     | address. Send queued |
     |            |                  | packets.             |
   *)
  | Incomplete _, `NA (_src, _dst, { NA.solicited= false; tlla= Some lladdr; _ })
    ->
      (Some (Stale lladdr, is_router), Some (Release_with (key, lladdr)))
  (* | INCOMPLETE | NA, Solicited=any, | Update content of | unchanged
     |            | Override=any, No   | IsRouter flag     |
     |            | Link-layer address |                   |
   *)
  | Incomplete _, `NA (_src, _dst, { NA.tlla= None; _ }) ->
      (Some (state, true), None)
  (* |  REACHABLE | NA, Solicited=1,     | - | STALE
     |            | Override=0           |   |
     |            | Different link-layer |   |
     |            | address than cached. |   |
   *)
  | ( Reachable { lladdr; _ }
    , `NA (_src, _dst, { NA.solicited= true; tlla= Some lladdr'; _ }) ) ->
      if Macaddr.compare lladdr lladdr' != 0 then
        (Some (Stale lladdr', is_router), None)
      else (Some (state, is_router), None)
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
        (Some (Reachable { lladdr; expire_at }, is_router), None)
      else (Some (state, is_router), None)
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
        (Some (state, is_router), None)
      else if solicited then
        let expire_at = now + _30s in
        (Some (Reachable { lladdr; expire_at }, is_router), None)
      else (* not solicited && Macaddr.compare lladdr lladdr' <> 0 *)
        let () = assert (not solicited) in
        let () = assert (Macaddr.compare lladdr lladdr' <> 0) in
        (Some (Stale lladdr, is_router), None)
  (* | !INCOMPLETE | NA, Solicited=any, | Update content of | unchanged
     |             | Override=any, No   | IsRouter flag.    |
     |             | link-layer address |                   |
   *)
  | ( (Stale _ | Probe _ | Delay _ | Reachable _)
    , `NA (_src, _dst, { NA.tlla= None; router; _ }) ) ->
      (Some (state, router), None)
  (* | !INCOMPLETE | NA, Solicited=0, | - | unchanged
     |             | Override=0       |   |
   *)
  | ( (Stale _ | Probe _ | Delay _ | Reachable _)
    , `NA (_src, _dst, { NA.solicited= false; override= false; _ }) ) ->
      (Some (state, is_router), None)
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
        (Some (state, is_router), Some (Release_with (key, lladdr)))
      else
        let state = Stale lladdr in
        (Some (state, false), None)
  | ( (Stale _ | Probe _ | Delay _ | Reachable _)
    , `NS (src, _dst, { NS.slla= Some lladdr; _ }) ) ->
      let lladdr' = Neighbor.lladdr state in
      let lladdr' = Option.get lladdr' in
      if Ipaddr.V6.compare key src = 0 && Macaddr.compare lladdr lladdr' <> 0
      then
        let state = Stale lladdr in
        (Some (state, is_router), None)
      else
        let state = Stale lladdr in
        (Some (state, false), None)
  | (Incomplete _ | Reachable _ | Delay _ | Probe _ | Stale _), _ ->
      (Some (state, is_router), None)

let tick t ~mac ~now event =
  let fn key value (actions, t') =
    let push = Option.fold ~none:actions ~some:(Fun.flip List.cons actions) in
    match transition ~mac key value now event with
    | Some value', action ->
        let t' = Neighbors.add key value' t' in
        (push action, t')
    | None, action -> (push action, t)
  in
  (* NOTE(dinosaure): even if we can [fold_k] here (which performs better), we
     would like to keep the usage order to clean up then. *)
  let actions, t' = Neighbors.fold fn ([], Neighbors.empty 0x7ff) t in
  (List.rev actions, Neighbors.trim t')

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

let query t ~mac ~now addr =
  (* | - | Packet to send. | Create entry.          | INCOMPLETE
     |   |                 | Send multicast NS.     |
     |   |                 | Start retransmit timer |
   *)
  match Neighbors.find addr t with
  | None ->
      let expire_at = now + _1s in
      let sent_probes = 0 in
      let state = Neighbor.Incomplete { expire_at; sent_probes } in
      let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix addr in
      assert (Ipaddr.V6.is_multicast dst);
      let lladdr = Ipaddr.V6.multicast_to_mac dst in
      (* RFC 4861: SLLA must be the sender's link-layer address *)
      let ns = { NS.target= addr; slla= Some mac } in
      let pkt = NS.encode_into ~lladdr ~dst ns in
      let action = Some (Packet pkt) in
      let t = Neighbors.add addr (state, false) t in
      let t = Neighbors.trim t in
      (t, None, action)
  | Some Neighbor.(Incomplete _, _) -> (t, None, None)
  (* | !INCOMPLETE | upper-layer reachability | - | REACHABLE
     |             | confirmation             |   |

     TODO(dinosaure): not sure that it's currently on this case
     that we should set the state to REACHABLE.
   *)
  | Some
      ( ( Neighbor.Reachable { lladdr; _ }
        | Delay { lladdr; _ }
        | Probe { lladdr; _ } )
      , _ ) ->
      (t, Some lladdr, None)
  (* | STALE | Sending packet | Start delay timer | DELAY *)
  | Some (Neighbor.Stale lladdr, is_router) ->
      let expire_at = now + _5s in
      let state = Neighbor.Delay { lladdr; expire_at } in
      let t = Neighbors.remove addr t in
      let t = Neighbors.add addr (state, is_router) t in
      (t, Some lladdr, None)
