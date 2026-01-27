module SBstr = Slice_bstr

let len sbstr = SBstr.get_uint16_be sbstr 4
let version sbstr = SBstr.get_uint8 sbstr 0 lsr 4
let nhdr sbstr = SBstr.get_uint8 sbstr 6
let ( let* ) = Result.bind
let guard err fn = if fn () then Ok () else Error err

(* Neighbor Advertisement *)
module NA = struct
  type t = {
      router: bool
    ; solicited: bool
    ; override: bool
    ; target: Ipaddr.V6.t
    ; tlla: Macaddr.t option
  }

  let decode sbstr =
    let res = SBstr.get_uint8 sbstr 4 in
    let router = res land 0x80 <> 0 in
    let solicited = res land 0x40 <> 0 in
    let override = res land 0x20 <> 0 in
    let target = SBstr.sub_string sbstr ~off:8 ~len:16 in
    let* target = Ipaddr.V6.of_octets target in
    let* tlla =
      let opts = SBstr.shift sbstr 24 in
      let* opts = options opts in
      let fn = function TLLA v -> Some v | _ -> None in
      List.find_map fn opts |> Result.ok
    in
    Ok { router; solicited; override; target; tlla }
end

module Neighbors = struct
  type state =
    | Incomplete of { expire_at: int; sent_probes: int }
    | Reachable of { addr: Macaddr.t; expire_at: int }
    | Stale of Macaddr.t
    | Delay of { addr: Macaddr.t; expire_at: int }
    | Probe of { addr: Macaddr.t; expire_at: int; sent_probes: int }
end

let solicited_node_prefix =
  Ipaddr.V6.(Prefix.make 104 (of_int16 (0xff02, 0, 0, 0, 0, 1, 0xff00, 0)))

let next key (state, is_router) event =
  match (state, pkt) with
  | Incomplete { expire_at: int; sent_probes; _ }, `Tick now
    when expire_at <= now ->
      if sent_probes >= 3 (* MAX_MULTICAST_SOLICIT *) then
        (* Event: Retransmit timeout, N or more retransmissions. *)
        (* Action: Discard entry. Send ICMPv6 error. *)
        (None, [ Send_ICMPv6_neighbor_unreachable ])
      else
        (* Event: Retransmit timeout, less than N retransmissions. *)
        (* Action: Retransmit NS. Start retransmit timer. *)
        let expire_at = now + _1s in
        let sent_probes = sent_probes + 1 in
        let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix key in
        let actions = [ Send_NS (dst, ipaddr) ] in
        (Some (Incomplete { expire_at; sent_probes }), actions)
  | Reachable { expire_at; addr }, `Tick now when expire_at <= now ->
      (* Event: timeout, more than N seconds since reachability confirm. *)
      Some (Stale addr, [])
  | Delay { addr; expire_at }, `Tick now when expire_at <= now ->
      (* Event: Delay timeout.
         Action: Send unicast NS probe. Start retransmit time. *)
      Some (Probe addr, [])
  | Incomplete _, `NA { NA.solicited= true; tlla= Some addr; _ } ->
      (* Event: NA, Solicited=1. *)
      (* Action: Record link-layer address. Send queued packets. *)
      let expire_at = now + _30s in
      Some (Reachable { addr; expire_at }, [])
  | Incomplete _, `NA { NA.solicited= false; tlla= Some addr; _ } ->
      (* Event: NA, Solicited=0. *)
      (* Action: Record link-layer address. Send queued packets. *)
      let expire_at = now + _30s in
      Some (Stale addr, [])
  | Incomplete incomplete, `NA { NA.ttla= None; _ } ->
      (* Event: NA, No link-layer addres. *)
      (* Action: Update content of [is_router] flag. *)
      (Some (Incomplete { incomplete with is_router= true }), [])
  | Reachable { addr; _ }, `NA { NA.solicited= true; tlla= Some addr'; _ } ->
      if Macaddr.compare addr addr' != 0 then
        (* Event: NA, Solicited=1, Different link-layer address than cached. *)
        Some (Stale addr', [])
      else (Some state, [])
  | Stale addr, `Send now ->
      (* Event: Sending packet at [key]. *)
      (* Action: Start delay timer. *)
      let expire_at = now + _5s in
      Some (Delay { addr; expire_at }, [])
  | ((Stale _ | Probe _ | Delay _) as state), `NA { NA.solicited= true; _ } ->
      (* Event: NA, Solicited=1, Different link-layer address than cached. *)
      (Some state, [])

type opt =
  | SLLA of Macaddr.t
  | TLLA of Macaddr.t
  | MTU of int
  | PREFIX of prefix

and prefix = {
    on_link: bool
  ; autonomous: bool
  ; valid_lifetime: int option
  ; preferred_lifetime: int option
  ; prefix: Ipaddr.V6.Prefix.t
}

let rec options acc sbstr =
  if SBstr.length sbstr >= 2 then
    let len = SBstr.get_uint8 sbstr 1 * 8 in
    let opt = SBstr.sub sbstr ~off:0 ~len in
    let rem = SBstr.shift sbstr len in
    match (SBstr.get_uint8 opt 0, SBstr.get_uint8 opt 1) with
    | 1, 1 ->
        let addr = SBstr.sub_string opt ~off:2 ~len:6 in
        let* addr = Macaddr.of_octets addr in
        options (SLLA addr :: acc) rem
    | 2, 1 ->
        let addr = SBstr.sub_string opt ~off:2 ~len:6 in
        let* addr = Macaddr.of_octets addr in
        options (TLLA addr :: acc) rem
    | 5, 1 ->
        let value = SBstr.get_int32_be opt 4 in
        options (MTU (Int32.to_int value) :: acc) rem
    | 3, 4 ->
        let prefix = SBstr.sub_string opt ~off:16 ~len:16 in
        let* prefix = Ipaddr.V6.of_octets prefix in
        let prefix = Ipaddr.V6.Prefix.make (SBstr.get_uint8 opt 1) prefix in
        let on_link = SBstr.get_uint8 opt 3 land 0x80 <> 0 in
        let autonomous = SBstr.get_uint8 opt 3 land 0x40 <> 0 in
        let valid_lifetime =
          match SBstr.get_int32_be opt 4 with
          | 0xffffffffl -> None
          | n -> Some (Int32.to_int n)
        in
        let preferred_lifetime =
          match SBstr.get_int32_be opt 8 with
          | 0xffffffffl -> None
          | n -> Some (Int32.to_int n)
        in
        let value =
          PREFIX
            { on_link; autonomous; valid_lifetime; preferred_lifetime; prefix }
        in
        options (value :: acc) rem
    | _ -> options acc rem
  else Ok (List.rev acc)

let options sbstr = options [] sbstr

module NS = struct
  type t = { target: Ipaddr.V6.t; slla: Macaddr.t option }

  let decode sbstr =
    let target = SBstr.sub_string sbstr ~off:6 ~len:16 in
    let* target = Ipaddr.V6.of_octets target in
    let* slla =
      let opts = SBstr.shift sbstr 24 in
      let* opts = options opts in
      let fn = function SLLA v -> Some v | _ -> None in
      List.find_map fn opts |> Result.ok
    in
    Ok { target; slla }
end

(* Router Advertisement *)
module RA = struct
  type t = {
      current_hop_limit: int
    ; router_lifetime: int
    ; reachable_time: int option
    ; retrans_timer: int option
    ; slla: Macaddr.t option
    ; prefix: prefix list
  }

  let decode sbstr =
    let current_hop_limit = SBstr.get_uint8 sbstr 4 in
    let router_lifetime = SBstr.get_uint16_be sbstr 6 in
    let reachable_time = SBstr.get_int32_be sbstr 8 in
    let reachable_time =
      if reachable_time = 0l then None
      else Some (Int32.to_int reachable_time / 1000)
    in
    let retrans_timer = SBstr.get_int32_be sbstr 12 in
    let retrans_timer =
      if retrans_timer = 0l then None
      else Some (Int32.to_int retrans_timer / 1000)
    in
    let* slla, prefix =
      let opts = SBstr.shift sbstr 16 in
      let* opts = options opts in
      let fn = function SLLA v -> Some v | _ -> None in
      let slla = List.find_map fn opts in
      let fn = function PREFIX v -> Some v | _ -> None in
      let prefix = List.filter_map fn opts in
      Ok (slla, prefix)
    in
    Ok
      {
        current_hop_limit
      ; router_lifetime
      ; reachable_time
      ; retrans_timer
      ; slla
      ; prefix
      }
end

module ICMP = struct
  let checksum =
    let hdr = Bytes.create 8 in
    Bytes.set_int32_be hdr 4 48l;
    fun payload ->
      Bytes.set_int32_be hdr 0 (Int32.of_int (SBstr.length payload));
      let chk =
        Utcp.Checksum.feed_string ~off:0 ~len:0 0 (Bytes.unsafe_to_string hdr)
      in
      let { Slice.buf; off; len } = payload in
      let cs = Cstruct.of_bigarray buf ~off ~len in
      let chk = Utcp.Checksum.feed_cstruct chk cs in
      Utcp.Checksum.finally chk

  let decode ~src ~dst sbstr off =
    let payload = SBstr.shift sbstr off in
    let chk = checksum payload in
    let* () = guard `Invalid_ICMP_checksum @@ fun () -> chk == 0 in
    match SBstr.get_uint8 payload 0 with
    | 128 ->
        let uid = SBstr.get_uint16_be payload 4 in
        let seq = SBstr.get_uint16_be payload 6 in
        Ok (`Ping (src, dst, uid, seq, SBstr.shift payload 8))
    | 129 -> Ok (`Pong payload)
    | 133 -> Error `Drop_RS
    | 134 ->
        (* The packet does not come from a direct neighbour if hlimit is not
           255. It must be dropped. It is the same of NS and NA. *)
        let hlim = SBstr.get_uint8 sbstr 7 in
        if hlim <> 255 then Error `Drop
        else
          let* ra = RA.decode payload in
          Ok (`RA (src, dst, ra))
    | 135 ->
        let hlim = SBstr.get_uint8 sbstr 7 in
        if hlim <> 255 then Error `Drop
        else
          let* ns = NS.decode payload in
          if Ipaddr.V6.is_multicast ns.NS.target then Error `Drop
          else Ok (`NS (src, dst, ns))
    | 136 ->
        let hlim = SBstr.get_uint8 sbstr 7 in
        if hlim <> 255 then Error `Drop
        else
          let* na = NA.decode payload in
          if
            Ipaddr.V6.is_multicast na.NA.target
            || (na.NA.solicited && Ipaddr.V6.is_multicast dst)
          then Error `Drop
          else Ok (`NA (src, dst, na))
    | 137 ->
        let hlim = SBstr.get_uint8 sbstr 7 in
        if hlim <> 255 then Error `Drop
        else
          (* let _redirect = redirect payload in *)
          Error `Drop
    | 1 -> Error `Destination_unreachable
    | 2 ->
        let mtu = Int32.to_int (SBstr.get_int32_be payload 4) in
        if mtu < 1280 then Error `Drop else Ok (`Packet_too_big (src, dst, mtu))
    | 3 -> Error `Time_exceeded
    | 4 -> Error `Parameter_problem
    | n -> Error (`Unknown_ICMP_packet n)
end

let rec with_extension ~src ~dst sbstr ?(first = false) hdr off =
  match hdr with
  | 0 when first -> with_options ~src ~dst sbstr off
  | 0 -> Error `Drop
  | 60 -> with_options ~src ~dst sbstr off
  | 43 | 44 | 50 | 51 | 135 | 59 -> Error `Drop
  | 58 -> ICMP.decode ~src ~dst sbstr off
  | 17 -> Ok (`UDP (src, dst, SBstr.shift sbstr off))
  | 6 -> Ok (`TCP (src, dst, SBstr.shift sbstr off))
  | n when 143 <= n && n <= 255 -> Ok `Drop
  | n -> Ok (`Default (n, src, dst, SBstr.shift sbstr off))

and with_options ~src ~dst sbstr off =
  let payload = SBstr.shift sbstr off in
  let nhdr = SBstr.get_uint8 payload 0 in
  let opt_len = SBstr.get_uint8 payload 1 in
  let rec go src_off =
    if src_off < off + opt_len then
      let opt = SBstr.shift sbstr src_off in
      match SBstr.get_uint8 opt 0 with
      | 0 -> go (src_off + 1)
      | 1 ->
          let len = SBstr.get_uint8 opt 1 in
          go (src_off + 2 + len)
      | _ as n -> begin
          let len = SBstr.get_uint8 opt 1 in
          match n land 0xc0 with
          | 0x00 -> go (src_off + 2 + len)
          | 0x40 -> Error `Drop
          | 0x80 -> Error (`ICMP_error (4, 2, src_off))
          | 0xc0 when Ipaddr.V6.is_multicast dst -> Error `Drop
          | 0xc0 -> Error (`ICMP_error (4, 2, src_off))
          | _ -> assert false (* TODO(dinosaure): [Error]? *)
        end
    else with_extension ~src ~dst sbstr nhdr (off + opt_len)
  in
  go (off + 2)

let decode is_my_addr payload =
  if SBstr.length payload < 40 || SBstr.length payload < 40 + len payload then
    Error `Truncated
  else if version payload <> 6 then Error `Bad_version
  else
    let sbstr = SBstr.sub payload ~off:0 ~len:(40 + len payload) in
    let src = SBstr.sub_string sbstr ~off:8 ~len:16 in
    let* src = Ipaddr.V6.of_octets src in
    let dst = SBstr.sub_string sbstr ~off:24 ~len:16 in
    let* dst = Ipaddr.V6.of_octets dst in
    if Ipaddr.V6.Prefix.(mem src multicast) then Error `Drop
    else if not (is_my_addr dst || Ipaddr.V6.Prefix.(mem dst multicast)) then
      Error `Drop
    else with_extension ~src ~dst sbstr ~first:true (nhdr sbstr) 40

(* NOTE(dinosaure):

   - The IPv6 minimum link MTU is 1280
   - A black-hole connection: this is when ICMPv6 packets are filtered by a
     proxy and the machine is never notified that it must fragment packets
 *)

module Dst = struct
  module Entry = struct
    type ivar = Macaddr.t Miou.Computation.t

    type t =
      | Pending of { ivar: ivar; retry: int }
      | Dynamic of { addr: Macaddr.t; mtu: int; epoch: int }

    let is_obsolete = function Dynamic _ -> true | Pending _ -> false
  end

  module Key = struct
    include Ipaddr.V6

    let equal a b = Ipaddr.V6.compare a b = 0
    let hash = Hashtbl.hash
  end

  module Entries = Table.Make (Key) (Entry)

  type t = { entries: Entries.t; mutable epoch: int; eth: Ethernet.t }
end

(*
module RC : sig
  type t

  val tick : t -> unit
  val query : Ipaddr.V6.t -> (int * Macaddr.t, [> error ]) result
  val ask : Ipaddr.V6.t -> (int * Macaddr.t) option
end = struct
  module K = struct
    type t = { ipaddr: Ipaddr.V6.t; mtu: int }

    let equal a b = Ipaddr.V6.compare a.ipaddr b.ipaddr = 0
    let hash = Hashtbl.hash
  end

  module V = struct
    type t = unit

    let weight (_ : t) = 1
  end

  module Lru = Lru.M.Make (K) (V)

  type t =
    { entries : }
end
*)
