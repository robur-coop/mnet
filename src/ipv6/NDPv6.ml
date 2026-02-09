let src = Logs.Src.create "mnet.ndpv6"

module Log = (val Logs.src_log src : Logs.LOG)
module SBstr = Slice_bstr

let ( let* ) = Result.bind
let guard err fn = if fn () then Ok () else Error err

module Fragment = struct
  type t = { uid: int; off: int; protocol: int; payload: SBstr.t; last: bool }
end

module Parser = struct
  let rec options acc sbstr =
    if SBstr.length sbstr >= 2 then
      let len = SBstr.get_uint8 sbstr 1 * 8 in
      let* () = guard `Invalid_option @@ fun () -> len >= 2 in
      let opt = SBstr.sub sbstr ~off:0 ~len in
      let rem = SBstr.shift sbstr len in
      match (SBstr.get_uint8 opt 0, SBstr.get_uint8 opt 1) with
      | 1, 1 ->
          let lladdr = SBstr.sub_string opt ~off:2 ~len:6 in
          let* lladdr = Macaddr.of_octets lladdr in
          options (`SLLA lladdr :: acc) rem
      | 2, 1 ->
          let lladdr = SBstr.sub_string opt ~off:2 ~len:6 in
          let* lladdr = Macaddr.of_octets lladdr in
          options (`TLLA lladdr :: acc) rem
      | 5, 1 ->
          let value = SBstr.get_int32_be opt 4 in
          options (`MTU (Int32.to_int value) :: acc) rem
      | 3, 4 ->
          let prefix = SBstr.sub_string opt ~off:16 ~len:16 in
          let* prefix = Ipaddr.V6.of_octets prefix in
          let prefix = Ipaddr.V6.Prefix.make (SBstr.get_uint8 opt 2) prefix in
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
            `PREFIX
              {
                Prefixes.Pfx.on_link
              ; autonomous
              ; valid_lifetime
              ; preferred_lifetime
              ; prefix
              }
          in
          options (value :: acc) rem
      | _ -> options acc rem
    else Ok (List.rev acc)

  let options sbstr = options [] sbstr

  let decode_na sbstr =
    let res = SBstr.get_uint8 sbstr 4 in
    let router = res land 0x80 <> 0 in
    let solicited = res land 0x40 <> 0 in
    let override = res land 0x20 <> 0 in
    let target = SBstr.sub_string sbstr ~off:8 ~len:16 in
    let* target = Ipaddr.V6.of_octets target in
    let* tlla =
      let opts = SBstr.shift sbstr 24 in
      let* opts = options opts in
      let fn = function `TLLA v -> Some v | _ -> None in
      List.find_map fn opts |> Result.ok
    in
    Ok { Neighbors.NA.router; solicited; override; target; tlla }

  let decode_redirect sbstr =
    let* () = guard `Drop @@ fun () -> SBstr.get_uint8 sbstr 1 = 0 in
    (* Code = 0 *)
    let target = SBstr.sub_string sbstr ~off:8 ~len:16 in
    let* target = Ipaddr.V6.of_octets target in
    let destination = SBstr.sub_string sbstr ~off:24 ~len:16 in
    let* destination = Ipaddr.V6.of_octets destination in
    (* RFC 4861 Section 8.1: Destination Address must not be multicast *)
    let* () =
      guard `Drop @@ fun () -> not (Ipaddr.V6.is_multicast destination)
    in
    Ok { Dsts.Redirect.target; destination }

  let decode_destination_unreachable sbstr =
    let code = SBstr.get_uint8 sbstr 1 in
    (* Extract original destination from the included IPv6 header *)
    let* () = guard `Drop @@ fun () -> SBstr.length sbstr >= 48 in
    let destination = SBstr.sub_string sbstr ~off:32 ~len:16 in
    let* destination = Ipaddr.V6.of_octets destination in
    Ok { Dsts.Unreachable.code; destination }

  let decode_packet_too_big sbstr =
    let mtu = Int32.to_int (SBstr.get_int32_be sbstr 4) in
    (* RFC 8201: MTU must be at least 1280 *)
    let* () = guard `Drop @@ fun () -> mtu >= 1280 in
    (* Extract original destination from the included IPv6 header *)
    let* () = guard `Drop @@ fun () -> SBstr.length sbstr >= 48 in
    let destination = SBstr.sub_string sbstr ~off:32 ~len:16 in
    let* destination = Ipaddr.V6.of_octets destination in
    Ok { Dsts.PTB.mtu; destination }

  let decode_ns sbstr =
    let target = SBstr.sub_string sbstr ~off:8 ~len:16 in
    let* target = Ipaddr.V6.of_octets target in
    let* slla =
      let opts = SBstr.shift sbstr 24 in
      let* opts = options opts in
      let fn = function `SLLA v -> Some v | _ -> None in
      List.find_map fn opts |> Result.ok
    in
    Ok { Neighbors.NS.target; slla }

  let decode_ra sbstr =
    let current_hop_limit = SBstr.get_uint8 sbstr 4 in
    (* RFC 4191 Section 2.2: Router Preference is bits 3-4 of the flags byte.
       00 = Medium (default), 01 = High, 10 = Low, 11 = Reserved (treat as 0) *)
    let flags = SBstr.get_uint8 sbstr 5 in
    let preference =
      match (flags lsr 3) land 0x3 with
      | 0x3 -> 0 (* Reserved, treat as Medium *)
      | prf -> prf
    in
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
    let* slla, lmtu, prefix =
      let opts = SBstr.shift sbstr 16 in
      let* opts = options opts in
      let fn = function `SLLA v -> Some v | _ -> None in
      let slla = List.find_map fn opts in
      let fn = function `MTU v -> Some v | _ -> None in
      let lmtu = List.find_map fn opts in
      let fn = function `PREFIX v -> Some v | _ -> None in
      let prefix = List.filter_map fn opts in
      Ok (slla, lmtu, prefix)
    in
    Ok
      {
        Routers.RA.current_hop_limit
      ; preference
      ; router_lifetime
      ; reachable_time
      ; retrans_timer
      ; slla
      ; lmtu
      ; prefix
      }

  let checksum ~src ~dst ?(protocol = 58l) payload =
    let src = Ipaddr.V6.to_octets src in
    let dst = Ipaddr.V6.to_octets dst in
    let chk = Utcp.Checksum.feed_string ~off:0 ~len:16 0 src in
    let chk = Utcp.Checksum.feed_string ~off:0 ~len:16 chk dst in
    let len = SBstr.length payload in
    let hdr = Bytes.create 8 in
    Bytes.set_int32_be hdr 0 (Int32.of_int len);
    Bytes.set_int32_be hdr 4 protocol;
    let hdr = Bytes.unsafe_to_string hdr in
    let chk = Utcp.Checksum.feed_string ~off:0 ~len:8 chk hdr in
    let { Slice.buf; off; len } = payload in
    let cs = Cstruct.of_bigarray buf ~off ~len in
    let chk = Utcp.Checksum.feed_cstruct chk cs in
    Utcp.Checksum.finally chk

  let decode_icmp ~src ~dst sbstr off =
    let payload = SBstr.shift sbstr off in
    let chk = checksum ~src ~dst payload in
    let* () = guard `Invalid_ICMP_checksum @@ fun () -> chk = 0 in
    match SBstr.get_uint8 payload 0 with
    | 128 | 129 -> Ok (`Packet (58, src, dst, payload))
    | 133 -> Error `Drop
    | 134 ->
        (* The packet does not come from a direct neighbour if [hlim] is not
           255. It must be dropped. It is the same of [`NS], [`NA] and
           [`Redirect]. *)
        let hlim = SBstr.get_uint8 sbstr 7 in
        if hlim <> 255 then Error `Drop
          (* RFC 4861 6.1.2: Source Address MUST be the link-local address
             assigned to the interface from which this message is sent. *)
        else if not Ipaddr.V6.Prefix.(mem src link) then Error `Drop
        else
          let* ra = decode_ra payload in
          Ok (`RA (src, dst, ra))
    | 135 ->
        let hlim = SBstr.get_uint8 sbstr 7 in
        if hlim <> 255 then Error `Drop
        else
          let* ns = decode_ns payload in
          if Ipaddr.V6.is_multicast ns.Neighbors.NS.target then Error `Drop
          else Ok (`NS (src, dst, ns))
    | 136 ->
        let hlim = SBstr.get_uint8 sbstr 7 in
        if hlim <> 255 then Error `Drop
        else
          let* na = decode_na payload in
          if
            Ipaddr.V6.is_multicast na.Neighbors.NA.target
            || (na.Neighbors.NA.solicited && Ipaddr.V6.is_multicast dst)
          then Error `Drop
          else Ok (`NA (src, dst, na))
    | 137 ->
        let hlim = SBstr.get_uint8 sbstr 7 in
        if hlim <> 255 then Error `Drop
          (* RFC 4861 Section 8.1: Source must be link-local address of a router *)
        else if not Ipaddr.V6.Prefix.(mem src link) then Error `Drop
        else
          let* redirect = decode_redirect payload in
          Ok (`Redirect (src, redirect))
    | 1 ->
        let* unreachable = decode_destination_unreachable payload in
        Ok (`Destination_unreachable unreachable)
    | 2 ->
        let* ptb = decode_packet_too_big payload in
        Ok (`Packet_too_big ptb)
    | 3 -> Error `Time_exceeded
    | 4 -> Error `Parameter_problem
    | n -> Error (`Unknown_ICMP_packet n)

  let rec with_extension ~src ~dst sbstr ?(first = false) nhdr off =
    match nhdr with
    | 0 when first -> with_options ~src ~dst sbstr off
    | 0 -> Error `Drop
    | 60 -> with_options ~src ~dst sbstr off
    | 44 ->
        let frag = SBstr.shift sbstr off in
        let payload = SBstr.shift sbstr (off + 8) in
        let protocol = SBstr.get_uint8 frag 0 in
        let off = (SBstr.get_uint16_be frag 2 lsr 3) * 8 in
        let more = SBstr.get_uint16_be frag 2 land 1 = 1 in
        let uid = Int32.to_int (SBstr.get_int32_be frag 4) in
        let frag = { Fragment.protocol; off; last= not more; uid; payload } in
        Ok (`Fragment (src, dst, frag))
    | 43 | 44 | 50 | 51 | 135 | 59 -> Error `Drop
    | 58 -> decode_icmp ~src ~dst sbstr off
    | n when 143 <= n && n <= 255 -> Error `Drop
    | protocol -> Ok (`Packet (protocol, src, dst, SBstr.shift sbstr off))

  and with_options ~src ~dst sbstr off =
    let payload = SBstr.shift sbstr off in
    let nhdr = SBstr.get_uint8 payload 0 in
    let opt_len = (SBstr.get_uint8 payload 1 * 8) + 8 in
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

  let decode ~is_my_addr payload =
    let len = SBstr.get_uint16_be payload 4 in
    let version = SBstr.get_uint8 payload 0 lsr 4 in
    if SBstr.length payload < 40 || SBstr.length payload < 40 + len then
      Error `Truncated
    else if version <> 6 then Error `Bad_version
    else
      let sbstr = SBstr.sub payload ~off:0 ~len:(40 + len) in
      let src = SBstr.sub_string sbstr ~off:8 ~len:16 in
      let* src = Ipaddr.V6.of_octets src in
      let dst = SBstr.sub_string sbstr ~off:24 ~len:16 in
      let* dst = Ipaddr.V6.of_octets dst in
      if Ipaddr.V6.Prefix.(mem src multicast) then Error `Drop
      else if not (is_my_addr dst || Ipaddr.V6.Prefix.(mem dst multicast)) then
        Error `Drop
      else
        let nhdr = SBstr.get_uint8 payload 6 in
        with_extension ~src ~dst sbstr ~first:true nhdr 40
end

module Packet = struct
  type t = { dst: Macaddr.t; len: int; fn: Bstr.t -> unit }
  type user's_packet = { len: int; fn: Bstr.t -> unit }
end

module RS = struct
  let encode_into ~mac select =
    let dst = Ipaddr.V6.link_routers in
    let src = select dst in
    let include_slla = Ipaddr.V6.compare src Ipaddr.V6.unspecified <> 0 in
    let slla_len = if include_slla then 8 else 0 in
    let payload_len = 8 + slla_len in
    let len = 40 + payload_len in
    let fn bstr =
      Bstr.set_int32_be bstr 0 0x60000000l;
      Bstr.set_uint16_be bstr 4 payload_len;
      Bstr.set_uint8 bstr 6 58 (* ICMPv6 *);
      Bstr.set_uint8 bstr 7 255 (* HOP limit *);
      let ssrc = Ipaddr.V6.to_octets src in
      Bstr.blit_from_string ssrc ~src_off:0 bstr ~dst_off:8 ~len:16;
      let sdst = Ipaddr.V6.to_octets dst in
      Bstr.blit_from_string sdst ~src_off:0 bstr ~dst_off:24 ~len:16;
      Bstr.set_uint8 bstr 40 133;
      Bstr.set_uint8 bstr 41 0 (* code *);
      Bstr.set_uint16_be bstr 42 0 (* checksum *);
      Bstr.set_int32_be bstr 44 0l (* reserved *);
      if include_slla then begin
        let bstr = Bstr.shift bstr 48 in
        Bstr.set_uint8 bstr 0 1;
        Bstr.set_uint8 bstr 1 1;
        let slla = Macaddr.to_octets mac in
        Bstr.blit_from_string slla ~src_off:0 bstr ~dst_off:2 ~len:6
      end;
      let cs0 = Cstruct.of_bigarray bstr ~off:8 ~len:32 in
      let cs1 =
        Neighbors.cs_of_len_and_protocol ~len:payload_len ~protocol:58
      in
      let payload = SBstr.make bstr ~off:40 ~len:payload_len in
      let chk = Parser.checksum ~src ~dst payload in
      Bstr.set_uint16_be bstr 42 chk
    in
    let dst = Ipaddr.V6.multicast_to_mac dst in
    { Packet.dst; len; fn }
end

module NA = struct
  include Neighbors.NA

  let encode_into ~mac ~src ~dst:(dst, addr) ?(solicited = false)
      ?(router = false) ?(override = true) ?tlla target =
    let include_tlla = Option.is_some tlla in
    let tlla_len = if include_tlla then 8 else 0 in
    let payload_len = 24 + tlla_len in
    let len = 40 + payload_len in
    let fn bstr =
      Bstr.set_int32_be bstr 0 0x60000000l;
      Bstr.set_uint16_be bstr 4 payload_len;
      Bstr.set_uint8 bstr 6 58 (* ICMPv6 *);
      Bstr.set_uint8 bstr 7 255 (* HOP limit *);
      let ssrc = Ipaddr.V6.to_octets src in
      Bstr.blit_from_string ssrc ~src_off:0 bstr ~dst_off:8 ~len:16;
      let sdst = Ipaddr.V6.to_octets addr in
      Bstr.blit_from_string sdst ~src_off:0 bstr ~dst_off:24 ~len:16;
      Bstr.set_uint8 bstr 40 136;
      Bstr.set_uint8 bstr 41 0 (* code *);
      Bstr.set_uint16_be bstr 42 0 (* checksum *);
      let reserved = 0 in
      let reserved = if router then (1 lsl 31) lor reserved else reserved in
      let reserved = if solicited then (1 lsl 30) lor reserved else reserved in
      let reserved = if override then (1 lsl 29) lor reserved else reserved in
      let reserved = Int32.of_int reserved in
      Bstr.set_int32_be bstr 44 reserved (* router|solicited|override *);
      let target = Ipaddr.V6.to_octets target in
      Bstr.blit_from_string target ~src_off:0 bstr ~dst_off:48 ~len:16;
      if include_tlla then begin
        Bstr.set_uint8 bstr 64 2;
        Bstr.set_uint8 bstr 65 1;
        let tlla = Macaddr.to_octets mac in
        Bstr.blit_from_string tlla ~src_off:0 bstr ~dst_off:66 ~len:6
      end;
      let payload = SBstr.make bstr ~off:40 ~len:payload_len in
      let chk = Parser.checksum ~src ~dst:addr payload in
      Bstr.set_uint16_be bstr 42 chk
    in
    { Packet.dst; len; fn }
end

type t = {
    neighbors: Neighbors.t
  ; routers: Routers.t
  ; prefixes: Prefixes.t
  ; addrs: Addrs.t
  ; dsts: Dsts.t
  ; queues: Packet.user's_packet list Ipaddr.V6.Map.t
  ; lmtu: int
  ; iid: string
  ; mac: Macaddr.t
}

let src t ?src dst =
  match src with Some src -> src | None -> Addrs.select t.addrs dst

let addresses t = Addrs.addresses t.addrs

let push addr pkts queues =
  match Ipaddr.V6.Map.find_opt addr queues with
  | Some pkts' -> Ipaddr.V6.Map.add addr (List.rev_append pkts pkts') queues
  | None -> Ipaddr.V6.Map.add addr pkts queues

type event =
  [ `Packet of int * Ipaddr.V6.t * Ipaddr.V6.t * SBstr.t
  | `Destination_unreachable of Dsts.Unreachable.t
  | `NA of Ipaddr.V6.t * Ipaddr.V6.t * NA.t
  | `NS of Ipaddr.V6.t * Ipaddr.V6.t * Neighbors.NS.t
  | `Packet_too_big of Dsts.PTB.t
  | `Ping of Ipaddr.V6.t * Ipaddr.V6.t * int * int * SBstr.t
  | `Pong of SBstr.t
  | `RA of Ipaddr.V6.t * Ipaddr.V6.t * Routers.RA.t
  | `Redirect of Ipaddr.V6.t * Dsts.Redirect.t
  | `Fragment of Ipaddr.V6.t * Ipaddr.V6.t * Fragment.t
  | `Tick ]

let pp_event ppf = function
  | `Packet (protocol, src, dst, payload) ->
      let { Slice.off; len; buf } = payload in
      let bstr = Bstr.sub ~off ~len buf in
      let str = Bstr.to_string bstr in
      Fmt.pf ppf "[%d] %a -> %a: @[<hov>%a@]" protocol Ipaddr.V6.pp src
        Ipaddr.V6.pp dst
        (Hxd_string.pp Hxd.default)
        str
  | `Destination_unreachable v -> Dsts.Unreachable.pp ppf v
  | `NA (src, dst, na) ->
      Fmt.pf ppf "na:%a -> %a: @[<hov>%a@]" Ipaddr.V6.pp src Ipaddr.V6.pp dst
        NA.pp na
  | `NS (src, dst, ns) ->
      Fmt.pf ppf "ns:%a -> %a: @[<hov>%a@]" Ipaddr.V6.pp src Ipaddr.V6.pp dst
        Neighbors.NS.pp ns
  | `Packet_too_big ptb -> Dsts.PTB.pp ppf ptb
  | `Ping (src, dst, uid, seq, payload) ->
      let { Slice.off; len; buf } = payload in
      let bstr = Bstr.sub ~off ~len buf in
      let str = Bstr.to_string bstr in
      Fmt.pf ppf "%a -> %a [ping:%d:%d]: @[<hov>%a@]" Ipaddr.V6.pp src
        Ipaddr.V6.pp dst uid seq
        (Hxd_string.pp Hxd.default)
        str
  | `Pong payload ->
      let { Slice.off; len; buf } = payload in
      let bstr = Bstr.sub ~off ~len buf in
      let str = Bstr.to_string bstr in
      Fmt.pf ppf "pong:@[<hov>%a@]" (Hxd_string.pp Hxd.default) str
  | `RA (src, dst, ra) ->
      Fmt.pf ppf "ra:%a -> %a: @[<hov>%a@]" Ipaddr.V6.pp src Ipaddr.V6.pp dst
        Routers.RA.pp ra
  | `Redirect (src, r) ->
      Fmt.pf ppf "redirect:%a -> %a" Ipaddr.V6.pp src Dsts.Redirect.pp r
  | `Tick -> Fmt.string ppf "tick"
  | `Fragment _ -> Fmt.string ppf "Fragment"

let next_hop t addr =
  if
    Ipaddr.V6.is_multicast addr
    || Ipaddr.V6.Prefix.(mem addr link)
    || Prefixes.is_local t.prefixes addr
  then
    (* on-link *)
    Ok (t, addr, Some t.lmtu)
  else
    match Dsts.next_hop addr t.dsts with
    | Ok (next_hop, pmtu, dsts) -> Ok ({ t with dsts }, next_hop, Some pmtu)
    | Error `Not_found ->
        let is_reachable = Neighbors.is_reachable t.neighbors in
        let next_hop, mtu, routers =
          Routers.select t.routers ~is_reachable addr
        in
        let dsts =
          if Ipaddr.V6.compare next_hop addr = 0 then t.dsts
          else Dsts.add t.dsts ?mtu addr next_hop
        in
        Ok ({ t with routers; dsts }, next_hop, mtu)
    | Error #Dsts.error as err -> err

let process t = function
  | Neighbors.Release_with (dst, lladdr) ->
      let queues = t.queues in
      let queues, pkts =
        match Ipaddr.V6.Map.find_opt dst queues with
        | Some pkts ->
            let queues = Ipaddr.V6.Map.remove dst queues in
            let fn { Packet.len; fn } = { Packet.dst= lladdr; len; fn } in
            let pkts = List.map fn pkts in
            (queues, pkts)
        | None -> (queues, [])
      in
      ({ t with queues }, pkts)
  | Cancel dst ->
      let queues = Ipaddr.V6.Map.remove dst t.queues in
      (* TODO(dinosaure): Send an ICMPv6, Neighbor unreachable? *)
      ({ t with queues }, [])
  | Packet { Neighbors.Packet.lladdr; dst; len; fn } ->
      let src = src t dst in
      let fn = fn ~src in
      let pkt = { Packet.dst= lladdr; len; fn } in
      (t, [ pkt ])

let send t ~now ~dst next_hop (user's_pkts : Packet.user's_packet list) =
  if Ipaddr.V6.is_multicast next_hop then
    let dst = Ipaddr.V6.multicast_to_mac next_hop in
    let fn { Packet.len; fn } = { Packet.dst; len; fn } in
    let pkts = List.map fn user's_pkts in
    (t, pkts)
  else
    let neighbors, lladdr, act =
      Neighbors.query t.neighbors ~mac:t.mac ~now next_hop
    in
    let t = { t with neighbors } in
    let t, pkts = Option.fold ~none:(t, []) ~some:(process t) act in
    match lladdr with
    | Some dst ->
        let fn { Packet.len; fn } = { Packet.dst; len; fn } in
        (* NOTE(dinosaure): here, the order of [pkts] is not important. *)
        let pkts = List.rev_append (List.map fn user's_pkts) pkts in
        (t, pkts)
    | None ->
        let queues = push dst user's_pkts t.queues in
        ({ t with queues }, pkts)

let tick t ~now (event : event) =
  (* NOTE(dinosaure): [Prefixes] only consumes prefixes's RA. *)
  let pfxs =
    match event with `RA (_, _, ra) -> ra.Routers.RA.prefix | _ -> []
  in
  let prefixes = Prefixes.tick t.prefixes ~now pfxs in
  let routers_to_delete, routers = Routers.tick t.routers ~now event in
  let dsts = Dsts.clean_old_routers routers_to_delete t.dsts in
  let addrs, pkts = Addrs.tick t.addrs ~now ~iid:t.iid event in
  let acts0 = List.map (fun pkt -> Neighbors.Packet pkt) pkts in
  (* NOTE(dinosaure): [acts0] contains only packets to send, so we don't need to
     change anything from our current state [t]. Only
     [Neighbors.{Release_with,Cancel}] can change the state [t] (and particulary
     [t.queues]). We can therefore defer the [acts0] process and merge it with
     [acts1] without any implications for our state [t]. *)
  let acts1, neighbors = Neighbors.tick t.neighbors ~mac:t.mac ~now event in
  let event =
    match event with
    | `Redirect (src, _) when not (Routers.mem routers src) ->
        (* RFC 4861 Section 8.1: Redirect must come from a router we know about.
           We validate the source before passing to [Dsts.tick]. We ignore them
           if it's not the case. *)
        `Tick
    | _ -> event
  in
  let dsts = Dsts.tick dsts ~now event in
  let t = { t with neighbors; routers; prefixes; addrs; dsts } in
  let t, pkts =
    let fn (t, pkts) act =
      let t, pkts' = process t act in
      (t, List.rev_append pkts' pkts)
    in
    List.fold_left fn (t, []) (List.rev_append acts0 acts1)
  in
  (* NOTE(dinosaure): Here, we want to manage NS packets and respond to them
     with a NA. The generated packet can statically know its MAC destination
     (unlike [Neighbors.Packet.t]). So we manage it here. *)
  let pkts =
    match event with
    | `NS (src, _, { Neighbors.NS.target; slla })
      when Addrs.is_my_addr t.addrs target ->
        let lladdr, dst, solicited =
          if Ipaddr.V6.compare src Ipaddr.V6.unspecified = 0 then
            let dst = Ipaddr.V6.link_nodes in
            let lladdr = Ipaddr.V6.multicast_to_mac dst in
            (lladdr, dst, false)
          else
            match slla with
            | None ->
                let dst = Ipaddr.V6.link_nodes in
                let lladdr = Ipaddr.V6.multicast_to_mac dst in
                (lladdr, dst, false)
            | Some lladdr -> (lladdr, src, true)
        in
        let pkt =
          NA.encode_into ~mac:t.mac ~src:target ~dst:(lladdr, dst) ~solicited
            ~tlla:t.mac target
        in
        pkt :: pkts
    | _ -> pkts
  in
  (t, pkts)

type mode = Random | EUI64 | Static of Ipaddr.V6.Prefix.t

let iid_of_mac mac =
  let octets = Macaddr.to_octets mac in
  let buf = Bytes.create 8 in
  Bytes.set buf 0 (Char.chr (Char.code octets.[0] lxor 0x02));
  Bytes.set buf 1 octets.[1];
  Bytes.set buf 2 octets.[2];
  Bytes.set buf 3 '\xff';
  Bytes.set buf 4 '\xfe';
  Bytes.set buf 5 octets.[3];
  Bytes.set buf 6 octets.[4];
  Bytes.set buf 7 octets.[5];
  Bytes.unsafe_to_string buf

let anonymous_iid () =
  let buf = Bytes.of_string (Mirage_crypto_rng.generate 8) in
  let b = Char.code (Bytes.get buf 0) in
  Bytes.set buf 0 (Char.chr (b lor 0x02 land 0xfe));
  Bytes.unsafe_to_string buf

let make ~now ~lmtu ~mac mode =
  let iid, addr =
    match mode with
    | Random -> (anonymous_iid (), None)
    | EUI64 -> (iid_of_mac mac, None)
    | Static prefix -> (iid_of_mac mac, Some prefix)
  in
  let neighbors = Neighbors.make 0x100 in
  let routers = Routers.make 16 in
  let prefixes = Prefixes.make 16 in
  let addrs, acts = Addrs.make ~now ~iid ?addr 16 in
  let dsts = Dsts.make ~lmtu 0x100 in
  let queues = Ipaddr.V6.Map.empty in
  let t =
    { neighbors; routers; prefixes; addrs; dsts; queues; lmtu; iid; mac }
  in
  let t, pkts' =
    let fn (t, pkts) act =
      let t, pkts' = process t (Neighbors.Packet act) in
      (t, List.rev_append pkts' pkts)
    in
    List.fold_left fn (t, []) acts
  in
  let pkt = RS.encode_into ~mac (Addrs.select t.addrs) in
  (t, pkt :: pkts')

type error =
  [ `Bad_version
  | `Drop
  | `ICMP_error of int * int * int
  | `Invalid_ICMP_checksum
  | `Msg of string
  | `Parameter_problem
  | `Invalid_option
  | `Time_exceeded
  | `Truncated
  | `Unknown_ICMP_packet of int ]

let pp_error ppf = function
  | `Bad_version -> Fmt.string ppf "Bad version"
  | `Drop -> Fmt.string ppf "Drop"
  | `ICMP_error _ -> Fmt.pf ppf "ICMP error"
  | `Invalid_ICMP_checksum -> Fmt.string ppf "Invalid ICMP checksum"
  | `Msg msg -> Fmt.string ppf msg
  | `Parameter_problem -> Fmt.string ppf "Parameter problem"
  | `Invalid_option -> Fmt.string ppf "Invalid option"
  | `Time_exceeded -> Fmt.string ppf "Time exceeded"
  | `Truncated -> Fmt.string ppf "Truncated"
  | `Unknown_ICMP_packet n -> Fmt.pf ppf "Unknown ICMP packet (%d)" n

let decode t payload =
  let is_my_addr = Addrs.is_my_addr t.addrs in
  Parser.decode ~is_my_addr payload
