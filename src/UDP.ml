let src = Logs.Src.create "mnet.udpv4"

module Log = (val Logs.src_log src : Logs.LOG)
module SBstr = Slice_bstr

module Packet = struct
  type t = { src_port: int; dst_port: int; length: int }

  let guard err fn = if fn () then Ok () else Error err

  let decode slice =
    let ( let* ) = Result.bind in
    let* () = guard `Invalid_UDP_packet @@ fun () -> SBstr.length slice >= 8 in
    let len0 = SBstr.get_uint16_be slice 4 in
    let len1 = len0 - 8 in
    let* () =
      guard `Invalid_UDP_packet @@ fun () ->
      len0 >= 8 && len1 <= SBstr.length slice - 8
    in
    let src_port = SBstr.get_uint16_be slice 0 in
    let dst_port = SBstr.get_uint16_be slice 2 in
    let payload = SBstr.sub slice ~off:8 ~len:len1 in
    Ok ({ src_port; dst_port; length= len1 }, payload)

  let checksum src dst length =
    match (src, dst) with
    | Ipaddr.V4 src, Ipaddr.V4 dst ->
        let pseudo_header = Bytes.make 12 '\000' in
        Bytes.set_int32_be pseudo_header 0 (Ipaddr.V4.to_int32 src);
        Bytes.set_int32_be pseudo_header 4 (Ipaddr.V4.to_int32 dst);
        Bytes.set_uint8 pseudo_header 9 17;
        Bytes.set_uint16_be pseudo_header 10 (length + 8);
        Bytes.unsafe_to_string pseudo_header
    | Ipaddr.V6 src, Ipaddr.V6 dst ->
        let pseudo_header = Bytes.make 40 '\000' in
        let src = Ipaddr.V6.to_octets src in
        let dst = Ipaddr.V6.to_octets dst in
        Bytes.blit_string src 0 pseudo_header 0 16;
        Bytes.blit_string dst 0 pseudo_header 16 16;
        Bytes.set_uint16_be pseudo_header 34 (length + 8);
        Bytes.set_uint8 pseudo_header 39 17;
        Bytes.unsafe_to_string pseudo_header
    | _ -> assert false

  let encode ~src ~dst { src_port; dst_port; length } ~off ~len payload =
    let buf = Bytes.make 8 '\000' in
    Bytes.set_uint16_be buf 0 src_port;
    Bytes.set_uint16_be buf 2 dst_port;
    Bytes.set_uint16_be buf 4 (length + 8);
    Bytes.set_uint16_be buf 6 0;
    let pseudo_header = checksum src dst length in
    let sum = 0 in
    let sum =
      Utcp.Checksum.feed_string sum ~off:0
        ~len:(String.length pseudo_header)
        pseudo_header
    in
    let str = Bytes.unsafe_to_string buf in
    let sum = Utcp.Checksum.feed_string sum ~off:0 ~len:8 str in
    let sum = Utcp.Checksum.feed_string sum ~off ~len payload in
    let chk = Utcp.Checksum.finally sum in
    Bytes.set_uint16_be buf 6 chk;
    Bytes.unsafe_to_string buf

  let encode_into ~src ~dst { src_port; dst_port; length } bstr =
    Bstr.set_uint16_be bstr 0 src_port;
    Bstr.set_uint16_be bstr 2 dst_port;
    Bstr.set_uint16_be bstr 4 (length + 8);
    Bstr.set_uint16_be bstr 6 0;
    let pseudo_header = checksum src dst length in
    let sum = 0 in
    let sum =
      Utcp.Checksum.feed_string sum ~off:0
        ~len:(String.length pseudo_header)
        pseudo_header
    in
    let cs = Cstruct.of_bigarray ~off:0 ~len:8 bstr in
    Utcp.Checksum.feed_cstruct sum cs

  let sum bstr sum ~len =
    let cs = Cstruct.of_bigarray ~off:8 ~len bstr in
    let sum = Utcp.Checksum.feed_cstruct sum cs in
    let chk = Utcp.Checksum.finally sum in
    Bstr.set_uint16_be bstr 6 chk
end

type out = { length: int; peer: Ipaddr.t; port: int }

type waiter = {
    buf: bytes
  ; dst_off: int
  ; len: int
  ; src: Ipaddr.t option
  ; waiter: out Miou.Computation.t
}

module Pending = struct
  type packet = Ipaddr.t * int * string
  type t = { queue: packet Queue.t; mutable weight: int; capacity: int }

  let create capacity =
    let queue = Queue.create () and weight = 0 in
    { queue; weight; capacity }

  let add ~dst_port ((_, _, str) as packet) t =
    if String.length str > 0 then begin
      while t.weight + String.length str > t.capacity do
        let ipaddr, src_port, str = Queue.pop t.queue in
        t.weight <- t.weight - String.length str;
        Log.warn (fun m ->
            m "Too may pending datagrams on port %d, drop one from %a:%d"
              dst_port Ipaddr.pp ipaddr src_port)
      done;
      Queue.push packet t.queue;
      t.weight <- t.weight + String.length str
    end

  let is_empty t = Queue.is_empty t.queue

  let pop t =
    let ((_, _, str) as packet) = Queue.pop t.queue in
    t.weight <- t.weight - String.length str;
    packet
end

type bound = {
    mutable any: Pending.t option
  ; mutable peers: (Ipaddr.t * Pending.t) list
}

type state = {
    readers: (int, waiter list) Hashtbl.t
  ; pending: (int, bound) Hashtbl.t
  ; ipv4: IPv4.t
  ; ipv6: IPv6.t
}

type error =
  [ `Route_not_found | `Destination_unreachable of int | `Packet_too_big ]

let pp_error ppf = function
  | `Route_not_found -> Fmt.string ppf "Route not found"
  | `Destination_unreachable _ -> Fmt.string ppf "Destination unreachable"
  | `Packet_too_big -> Fmt.string ppf "Packet too big"

let create ipv4 ipv6 =
  { readers= Hashtbl.create 0x7ff; pending= Hashtbl.create 0x7ff; ipv4; ipv6 }

let bind ?(capacity = 0x10000) ?src state ~port =
  let value =
    match Hashtbl.find_opt state.pending port with
    | Some value -> value
    | None ->
        let value = { any= None; peers= [] } in
        Hashtbl.add state.pending port value;
        value
  in
  match src with
  | None when Option.is_none value.any ->
      value.any <- Some (Pending.create capacity)
  | None -> ()
  | Some src ->
      let fn (src', _) = Ipaddr.compare src src' = 0 in
      if not (List.exists fn value.peers) then
        value.peers <- (src, Pending.create capacity) :: value.peers

let unbind ?src state ~port =
  match Hashtbl.find_opt state.pending port with
  | None -> ()
  | Some value ->
      begin match src with
      | None -> value.any <- None
      | Some src ->
          let fn (src', _) = Ipaddr.compare src src' <> 0 in
          value.peers <- List.filter fn value.peers
      end;
      if Option.is_none value.any && value.peers = [] then
        Hashtbl.remove state.pending port

let matches peer waiter =
  match waiter.src with
  | Some src -> Ipaddr.compare src peer = 0
  | None -> false

let deliver ~peer ~src_port payload { buf; dst_off; len; waiter; _ } =
  let length = Int.min len (SBstr.length payload) in
  SBstr.blit_to_bytes payload ~src_off:0 buf ~dst_off ~len:length;
  let out = { length; peer; port= src_port } in
  Log.debug (fun m ->
      m "<- %d byte(s) from %a:%d" length Ipaddr.pp peer src_port);
  ignore (Miou.Computation.try_return waiter out)

(* NOTE(dinosaure): find pending entries for a specific port and refine with
   a specific peer (if [Option.is_some src]) or for any peers (if
   [Option.is_none src]). *)
let find state ~port src =
  match Hashtbl.find_opt state.pending port with
  | None -> None
  | Some value ->
      begin match src with
      | None -> value.any
      | Some src ->
          let fn (src', _) = Ipaddr.compare src src' = 0 in
          List.find_opt fn value.peers |> Option.map snd
      end

let fill state ~peer ~pkt payload =
  let port = pkt.Packet.dst_port in
  let queue_for_peer = find state ~port (Some peer) in
  let waiters =
    Option.value ~default:[] (Hashtbl.find_opt state.readers port)
  in
  let specific, rem = List.partition (matches peer) waiters in
  let chosen, rem =
    match (specific, queue_for_peer) with
    | _ :: _, _ -> (specific, rem)
    | [], Some _ -> ([], rem)
    | [], None -> List.partition (fun waiter -> Option.is_none waiter.src) rem
  in
  (* NOTE(dinosaure): [fill] must be **uninterruptible** until we
     [Hashtbl.{replace,remove}] in the sense that this function
     should not be resumed and re-scheduled later by Miou before to set our
     global [Hashtbl]. We must [deliver] packets only after such update. *)
  begin match rem with
  | [] -> Hashtbl.remove state.readers port
  | rem -> Hashtbl.replace state.readers port rem
  end;
  match chosen with
  | _ :: _ ->
      List.iter (deliver ~peer ~src_port:pkt.Packet.src_port payload) chosen
  | [] ->
      (* NOTE(dinosaure): nobody did a [recvfrom], let's fill a pending entry
         (for a specific peer [Some peer] or for any [None]) only if it exists
         (otherwise, we ignore it). *)
      let target =
        match queue_for_peer with
        | Some _ -> queue_for_peer
        | None -> find state ~port None
      in
      let fn pending =
        let src_port = pkt.Packet.src_port and str = SBstr.to_string payload in
        Pending.add ~dst_port:port (peer, src_port, str) pending
      in
      Option.iter fn target

let handler_ipv4 state (pkt, payload) =
  let peer = Ipaddr.V4 pkt.IPv4.src in
  let slice =
    match payload with
    | IPv4.String str ->
        (* TODO(dinosaure): we probably can avoid a copy here... *)
        let bstr = Bstr.of_string str in
        SBstr.make bstr
    | IPv4.Slice slice -> slice
  in
  match Packet.decode slice with
  | Ok (pkt, payload) -> fill state ~peer ~pkt payload
  | Error _ -> Log.err (fun m -> m "Invalid UDP packet, ignore it")

let handler_ipv6 state src _dst (payload : Bstr.t) =
  let peer = Ipaddr.V6 src in
  let slice = SBstr.make payload in
  match Packet.decode slice with
  | Ok (pkt, payload) -> fill state ~peer ~pkt payload
  | Error _ -> Log.err (fun m -> m "Invalid UDP packet, ignore it")

let recvfrom state ?src ~port ?(off = 0) ?len ?trigger buf =
  let len = match len with Some len -> len | None -> Bytes.length buf - off in
  if off < 0 || len < 0 || off > Bytes.length buf - len then
    invalid_arg "UDP.recvfrom: out of bounds";
  match find state ~port src with
  | Some pending when not (Pending.is_empty pending) ->
      let peer, src_port, data = Pending.pop pending in
      let length = Int.min len (String.length data) in
      Bytes.blit_string data 0 buf off length;
      (length, (peer, src_port))
  | _ ->
      let waiter = Miou.Computation.create () in
      let attach t = ignore (Miou.Computation.try_attach waiter t) in
      Option.iter attach trigger;
      let waiter = { buf; dst_off= off; len; src; waiter } in
      (* NOTE(dinosaure): [finally] is required if we would like to cancel the
         task which perform this function. In that case, we must clean-up our
         internal [state.readers] to be sure that we don't have a memory-leak. *)
      let finally () =
        let waiters = Hashtbl.find_opt state.readers port in
        let waiters = Option.value ~default:[] waiters in
        match List.filter (( != ) waiter) waiters with
        | [] -> Hashtbl.remove state.readers port
        | waiters -> Hashtbl.replace state.readers port waiters
      in
      let waiters = Hashtbl.find_opt state.readers port in
      let waiters = Option.value ~default:[] waiters in
      Hashtbl.replace state.readers port (waiter :: waiters);
      Fun.protect ~finally @@ fun () ->
      let out = Miou.Computation.await_exn waiter.waiter in
      (out.length, (out.peer, out.port))

let sendto state ~dst ?src_port ~port:dst_port ?(off = 0) ?len payload =
  let len =
    match len with Some len -> len | None -> String.length payload - off
  in
  if off < 0 || len < 0 || off > String.length payload - len then
    invalid_arg "UDP.sendto: out of bounds";
  let src_port : int =
    match src_port with
    | Some src_port -> src_port
    | None -> String.get_uint16_ne (Mirage_crypto_rng.generate 2) 0
  in
  let pkt = { Packet.src_port; dst_port; length= len } in
  match dst with
  | Ipaddr.V4 dst ->
      let src = IPv4.src state.ipv4 ~dst in
      let src = Ipaddr.V4 src and dstv6 = Ipaddr.V4 dst in
      let str = Packet.encode ~src ~dst:dstv6 pkt ~off ~len payload in
      let writer = IPv4.Writer.of_strings state.ipv4 [ str; payload ] in
      IPv4.write state.ipv4 dst ~protocol:17 writer
  | Ipaddr.V6 dst ->
      let src = IPv6.src state.ipv6 ~dst in
      let srcv6 = Ipaddr.V6 src and dstv6 = Ipaddr.V6 dst in
      let str = Packet.encode ~src:srcv6 ~dst:dstv6 pkt ~off ~len payload in
      let hdr_len = String.length str in
      let total_len = hdr_len + len in
      let fn bstr =
        Bstr.blit_from_string str ~src_off:0 bstr ~dst_off:0 ~len:hdr_len;
        Bstr.blit_from_string payload ~src_off:off bstr ~dst_off:hdr_len ~len
      in
      IPv6.write_directly state.ipv6 ~src dst ~protocol:17 ~len:total_len fn

let sendfn state ~dst ?src_port ~port:dst_port ~len fn =
  let src_port : int =
    match src_port with
    | Some src_port -> src_port
    | None -> String.get_uint16_ne (Mirage_crypto_rng.generate 2) 0
  in
  match dst with
  | Ipaddr.V4 dst ->
      let src = IPv4.src state.ipv4 ~dst in
      let pkt = { Packet.src_port; dst_port; length= len } in
      let srcv4 = Ipaddr.V4 src and dstv4 = Ipaddr.V4 dst in
      let fn bstr =
        let sum = Packet.encode_into ~src:srcv4 ~dst:dstv4 pkt bstr in
        fn (SBstr.make ~off:8 ~len bstr);
        Packet.sum bstr sum ~len
      in
      let writer = IPv4.Writer.into state.ipv4 ~len:(8 + len) fn in
      IPv4.write state.ipv4 dst ~protocol:17 writer
  | Ipaddr.V6 dst ->
      let src = IPv6.src state.ipv6 ~dst in
      let pkt = { Packet.src_port; dst_port; length= len } in
      let srcv6 = Ipaddr.V6 src and dstv6 = Ipaddr.V6 dst in
      let fn' bstr =
        let sum = Packet.encode_into ~src:srcv6 ~dst:dstv6 pkt bstr in
        fn (SBstr.make ~off:8 ~len bstr);
        Packet.sum bstr sum ~len
      in
      IPv6.write_directly state.ipv6 ~src dst ~protocol:17 ~len:(8 + len) fn'
