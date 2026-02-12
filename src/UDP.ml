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
  ; waiter: out Miou.Computation.t
}

type state = {
    readers: (int, waiter list) Hashtbl.t
  ; ipv4: IPv4.t
  ; ipv6: IPv6.t
}

type error =
  [ `Route_not_found | `Destination_unreachable of int | `Packet_too_big ]

let pp_error ppf = function
  | `Route_not_found -> Fmt.string ppf "Route not found"
  | `Destination_unreachable _ -> Fmt.string ppf "Destination unreachable"
  | `Packet_too_big -> Fmt.string ppf "Packet too big"

let create ipv4 ipv6 = { readers= Hashtbl.create 0x7ff; ipv4; ipv6 }

let fill state ~peer ~pkt payload =
  match Hashtbl.find state.readers pkt.Packet.dst_port with
  | exception Not_found -> ()
  | waiters ->
      let fn { buf; dst_off; len; waiter } =
        let length = Int.min len (SBstr.length payload) in
        let out = { length; peer; port= pkt.Packet.src_port } in
        Log.debug (fun m ->
            m "<- %d byte(s) from %a:%d" length Ipaddr.pp peer
              pkt.Packet.src_port);
        SBstr.blit_to_bytes payload ~src_off:0 buf ~dst_off ~len:length;
        assert (Miou.Computation.try_return waiter out)
      in
      List.iter fn waiters;
      Hashtbl.remove state.readers pkt.Packet.dst_port
(* TODO(dinosaure): we need to check that [Miou.Computation.try_return] does not
   re-schedule. If it's the case, it's safe to [Hashtbl.remove]. Otherwise, we must
   aggregate everything into a list, remove and apply our [fn] to the list.

   Deeply, [try_return] mostly fills the scheduler of tasks without interruption. *)

let handler_ipv4 state (pkt, payload) =
  let peer = Ipaddr.V4 pkt.IPv4.src in
  match payload with
  | IPv4.String _ -> assert false
  | IPv4.Slice slice -> begin
      match Packet.decode slice with
      | Ok (pkt, payload) -> fill state ~peer ~pkt payload
      | Error _ -> Log.err (fun m -> m "Invalid UDP packet, ignore it")
    end

let handler_ipv6 state src _dst (payload : Bstr.t) =
  let peer = Ipaddr.V6 src in
  let slice = SBstr.make payload in
  match Packet.decode slice with
  | Ok (pkt, payload) -> fill state ~peer ~pkt payload
  | Error _ -> Log.err (fun m -> m "Invalid UDP packet, ignore it")

let recvfrom state ?src:_ ~port ?(off = 0) ?len ?trigger buf =
  let len = match len with Some len -> len | None -> Bytes.length buf - off in
  if off < 0 || len < 0 || off > Bytes.length buf - len then
    invalid_arg "UDP.recvfrom: out of bounds";
  let waiter = Miou.Computation.create () in
  let attach t = ignore (Miou.Computation.try_attach waiter t) in
  Option.iter attach trigger;
  let waiter = { buf; dst_off= off; len; waiter } in
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
  match Hashtbl.find state.readers port with
  | exception Not_found ->
      Hashtbl.add state.readers port [ waiter ];
      Fun.protect ~finally @@ fun () ->
      let { length; peer; port } = Miou.Computation.await_exn waiter.waiter in
      (length, (peer, port))
  | waiters ->
      Hashtbl.replace state.readers port (waiter :: waiters);
      Fun.protect ~finally @@ fun () ->
      let { length; peer; port } = Miou.Computation.await_exn waiter.waiter in
      (length, (peer, port))

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
