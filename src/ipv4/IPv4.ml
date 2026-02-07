let src = Logs.Src.create "mnet.ipv4"
let guard err fn = if fn () then Ok () else Error err

module Log = (val Logs.src_log src : Logs.LOG)
module SBstr = Slice_bstr

module Flag = struct
  type t = DF | MF

  let _dfmf = [ DF; MF ]
  let _df = [ DF ]
  let _mf = [ MF ]
  let _none = []

  let of_int cmd =
    match cmd land 0b11 with
    | 0b11 -> _dfmf
    | 0b10 -> _df
    | 0b01 -> _mf
    | _ -> _none

  let to_int flags =
    let cmd = ref 0 in
    let fn = function
      | DF -> cmd := !cmd lor 0b10
      | MF -> cmd := !cmd lor 0b01
    in
    List.iter fn flags; !cmd
end

module Packet = struct
  type partial = Partial
  type complete = { checksum: int; length: int }
  type error = [ `Invalid_IPv4_packet | `Invalid_checksum ]

  type 'a packet = {
      src: Ipaddr.V4.t
    ; dst: Ipaddr.V4.t
    ; uid: int
    ; flags: Flag.t list
    ; off: int
    ; ttl: int
    ; protocol: int
    ; checksum_and_length: 'a
    ; opt: Slice_bstr.t
  }

  let pp_error ppf = function
    | `Invalid_IPv4_packet -> Fmt.string ppf "bad packet"
    | `Invalid_checksum -> Fmt.string ppf "bad checksum"
    | `Msg msg -> Fmt.string ppf msg

  let decode slice =
    let ( let* ) = Result.bind in
    let version_and_ihl = SBstr.get_uint8 slice 0 in
    let ihl = version_and_ihl land 0b1111 in
    let* () =
      guard `Invalid_IPv4_packet @@ fun () -> SBstr.length slice >= 20
    in
    let length = SBstr.get_uint16_be slice 2 in
    let uid = SBstr.get_uint16_be slice 4 in
    let flags_and_off = SBstr.get_uint16_be slice 6 in
    let flags = Flag.of_int (flags_and_off lsr 13) in
    let off = flags_and_off land 0x1fff in
    let ttl = SBstr.get_uint8 slice 8 in
    let protocol = SBstr.get_uint8 slice 9 in
    let checksum = SBstr.get_uint16_be slice 10 in
    let chk =
      let { Slice.buf; off; _ } = slice in
      Bstr.set_uint16_be buf (off + 10) 0;
      Utcp.Checksum.digest ~off ~len:(ihl * 4) buf
    in
    let* () = guard `Invalid_checksum @@ fun () -> checksum == chk in
    let src = Ipaddr.V4.of_int32 (SBstr.get_int32_be slice 12) in
    let dst = Ipaddr.V4.of_int32 (SBstr.get_int32_be slice 16) in
    let opt =
      if ihl == 5 then SBstr.empty
      else SBstr.sub slice ~off:20 ~len:((ihl * 4) - 20)
    in
    let checksum_and_length = { checksum; length } in
    let pkt =
      { src; dst; uid; flags; off; ttl; protocol; checksum_and_length; opt }
    in
    let payload = SBstr.shift slice (20 + SBstr.length opt) in
    Ok (pkt, payload)

  let flags_and_off_to_int t =
    let flags = Flag.to_int t.flags in
    (flags lsl 13) lor t.off

  let unsafe_encode_into t ?(off = 0) bstr =
    let version_and_ihl = (4 lsl 4) lor 5 in
    Bstr.set_uint8 bstr (off + 0) version_and_ihl;
    Bstr.set_uint8 bstr (off + 1) 0;
    Bstr.set_uint16_be bstr (off + 2) 0;
    Bstr.set_uint16_be bstr (off + 4) t.uid;
    Bstr.set_uint16_be bstr (off + 6) (flags_and_off_to_int t);
    Bstr.set_uint8 bstr (off + 8) t.ttl;
    Bstr.set_uint8 bstr (off + 9) t.protocol;
    Bstr.set_uint16_be bstr (off + 10) 0;
    Bstr.set_int32_be bstr (off + 12) (Ipaddr.V4.to_int32 t.src);
    Bstr.set_int32_be bstr (off + 16) (Ipaddr.V4.to_int32 t.dst)
end

module Key = struct
  type t = { src: Ipaddr.V4.t; dst: Ipaddr.V4.t; protocol: int; uid: int }

  let equal a b =
    Ipaddr.V4.compare a.src b.src == 0
    && Ipaddr.V4.compare a.dst b.dst == 0
    && a.protocol == b.protocol
    && a.uid == b.uid

  let hash = Hashtbl.hash
end

module Fragments = Fragments.Make (Key)

type packet = Key.t = {
    src: Ipaddr.V4.t
  ; dst: Ipaddr.V4.t
  ; protocol: int
  ; uid: int
}

and payload = Fragments.payload = Slice of SBstr.t | String of string

type t = {
    eth: Ethernet.t
  ; arp: ARPv4.t
  ; cidr: Ipaddr.V4.Prefix.t
  ; gateway: Ipaddr.V4.t option
  ; cache: Fragments.t
  ; mutable handler: packet * payload -> unit
  ; tags: Logs.Tag.set
  ; cnt: int Atomic.t
}

let tags { tags; _ } = tags

module Writer = struct
  type ipv4 = t

  type t =
    | Fixed of { total_length: int; fn: Bstr.t -> unit }
      (* invariant: [total_length <= mtu - 20] *)
    | Fragmented of { total_length: int; fn: (Bstr.t -> unit) Seq.t }
  (* invariant: [bstr] is filled to [(mtu - 20) land (lnot 0b111)]
         until the last element (which contains remaining unaligned bytes. *)

  let of_string t str =
    let mtu = Ethernet.mtu t.eth in
    let total_length = String.length str in
    if 20 + total_length <= mtu then
      let len = total_length in
      let fn = Bstr.blit_from_string str ~src_off:0 ~dst_off:0 ~len in
      Fixed { total_length; fn }
    else
      let fragment = (mtu - 20) land lnot 0b111 in
      let rec go src_off () =
        if src_off == total_length then Seq.Nil
        else
          let len = Int.min (total_length - src_off) fragment in
          let fn = Bstr.blit_from_string str ~src_off ~dst_off:0 ~len in
          Seq.Cons (fn, go (src_off + len))
      in
      Fragmented { total_length; fn= go 0 }

  (* TODO(dinosaure): it should be possible to make a Seq.t version of this
     function to be able to fragment correctly a /stream/. *)
  let chunk chunk_size ?(str_off = 0) sstr =
    let rec go acc str_off chunk_size sstr =
      if chunk_size == 0 then (List.rev acc, str_off, sstr)
      else
        match sstr with
        | [] -> (List.rev acc, str_off, sstr)
        | str :: sstr as lst ->
            let len = Int.min chunk_size (String.length str - str_off) in
            let acc = (str, str_off, len) :: acc in
            if str_off + len == String.length str then
              go acc 0 (chunk_size - len) sstr
            else go acc (str_off + len) (chunk_size - len) lst
    in
    go [] str_off chunk_size sstr

  let of_strings t sstr =
    let mtu = Ethernet.mtu t.eth in
    let total_length =
      let fn acc str = acc + String.length str in
      List.fold_left fn 0 sstr
    in
    if 20 + total_length <= mtu then
      let bufs = Array.of_list sstr in
      let fn bstr =
        let dst_off = ref 0 in
        for i = 0 to Array.length bufs - 1 do
          let str = Array.unsafe_get bufs i in
          let len = String.length str in
          Bstr.blit_from_string str ~src_off:0 bstr ~dst_off:!dst_off ~len;
          dst_off := !dst_off + len
        done
      in
      Fixed { total_length; fn }
    else
      let fragment = (mtu - 20) land lnot 0b111 in
      let rec go (str_off, sstr) () =
        match sstr with
        | [] -> Seq.Nil
        | sstr ->
            let chunk, str_off, sstr = chunk fragment ~str_off sstr in
            let chunk = Array.of_list chunk in
            let fn bstr =
              let dst_off = ref 0 in
              for i = 0 to Array.length chunk - 1 do
                let str, src_off, len = Array.unsafe_get chunk i in
                Bstr.blit_from_string str ~src_off bstr ~dst_off:!dst_off ~len;
                dst_off := !dst_off + len
              done
            in
            Seq.Cons (fn, go (str_off, sstr))
      in
      let fn = go (0, sstr) in
      Fragmented { total_length; fn }

  let into t ~len:total_length fn =
    if 20 + total_length > Ethernet.mtu t.eth then
      invalid_arg "IPv4.Writer.into: too huge IPv4 packet";
    Fixed { total_length; fn }
end

let create ?to_expire eth arp ?gateway ?(handler = ignore) cidr =
  let tags = Ethernet.tags eth in
  let tags = Logs.Tag.add Tags.ipv4 cidr tags in
  let cache = Fragments.create ?to_expire () in
  let cnt = Atomic.make 0 in
  let t = { eth; arp; cidr; gateway; cache; handler; tags; cnt } in
  let ( let* ) = Result.bind in
  let* () = guard `MTU_too_small @@ fun () -> Ethernet.mtu eth >= 20 + 1 in
  Ok t

let max t =
  let mtu = Ethernet.mtu t.eth in
  mtu - 20

let src t ~dst:_ = Ipaddr.V4.Prefix.address t.cidr

let fixed pkt user's_fn len bstr =
  Packet.unsafe_encode_into pkt bstr;
  Bstr.set_uint16_be bstr 2 (20 + len);
  let rest = Bstr.sub bstr ~off:20 ~len in
  user's_fn rest;
  let chk = Utcp.Checksum.digest ~off:0 ~len:20 bstr in
  Bstr.set_uint16_be bstr 10 chk;
  20 + len

let write_directly t ?(ttl = 38) ?src (dst, macaddr) ~protocol p =
  Log.debug (fun m ->
      m ~tags:t.tags "%a is-at %a" Ipaddr.V4.pp dst Macaddr.pp macaddr);
  let src = Option.value ~default:(Ipaddr.V4.Prefix.address t.cidr) src in
  let mtu = Ethernet.mtu t.eth in
  match p with
  | Writer.Fixed { total_length; fn= user's_fn } ->
      let pkt =
        {
          Packet.src
        ; dst
        ; uid= 0
        ; flags= Flag._none
        ; off= 0
        ; ttl
        ; protocol
        ; checksum_and_length= Packet.Partial
        ; opt= SBstr.empty
        }
      in
      let protocol = Ethernet.IPv4 in
      let fn = fixed pkt user's_fn total_length in
      Ethernet.write_directly_into t.eth ~len:(20 + total_length) ~dst:macaddr
        ~protocol fn
  | Writer.Fragmented { total_length; fn } ->
      let uid = Mirage_crypto_rng.generate 2 in
      let uid = String.get_uint16_be uid 0 in
      let rec go off total_length = function
        | Seq.Nil -> ()
        | Seq.Cons (user's_fn, next) ->
            let next = next () in
            let size = Int.min total_length (mtu - 20) in
            let flags = if next != Seq.Nil then Flag._mf else Flag._none in
            let pkt =
              {
                Packet.src
              ; dst
              ; uid
              ; flags
              ; off= off lsr 3
              ; ttl
              ; protocol
              ; checksum_and_length= Packet.Partial
              ; opt= SBstr.empty
              }
            in
            let protocol = Ethernet.IPv4 in
            let fn = fixed pkt user's_fn size in
            Ethernet.write_directly_into t.eth ~len:(20 + size) ~dst:macaddr
              ~protocol fn;
            if next != Seq.Nil && total_length - size > 0 then
              go (off + size) (total_length - size) next
      in
      go 0 total_length (fn ())

let write t ?(ttl = 38) ?src dst ~protocol p =
  Log.debug (fun m -> m ~tags:t.tags "Asking where is %a" Ipaddr.V4.pp dst);
  match Routing.destination_macaddr t.cidr t.gateway t.arp dst with
  | Error (`Exn _ | `Timeout | `Clear) ->
      Log.err (fun m -> m ~tags:t.tags "no route found for %a" Ipaddr.V4.pp dst);
      Error `Route_not_found
  | Error `Gateway ->
      Log.debug (fun m ->
          m ~tags:t.tags "no gateway specified for writing IPv4 packets");
      Ok ()
  | Ok macaddr ->
      write_directly t ~ttl ?src (dst, macaddr) ~protocol p;
      Ok ()

let attempt_to_discover_destination t dst =
  Routing.destination_macaddr_without_interruption t.cidr t.gateway t.arp dst

let input t pkt =
  match Packet.decode pkt.Ethernet.payload with
  | Error err ->
      let str = SBstr.to_string pkt.payload in
      Log.err (fun m ->
          m ~tags:t.tags "Invalid IPv4 packet: %a" Packet.pp_error err);
      Log.err (fun m ->
          m ~tags:t.tags "@[<hov>%a@]" (Hxd_string.pp Hxd.default) str)
  | Ok (ipv4, payload) ->
      let dst = ipv4.Packet.dst in
      if
        SBstr.length payload > 0
        && (Ipaddr.V4.(compare dst (Prefix.address t.cidr)) == 0
           || Ipaddr.V4.(compare dst Ipaddr.V4.broadcast) == 0
           || Ipaddr.V4.(compare dst (Prefix.broadcast t.cidr)) == 0)
      then begin
        let now = Mkernel.clock_monotonic () in
        let key =
          let src = ipv4.Packet.src
          and dst = ipv4.Packet.dst
          and protocol = ipv4.Packet.protocol
          and uid = ipv4.Packet.uid in
          { Key.src; dst; protocol; uid }
        and off = ipv4.Packet.off * 8
        and len = ipv4.Packet.checksum_and_length.length - 20
        and last = not (List.exists (( = ) Flag.MF) ipv4.Packet.flags) in
        Log.debug (fun m ->
            m ~tags:t.tags
              "Incoming IPv4 packet %a -> %a (off:%d, len:%d, last:%b)"
              Ipaddr.V4.pp ipv4.Packet.src Ipaddr.V4.pp ipv4.Packet.dst off len
              last);
        let pkt = Fragments.insert ~now t.cache key ~off ~len ~last payload in
        Option.iter t.handler pkt
      end

let set_handler t handler =
  Atomic.incr t.cnt;
  t.handler <- handler;
  if Atomic.get t.cnt > 1 then
    Log.warn (fun m -> m ~tags:t.tags "IPv4 handler modified more than once")
