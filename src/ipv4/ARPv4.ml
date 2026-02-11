let src = Logs.Src.create "mnet.arp"
let[@inline always] now () = Mkernel.clock_monotonic ()

module Log = (val Logs.src_log src : Logs.LOG)
module Ethernet = Ethernet

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

module Packet = struct
  type t = {
      operation: operation
    ; src_mac: Macaddr.t
    ; dst_mac: Macaddr.t
    ; src_ip: Ipaddr.V4.t
    ; dst_ip: Ipaddr.V4.t
  }

  and operation = Request | Reply

  let operation_of_int = function
    | 1 -> Ok Request
    | 2 -> Ok Reply
    | n -> error_msgf "Invalid ARPv4 operation (%02x)" n

  let operation_to_int = function Request -> 1 | Reply -> 2
  let guard err fn = if fn () then Ok () else Error err

  let decode ?(off = 0) str =
    let ( let* ) = Result.bind in
    let* () =
      guard `Invalid_ARPv4_packet @@ fun () -> String.length str - off >= 28
    in
    let operation = String.get_uint16_be str (off + 6) in
    let* operation = operation_of_int operation in
    let src_mac = Macaddr.of_octets_exn (String.sub str (off + 8) 6) in
    let src_ip = Ipaddr.V4.of_int32 (String.get_int32_be str (off + 14)) in
    let dst_mac = Macaddr.of_octets_exn (String.sub str (off + 18) 6) in
    let dst_ip = Ipaddr.V4.of_int32 (String.get_int32_be str (off + 24)) in
    Ok { operation; src_mac; dst_mac; src_ip; dst_ip }

  let unsafe_encode_into t ?(off = 0) bstr =
    Bstr.set_uint16_be bstr (off + 0) 1;
    Bstr.set_uint16_be bstr (off + 2) 0x0800;
    Bstr.set_uint8 bstr (off + 4) 6;
    Bstr.set_uint8 bstr (off + 5) 4;
    Bstr.set_uint16_be bstr (off + 6) (operation_to_int t.operation);
    let src_mac = Macaddr.to_octets t.src_mac in
    Bstr.blit_from_string src_mac ~src_off:0 bstr ~dst_off:(off + 8) ~len:6;
    Bstr.set_int32_be bstr (off + 14) (Ipaddr.V4.to_int32 t.src_ip);
    let dst_mac = Macaddr.to_octets t.dst_mac in
    Bstr.blit_from_string dst_mac ~src_off:0 bstr ~dst_off:(off + 18) ~len:6;
    Bstr.set_int32_be bstr (off + 24) (Ipaddr.V4.to_int32 t.dst_ip);
    28
end

let mac0 = Macaddr.of_octets_exn (String.make 6 '\000')

module Entry = struct
  type ivar = Macaddr.t Miou.Computation.t

  type t =
    | Static of Macaddr.t
    | Dynamic of { addr: Macaddr.t; epoch: int }
    | Pending of { ivar: ivar; retry: int }

  let is_disposable = function Dynamic _ -> true | _ -> false
end

module Key = struct
  include Ipaddr.V4

  let equal a b = Ipaddr.V4.compare a b = 0
  let hash = Hashtbl.hash
end

module Entries = Table.Make (Key) (Entry)

type t = {
    entries: Entries.t
  ; macaddr: Macaddr.t
  ; ipaddr: Ipaddr.V4.t
  ; timeout: int
  ; retries: int
  ; mutable epoch: int
  ; eth: Ethernet.t
  ; mutex: Miou.Mutex.t
  ; condition: Miou.Condition.t
  ; queue: string Ethernet.packet Queue.t
}

let alias t ipaddr =
  begin match Entries.find t.entries ipaddr with
  | exception Not_found -> ()
  | Pending { ivar; _ } -> ignore (Miou.Computation.try_return ivar t.macaddr)
  | _ -> ()
  end;
  Entries.add t.entries ipaddr (Static t.macaddr);
  let operation = Packet.Request in
  let src_mac = t.macaddr in
  let dst_mac = mac0 in
  let src_ip = ipaddr in
  let dst_ip = ipaddr in
  let pkt = { Packet.operation; src_mac; dst_mac; src_ip; dst_ip } in
  (pkt, Macaddr.broadcast)

let write t (arp, dst) =
  (* NOTE(dinosaure): we already check, in [create] that the MTU is more than
     [28] bytes. The buffer given by [Ethernet] is also more than [28] bytes. *)
  let fn = Packet.unsafe_encode_into arp ~off:0 in
  Ethernet.write_directly_into ~len:28 t.eth ~dst ~protocol:Ethernet.ARPv4 fn

let guard err fn = if fn () then Ok () else Error err
let macaddr t = t.macaddr

let request t dst_ip =
  let operation = Packet.Request in
  let src_mac = t.macaddr in
  let dst_mac = Macaddr.broadcast in
  let src_ip = t.ipaddr in
  ({ Packet.operation; src_mac; dst_mac; src_ip; dst_ip }, dst_mac)

let reply arp macaddr =
  let operation = Packet.Reply in
  let src_mac = macaddr in
  let dst_mac = arp.Packet.src_mac in
  let src_ip = arp.Packet.dst_ip in
  let dst_ip = arp.Packet.src_ip in
  let pkt = { Packet.operation; src_mac; dst_mac; src_ip; dst_ip } in
  (pkt, arp.Packet.src_mac)

exception Timeout
exception Clear

let empty_bt = Printexc.get_callstack 0
let timeout = (Timeout, empty_bt)
let timeout c = ignore (Miou.Computation.try_cancel c timeout)
let clear = (Clear, empty_bt)
let clear c = ignore (Miou.Computation.try_cancel c clear)

let tick t =
  let epoch = t.epoch in
  let fn k v (pkts, to_remove, timeouts) =
    match v with
    | Entry.Dynamic { epoch= epoch'; _ } when epoch' <= epoch ->
        (pkts, k :: to_remove, timeouts)
    | Dynamic { epoch= epoch'; _ } when epoch' <= epoch + 1 ->
        (request t k :: pkts, to_remove, timeouts)
    | Pending { ivar; retry } ->
        if retry <= t.epoch then (pkts, k :: to_remove, ivar :: timeouts)
        else (request t k :: pkts, to_remove, timeouts)
    | _ -> (pkts, to_remove, timeouts)
  in
  let outs, to_remove, timeouts = Entries.fold fn t.entries ([], [], []) in
  List.iter (Entries.remove t.entries) to_remove;
  List.iter (write t) outs;
  List.iter timeout timeouts;
  t.epoch <- t.epoch + 1

let handle_request t arp =
  let dst = arp.Packet.dst_ip in
  let src = arp.Packet.src_ip in
  let src_mac = arp.Packet.src_mac in
  Log.debug (fun m ->
      let tags = Ethernet.tags t.eth in
      m ~tags "%a:%a: who has %a?" Macaddr.pp src_mac Ipaddr.V4.pp src
        Ipaddr.V4.pp dst);
  match Entries.find t.entries dst with
  | exception Not_found -> ()
  | Static macaddr -> write t (reply arp macaddr)
  | _ -> ()

let handle_reply t src macaddr =
  let entry = Entry.Dynamic { addr= macaddr; epoch= t.epoch + t.timeout } in
  Log.debug (fun m ->
      let tags = Ethernet.tags t.eth in
      m ~tags "handle ARPv4 reply packet from %a:%a" Macaddr.pp macaddr
        Ipaddr.V4.pp src);
  match Entries.find t.entries src with
  | exception Not_found -> ()
  | Static _ ->
      if Macaddr.compare macaddr mac0 == 0 then
        Log.debug (fun m ->
            let tags = Ethernet.tags t.eth in
            m ~tags "ignoring gratuitious ARP from %a using %a" Macaddr.pp
              macaddr Ipaddr.V4.pp src)
  | Dynamic { addr= macaddr'; _ } ->
      if Macaddr.compare macaddr macaddr' != 0 then
        Log.debug (fun m ->
            let tags = Ethernet.tags t.eth in
            m ~tags "set %a from %a to %a" Ipaddr.V4.pp src Macaddr.pp macaddr'
              Macaddr.pp macaddr);
      Entries.add t.entries src entry
  | Pending { ivar; _ } ->
      Log.debug (fun m -> m "%a is-at %a" Ipaddr.V4.pp src Macaddr.pp macaddr);
      ignore (Miou.Computation.try_return ivar macaddr);
      Entries.add t.entries src entry

let input t pkt =
  match Packet.decode pkt.Ethernet.payload with
  | Error _ ->
      let tags = Ethernet.tags t.eth in
      Log.err (fun m -> m ~tags "Invalid ARPv4 packet:");
      Log.err (fun m ->
          m ~tags "@[<hov>%a@]" (Hxd_string.pp Hxd.default) pkt.Ethernet.payload)
  | Ok arp ->
      if
        Ipaddr.V4.compare arp.Packet.src_ip arp.Packet.dst_ip == 0
        || arp.Packet.operation == Packet.Reply
      then
        let mac = arp.Packet.src_mac and src = arp.Packet.src_ip in
        handle_reply t src mac
      else handle_request t arp

let to_error (exn, _bt) =
  match exn with Timeout -> `Timeout | Clear -> `Clear | exn -> `Exn exn

type error = [ `Timeout | `Clear | `Exn of exn ]

let pp_error ppf = function
  | `Timeout -> Fmt.string ppf "Timeout"
  | `Clear -> Fmt.string ppf "ARP table reset"
  | `Exn exn -> Fmt.pf ppf "Unexpected exception: %s" (Printexc.to_string exn)

let query t ipaddr =
  match Entries.find t.entries ipaddr with
  | exception Not_found ->
      let ivar = Miou.Computation.create () in
      let retry = t.epoch + t.retries in
      let pending = Entry.Pending { ivar; retry } in
      Entries.add t.entries ipaddr pending;
      write t (request t ipaddr);
      Miou.Computation.await ivar |> Result.map_error to_error
  | Pending { ivar; _ } ->
      Miou.Computation.await ivar |> Result.map_error to_error
  | Static addr | Dynamic { addr; _ } -> Ok addr

let ask t ipaddr =
  match Entries.find t.entries ipaddr with
  | exception Not_found -> None
  | Pending _ -> None
  | Static addr | Dynamic { addr; _ } -> Some addr

let ips t =
  let fn k v acc = match v with Entry.Static _ -> k :: acc | _ -> acc in
  Entries.fold fn t.entries []

let add_ip t ipaddr =
  match ips t with
  | [] ->
      let fn _ = function Entry.Pending { ivar; _ } -> clear ivar | _ -> () in
      Entries.iter fn t.entries;
      Entries.reset t.entries;
      (* TODO(dinosaure): reset the dynamic cache *)
      write t (alias t ipaddr)
  | _ -> write t (alias t ipaddr)

let set_ips t = function
  | [] ->
      let fn _ = function Entry.Pending { ivar; _ } -> clear ivar | _ -> () in
      Entries.iter fn t.entries;
      Entries.reset t.entries (* TODO(dinosaure): reset the dynamic cache. *)
  | ipaddr :: rest ->
      Entries.iter
        (fun _ -> function Pending { ivar; _ } -> clear ivar | _ -> ())
        t.entries;
      Entries.reset t.entries;
      (* TODO(dinosaure): reset the dynamic cache. *)
      write t (alias t ipaddr);
      List.iter (add_ip t) rest

type daemon = unit Miou.t
type event = In of string Ethernet.packet Queue.t | Tick

let read_or_sync ?(delay = 1_500_000_000) t =
  let prm1 =
    Miou.async @@ fun () ->
    Miou.Mutex.protect t.mutex @@ fun () ->
    if Queue.is_empty t.queue then Miou.Condition.wait t.condition t.mutex;
    let todo = Queue.create () in
    Queue.transfer t.queue todo;
    In todo
  in
  let prm0 = Miou.async @@ fun () -> Mkernel.sleep delay; Tick in
  match Miou.await_first [ prm0; prm1 ] with
  | Ok value -> value
  | Error exn ->
      Log.err (fun m ->
          let tags = Ethernet.tags t.eth in
          m ~tags "Unexpected exception: %s" (Printexc.to_string exn));
      In (Queue.create ())

let arp ?(delay = 1_500_000_000) t =
  Log.debug (fun m -> m "tick");
  let rec go rem =
    let t0 = now () in
    match read_or_sync ~delay:rem t with
    | In queue ->
        let fn = input t in
        Queue.iter fn queue;
        let t1 = now () in
        let rem = rem - (t1 - t0) in
        let rem = if rem <= 0 then delay else rem in
        go rem
    | Tick -> tick t; go delay
  in
  go delay

let create ?(delay = 1_500_000_000) ?(timeout = 800) ?(retries = 5) ?ipaddr eth
    =
  let ( let* ) = Result.bind in
  let macaddr = Ethernet.macaddr eth in
  (* enough for ARP packets *)
  let* () = guard `MTU_too_small @@ fun () -> Ethernet.mtu eth >= 28 in
  if timeout <= 0 then Fmt.invalid_arg "Arp.create: null or negative timeout";
  if retries < 0 then Fmt.invalid_arg "Arg.create: negative retries value";
  let unknown = Option.is_none ipaddr in
  let ipaddr = Option.value ~default:Ipaddr.V4.any ipaddr in
  let t =
    {
      entries= Entries.create 0x10
    ; macaddr
    ; ipaddr
    ; timeout
    ; retries
    ; epoch= 0
    ; eth
    ; mutex= Miou.Mutex.create ()
    ; condition= Miou.Condition.create ()
    ; queue= Queue.create ()
    }
  in
  if unknown == false then write t (alias t ipaddr);
  let prm = Miou.async (fun () -> arp ~delay t) in
  Ok (prm, t)

let transfer t pkt =
  let payload = Slice_bstr.sub_string pkt.Ethernet.payload ~off:0 ~len:28 in
  let pkt = { pkt with Ethernet.payload } in
  Miou.Mutex.protect t.mutex @@ fun () ->
  Queue.push pkt t.queue;
  Miou.Condition.signal t.condition

let kill = Miou.cancel
