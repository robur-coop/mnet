exception Net_unreach
exception Closed_by_peer
exception Connection_refused

module Buffer = struct
  type t = { mutable bstr: Bstr.t; mutable off: int; mutable len: int }

  let create size =
    let bstr = Bstr.create size in
    { bstr; off= 0; len= 0 }

  let available { bstr; off; len } = Bstr.length bstr - off - len
  let length { len; _ } = len

  let compress t =
    if t.len == 0 then begin
      t.off <- 0;
      t.len <- 0
    end
    else if t.off > 0 then begin
      Bstr.blit t.bstr ~src_off:t.off t.bstr ~dst_off:0 ~len:t.len;
      t.off <- 0
    end

  let get t ~fn =
    let n = fn t.bstr ~off:t.off ~len:t.len in
    t.off <- t.off + n;
    t.len <- t.len - n;
    if t.len == 0 then t.off <- 0;
    n

  let put t ~fn =
    compress t;
    let off = t.off + t.len in
    let bstr = t.bstr in
    if Bstr.length bstr == t.len then begin
      (* TODO(dinosaure): we probably should add a limit here. *)
      t.bstr <- Bstr.create (2 * Bstr.length bstr);
      Bstr.blit bstr ~src_off:t.off t.bstr ~dst_off:0 ~len:t.len
    end;
    let n = fn t.bstr ~off ~len:(Bstr.length t.bstr - off) in
    t.len <- t.len + n;
    n

  let flush t =
    let buf = Bytes.create t.len in
    Bstr.blit_to_bytes t.bstr ~src_off:t.off buf ~dst_off:0 ~len:t.len;
    t.off <- 0;
    t.len <- 0;
    Bytes.unsafe_to_string buf
end

module Notify = struct
  type 'a t = {
      queue: 'a Queue.t
    ; mutex: Miou.Mutex.t
    ; condition: Miou.Condition.t
  }

  let create () =
    {
      queue= Queue.create ()
    ; mutex= Miou.Mutex.create ()
    ; condition= Miou.Condition.create ()
    }

  let signal value t =
    (* NOTE(dinosaure): we use only one core into an unikernel.
       So we are sure that we have the exclusivity of the memory. *)
    (* Miou.Mutex.protect t.mutex @@ fun () -> *)
    Queue.push value t.queue;
    Miou.Condition.signal t.condition

  let await t =
    Miou.Mutex.protect t.mutex @@ fun () ->
    while Queue.is_empty t.queue do
      Miou.Condition.wait t.condition t.mutex
    done;
    Queue.pop t.queue
end

let src = Logs.Src.create "mnet.tcp"

module Log = (val Logs.src_log src : Logs.LOG)

type w = (unit, [ `Eof | `Msg of string ]) result Notify.t

type state = {
    mutable tcp: w Utcp.state
  ; ipv4: IPv4.t
  ; ipv6: IPv6.t
  ; queue: Utcp.output Queue.t
  ; outs: (Ipaddr.t * Ipaddr.t * Utcp.Segment.t) Queue.t
  ; accept: (int, accept) Hashtbl.t
  ; mutex: Miou.Mutex.t
  ; condition: Miou.Condition.t
  ; kill: bool ref
}

and accept = Await of flow Miou.Computation.t | Pending of flow Queue.t

and flow = {
    state: state
  ; tags: Logs.Tag.set
  ; flow: Utcp.flow
  ; buffer: Buffer.t
  ; mutable closed: bool
}

let[@inline always] now () =
  let now = Mkernel.clock_monotonic () in
  Mtime.of_uint64_ns (Int64.of_int now)

let write_without_interruption_ipv4 state (src, dst, seg) =
  let len = Utcp.Segment.length seg in
  let fn bstr =
    let cs = Cstruct.of_bigarray bstr in
    let src = Ipaddr.V4 src and dst = Ipaddr.V4 dst in
    Utcp.Segment.encode_and_checksum_into (now ()) cs ~src ~dst seg
  in
  let pkt = IPv4.Writer.into state.ipv4 ~len fn in
  match IPv4.attempt_to_discover_destination state.ipv4 dst with
  | None ->
      Log.warn (fun m -> m "A packet is kept in our internal queue");
      Queue.push (Ipaddr.V4 src, Ipaddr.V4 dst, seg) state.outs
  | Some macaddr ->
      IPv4.write_directly state.ipv4 ~src (dst, macaddr) ~protocol:6 pkt

let write_ipv4 ipv4 (src, dst, seg) =
  let len = Utcp.Segment.length seg in
  let fn bstr =
    let cs = Cstruct.of_bigarray bstr in
    let src = Ipaddr.V4 src and dst = Ipaddr.V4 dst in
    Utcp.Segment.encode_and_checksum_into (now ()) cs ~src ~dst seg
  in
  let pkt = IPv4.Writer.into ipv4 ~len fn in
  match IPv4.write ipv4 ~src dst ~protocol:6 pkt with
  | Ok () -> ()
  | Error `Route_not_found ->
      Log.err (fun m -> m "%a is unreachable" Ipaddr.V4.pp dst);
      raise Net_unreach

let write_ipv6 ipv6 (src, dst, seg) =
  let len = Utcp.Segment.length seg in
  let fn bstr =
    let cs = Cstruct.of_bigarray ~off:0 ~len bstr in
    let src = Ipaddr.V6 src and dst = Ipaddr.V6 dst in
    Utcp.Segment.encode_and_checksum_into (now ()) cs ~src ~dst seg
  in
  match IPv6.write_directly ipv6 ~src dst ~protocol:6 ~len fn with
  | Ok () -> ()
  | Error `Packet_too_big ->
      (* TODO(dinosaure): we should set MSS on the TCP layer and retry
         everything which was not ACKed. *)
      assert false
  | Error (`Destination_unreachable _) ->
      Log.err (fun m -> m "%a is unreachable" Ipaddr.V6.pp dst);
      raise Net_unreach

let write_ip ipv4 ipv6 (src, dst, seg) =
  match (src, dst) with
  | Ipaddr.V4 src, Ipaddr.V4 dst -> write_ipv4 ipv4 (src, dst, seg)
  | Ipaddr.V6 src, Ipaddr.V6 dst -> write_ipv6 ipv6 (src, dst, seg)
  | Ipaddr.V4 _, Ipaddr.V6 _ ->
      failwith "Impossible to write an IPv6 packet from an IPv4 host"
  | Ipaddr.V6 _, Ipaddr.V4 _ ->
      failwith "Impossible to write an IPv4 packet from an IPv6 host"

let write_without_interruption_ip state (src, dst, seg) =
  match (src, dst) with
  | Ipaddr.V4 src, Ipaddr.V4 dst ->
      write_without_interruption_ipv4 state (src, dst, seg)
  | Ipaddr.V6 src, Ipaddr.V6 dst -> write_ipv6 state.ipv6 (src, dst, seg)
  | Ipaddr.V4 _, Ipaddr.V6 _ ->
      failwith "Impossible to write an IPv6 packet from an IPv4 host"
  | Ipaddr.V6 _, Ipaddr.V4 _ ->
      failwith "Impossible to write an IPv4 packet from an IPv6 host"

type result = Eof | Refused

let fill t =
  let rec one str str_off str_len =
    if str_len > 0 then begin
      let len = Int.min str_len (Buffer.available t.buffer) in
      let into_buffer dst ~off:dst_off ~len:_ =
        Bstr.blit_from_string str ~src_off:str_off dst ~dst_off ~len;
        len
      in
      let _ = Buffer.put t.buffer ~fn:into_buffer in
      one str (str_off + len) (str_len - len)
    end
  in
  List.iter (fun str -> one str 0 (String.length str))

let rec get t =
  match Utcp.recv t.state.tcp (now ()) t.flow with
  | Ok (tcp, [], c, segs) -> begin
      t.state.tcp <- tcp;
      List.iter (write_ip t.state.ipv4 t.state.ipv6) segs;
      match Notify.await c with
      | Ok () -> begin
          match Utcp.recv t.state.tcp (now ()) t.flow with
          | Ok (tcp, [], _c, segs) ->
              t.state.tcp <- tcp;
              List.iter (write_ip t.state.ipv4 t.state.ipv6) segs;
              get t
          | Ok (tcp, data, _c, segs) ->
              t.state.tcp <- tcp;
              List.iter (write_ip t.state.ipv4 t.state.ipv6) segs;
              Ok data
          | Error `Not_found -> Error Refused
          | Error `Eof -> Error Eof
          | Error (`Msg msg) ->
              Log.err (fun m ->
                  m ~tags:t.tags "%a error while read (second recv): %s"
                    Utcp.pp_flow t.flow msg);
              Error Refused
        end
      | Error `Eof -> Error Eof
      | Error (`Msg msg) ->
          Log.err (fun m ->
              m ~tags:t.tags "%a error from computation while recv: %s"
                Utcp.pp_flow t.flow msg);
          Error Refused
    end
  | Ok (tcp, data, _c, segs) ->
      t.state.tcp <- tcp;
      List.iter (write_ip t.state.ipv4 t.state.ipv6) segs;
      Ok data
  | Error `Eof -> Error Eof
  | Error (`Msg msg) ->
      Log.err (fun m ->
          m ~tags:t.tags "%a error while read: %s" Utcp.pp_flow t.flow msg);
      Error Refused
  | Error `Not_found -> Error Refused

let read t ?off:(dst_off = 0) ?len buf =
  if not t.closed then begin
    let default = Bytes.length buf - dst_off in
    let len = Option.value ~default len in
    let fn bstr ~off:src_off ~len:src_len =
      let len = Int.min src_len len in
      Bstr.blit_to_bytes bstr ~src_off buf ~dst_off ~len;
      len
    in
    if Buffer.length t.buffer > 0 then Buffer.get t.buffer ~fn
    else
      match get t with
      | Ok data -> fill t data; Buffer.get t.buffer ~fn
      | Error Eof -> 0
      | Error Refused ->
          t.closed <- true;
          0
  end
  else 0

let get t =
  match get t with
  | Ok css as value ->
      if Buffer.length t.buffer <= 0 then value
      else
        let pre = Buffer.flush t.buffer in
        Ok (pre :: css)
  | Error Eof -> Error `Eof
  | Error Refused ->
      t.closed <- true;
      Error `Refused

let rec really_read t off len buf =
  let len' = read t ~off ~len buf in
  if len' == 0 then raise End_of_file
  else if len - len' > 0 then really_read t (off + len') (len - len') buf

let really_read t ?(off = 0) ?len buf =
  let len = match len with None -> Bytes.length buf - off | Some len -> len in
  if off < 0 || len < 0 || off > Bytes.length buf - len then
    invalid_arg "TCP.really_read";
  if len > 0 then really_read t off len buf

let rec write t str off len =
  match Utcp.send t.state.tcp (now ()) t.flow ~off ~len str with
  | Error `Not_found -> raise Connection_refused
  | Error (`Msg msg) ->
      Log.err (fun m ->
          m ~tags:t.tags "%a error while write: %s" Utcp.pp_flow t.flow msg);
      raise Closed_by_peer
  | Ok (tcp, bytes_sent, c, segs) -> begin
      t.state.tcp <- tcp;
      List.iter (write_ip t.state.ipv4 t.state.ipv6) segs;
      Log.debug (fun m -> m ~tags:t.tags "write %d byte(s)" bytes_sent);
      if bytes_sent < len then
        let result = Notify.await c in
        match result with
        | Error `Eof -> raise Closed_by_peer
        | Error (`Msg msg) ->
            Log.err (fun m ->
                m ~tags:t.tags "%a error from condition while sending: %s"
                  Utcp.pp_flow t.flow msg);
            raise Closed_by_peer
        | Ok () ->
            if len - bytes_sent > 0 then
              write t str (off + bytes_sent) (len - bytes_sent)
    end

let write t ?(off = 0) ?len str =
  let default = String.length str - off in
  let len = Option.value ~default len in
  write t str off len

let write_without_interruption t ?(off = 0) ?len str =
  let default = String.length str - off in
  let len = Option.value ~default len in
  match Utcp.force_enqueue t.state.tcp (now ()) t.flow ~off ~len str with
  | Ok tcp -> t.state.tcp <- tcp
  | Error `Not_found -> raise Connection_refused
  | Error (`Msg msg) ->
      Log.err (fun m ->
          m ~tags:t.tags "%a error while write: %s" Utcp.pp_flow t.flow msg);
      raise Closed_by_peer

let close t =
  if t.closed then Fmt.invalid_arg "Connection already closed";
  match Utcp.close t.state.tcp (now ()) t.flow with
  | Ok (tcp, segs) ->
      t.state.tcp <- tcp;
      List.iter (write_without_interruption_ip t.state) segs;
      t.closed <- true
      (* TODO(dinosaure): You should wait until the connection status is
         [Fin_wait_1], [Fin_wait_2], or [Closing] to be sure that the
         connection has been properly terminated. *)
  | Error `Not_found -> ()
  | Error (`Msg msg) ->
      Log.err (fun m ->
          m ~tags:t.tags "%a error in close: %s" Utcp.pp_flow t.flow msg)

let shutdown t mode =
  match Utcp.shutdown t.state.tcp (now ()) t.flow mode with
  | Ok (tcp, segs) ->
      t.state.tcp <- tcp;
      List.iter (write_ip t.state.ipv4 t.state.ipv6) segs
  | Error (`Msg msg) ->
      Log.err (fun m ->
          m ~tags:t.tags "%a error in shutdown: %s" Utcp.pp_flow t.flow msg)
  | Error `Not_found -> ()

let peers { flow; _ } = Utcp.peers flow
let tags { tags; _ } = tags
let _eof = Error `Eof
let _ok = Ok ()

let handler state src dst payload =
  Log.debug (fun m -> m "New TCP packet (%a -> %a)" Ipaddr.pp src Ipaddr.pp dst);
  let cs = Cstruct.of_bigarray payload in
  Log.debug (fun m ->
      m "@[<hov>%a@]" (Hxd_string.pp Hxd.default) (Cstruct.to_string cs));
  let tcp, ev, segs = Utcp.handle_buf state.tcp (now ()) ~src ~dst cs in
  state.tcp <- tcp;
  begin match ev with
  | Some (`Established (flow, None)) ->
      let (_, src_port), (ipaddr, port) = Utcp.peers flow in
      Log.debug (fun m ->
          m "established connection with %a:%d" Ipaddr.pp ipaddr port);
      let tags = IPv4.tags state.ipv4 in
      let tags = Logs.Tag.add Tags.tcp (ipaddr, port) tags in
      let buffer = Buffer.create 0x7ff in
      let flow = { state; tags; flow; buffer; closed= false } in
      begin match Hashtbl.find state.accept src_port with
      | Await c ->
          Hashtbl.remove state.accept src_port;
          Log.debug (fun m ->
              m "transmit the new incoming TCP connection to the handler");
          ignore (Miou.Computation.try_return c flow)
      | Pending q ->
          if Queue.length q < 1024 then Queue.push flow q
            (* TODO(dinosaure): we only accept 1024 pending established
               connections. We should respond to the client if we reach
               this limit.
               XXX(hannes): not convinced by this hard limit. *)
      | exception Not_found ->
          let q = Queue.create () in
          Queue.push flow q;
          Hashtbl.add state.accept src_port (Pending q)
      end
  | Some (`Established (flow, Some c)) ->
      Log.debug (fun m -> m "connection established (%a)" Utcp.pp_flow flow);
      Notify.signal _ok c
  | Some (`Drop (flow, c, cs)) ->
      Log.debug (fun m -> m "drop (%a)" Utcp.pp_flow flow);
      List.iter (Notify.signal _eof) cs;
      Option.iter (Notify.signal _ok) c
  | Some (`Signal (flow, cs)) ->
      Log.debug (fun m ->
          m "signal (%a)(%d)" Utcp.pp_flow flow (List.length cs));
      List.iter (Notify.signal _ok) cs
  | None -> ()
  end;
  Log.debug (fun m -> m "%d segment(s) produced" (List.length segs));
  List.iter (fun out -> Queue.push out state.queue) segs

exception Timeout

let with_timeout ts fn =
  let prm0 = Miou.async @@ fun () -> Mkernel.sleep ts; raise Timeout in
  let prm1 = Miou.async @@ fn in
  match Miou.await_first [ prm0; prm1 ] with
  | Error Timeout -> `Timeout
  | Error exn -> raise exn
  | Ok value -> value

let or_killed (state : state) () =
  Miou.Mutex.protect state.mutex @@ fun () ->
  while not !(state.kill) do
    Miou.Condition.wait state.condition state.mutex
  done;
  `Kill

let rec transfer state acc =
  match Queue.pop state.queue with
  | exception Queue.Empty -> acc
  | out -> transfer state (out :: acc)

let rec daemon state n =
  Log.debug (fun m -> m "tick");
  match with_timeout 100_000_000 (or_killed state) with
  | `Kill ->
      let handler's_outs = transfer state [] in
      let pending_outs = List.of_seq (Queue.to_seq state.outs) in
      let _tcp, _drop, outs = Utcp.timer state.tcp (now ()) in
      let outs = List.rev_append pending_outs outs in
      let outs = List.rev_append handler's_outs outs in
      Log.debug (fun m ->
          m "Write %d remaining TCP packet(s)" (List.length outs));
      let fn out =
        try write_ip state.ipv4 state.ipv6 out with
        | Net_unreach -> ()
        | _exn -> ()
      in
      List.iter fn outs
  | `Timeout ->
      let handler's_outs = transfer state [] in
      let pending_outs = List.of_seq (Queue.to_seq state.outs) in
      Queue.clear state.outs;
      let tcp, drops, outs = Utcp.timer state.tcp (now ()) in
      state.tcp <- tcp;
      let outs = List.rev_append pending_outs outs in
      let outs = List.rev_append handler's_outs outs in
      let fn out =
        Log.debug (fun m -> m "write new TCP packet from daemon");
        try write_ip state.ipv4 state.ipv6 out with
        | Net_unreach ->
            let _, dst, _ = out in
            Log.err (fun m -> m "Network unreachable for %a" Ipaddr.pp dst)
        | exn ->
            let src, dst, _ = out in
            Log.err (fun m ->
                m "Unexpected exception (%a -> %a): %s" Ipaddr.pp src Ipaddr.pp
                  dst (Printexc.to_string exn))
      in
      List.iter fn outs;
      let fn (_id, err, rcv, snd) =
        let err =
          match err with
          | `Retransmission_exceeded -> `Msg "retransmission exceeded"
          | `Timer_2msl -> `Eof
          | `Timer_connection_established -> `Eof
          | `Timer_fin_wait_2 -> `Eof
        in
        let err = Error err in
        Notify.signal err rcv; Notify.signal err snd
      in
      List.iter fn drops;
      daemon state (n + 1)

type listen = Listen of int [@@unboxed]

(* TODO(dinosaure): clean-up [state.accept] if [accept] is cancelled. *)
let accept state (Listen port) =
  match Hashtbl.find state.accept port with
  | exception Not_found ->
      Log.debug (fun m -> m "Add waiter for *:%d" port);
      let c = Miou.Computation.create () in
      Hashtbl.add state.accept port (Await c);
      Miou.Computation.await_exn c
  | Await c ->
      Log.debug (fun m -> m "Waiter already exists for *:%d" port);
      Miou.Computation.await_exn c
  | Pending q -> begin
      Log.debug (fun m ->
          m "Pending established connections (%d)" (Queue.length q));
      match Queue.pop q with
      | exception Queue.Empty ->
          let c = Miou.Computation.create () in
          Hashtbl.replace state.accept port (Await c);
          Miou.Computation.await_exn c
      | flow -> flow
    end

let listen state port =
  let tcp = Utcp.start_listen state.tcp port in
  state.tcp <- tcp;
  Listen port

type daemon = {
    condition: Miou.Condition.t
  ; mutex: Miou.Mutex.t
  ; prm: unit Miou.t
  ; kill: bool ref
}

let create ~name ipv4 ipv6 =
  let tcp = Utcp.empty Notify.create name in
  let accept = Hashtbl.create 0x10 in
  let mutex = Miou.Mutex.create () in
  let condition = Miou.Condition.create () in
  let kill = ref false in
  let state =
    {
      tcp
    ; ipv4
    ; ipv6
    ; queue= Queue.create ()
    ; mutex
    ; condition
    ; accept
    ; outs= Queue.create ()
    ; kill
    }
  in
  let prm = Miou.async (fun () -> daemon state 0) in
  let daemon = { condition; mutex; prm; kill } in
  (daemon, state)

let kill (daemon : daemon) =
  begin
    Miou.Mutex.protect daemon.mutex @@ fun () ->
    daemon.kill := true;
    Miou.Condition.broadcast daemon.condition
  end;
  Miou.await_exn daemon.prm

let connect state (dst, dst_port) =
  let src =
    match dst with
    | Ipaddr.V4 dst -> Ipaddr.V4 (IPv4.src state.ipv4 ~dst)
    | Ipaddr.V6 dst -> Ipaddr.V6 (IPv6.src state.ipv6 ~dst)
  in
  let tcp, flow, c, seg = Utcp.connect ~src ~dst ~dst_port state.tcp (now ()) in
  let tags = IPv4.tags state.ipv4 in
  let tags = Logs.Tag.add Tags.tcp (dst, dst_port) tags in
  state.tcp <- tcp;
  write_ip state.ipv4 state.ipv6 seg;
  Log.debug (fun m -> m ~tags "Waiting for a TCP handshake");
  match Notify.await c with
  | Ok () ->
      let buffer = Buffer.create 0x7ff in
      { state; flow; tags; buffer; closed= false }
  | Error `Eof ->
      Log.err (fun m ->
          m ~tags "%a error established connection (timeout)" Utcp.pp_flow flow);
      raise Connection_refused
  | Error (`Msg msg) ->
      Log.err (fun m ->
          m ~tags "%a error established connection: %s" Utcp.pp_flow flow msg);
      raise Connection_refused
