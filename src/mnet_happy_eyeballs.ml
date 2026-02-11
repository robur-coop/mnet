let src = Logs.Src.create "mnet.happy_eyeballs"
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

module Log = (val Logs.src_log src : Logs.LOG)
module HE = Happy_eyeballs

[@@@warning "-30"]

type state = ((Ipaddr.t * int) * Mnet.TCP.flow) Miou.Computation.t
and entry = HE.id * attempt * [ `host ] Domain_name.t * addr
and attempt = int
and addr = Ipaddr.t * int
and cancel = attempt * unit Miou.t

and connect_ip = {
    aaaa_timeout: int64 option
  ; connect_delay: int64 option
  ; connect_timeout: int64 option
  ; state: state
  ; addrs: addr list
}

and connect = {
    aaaa_timeout: int64 option
  ; connect_delay: int64 option
  ; connect_timeout: int64 option
  ; resolve_timeout: int64 option
  ; resolve_retries: int option
  ; state: state
  ; host: [ `host ] Domain_name.t
  ; ports: int list
}

and action = [ `Connect_ip of connect_ip | `Connect of connect ]
and connected = [ `Connected of entry * Mnet.TCP.flow ]

type event =
  [ connected
  | `Connection_failed of entry * string
  | `Resolution_v4 of
    [ `host ] Domain_name.t * (Ipaddr.V4.Set.t, [ `Msg of string ]) result
  | `Resolution_v6 of
    [ `host ] Domain_name.t * (Ipaddr.V6.Set.t, [ `Msg of string ]) result ]

and getaddrinfo =
     [ `A | `AAAA ]
  -> [ `host ] Domain_name.t
  -> (Ipaddr.Set.t, [ `Msg of string ]) result

type t = {
    mutable cancel_connecting: cancel list HE.Waiter_map.t
  ; mutable waiters: state HE.Waiter_map.t
  ; condition: Miou.Condition.t
  ; mutex: Miou.Mutex.t
  ; queue: [ action | event ] Queue.t
  ; mutable set: bool
  ; mutable getaddrinfo: getaddrinfo
  ; timer_interval: int
  ; tcp: Mnet.TCP.state
}

and daemon = unit Miou.t

let try_connect t ~meta ((ipaddr, port) as addr) () =
  try
    let flow = Mnet.TCP.connect t.tcp addr in
    Miou.Mutex.protect t.mutex @@ fun () ->
    Queue.push (`Connected (meta, flow)) t.queue;
    Miou.Condition.signal t.condition
  with exn ->
    let msg =
      Fmt.str "Connection to %a:%d failed with: %s" Ipaddr.pp ipaddr port
        (Printexc.to_string exn)
    in
    Miou.Mutex.protect t.mutex @@ fun () ->
    Queue.push (`Connection_failed (meta, msg)) t.queue;
    Miou.Condition.signal t.condition

let connect t ~prms:orphans host id attempt addr =
  let meta = (id, attempt, host, addr) in
  let prm : unit Miou.t = Miou.async ~orphans (try_connect t ~meta addr) in
  let entry = (attempt, prm) in
  let fn = function None -> Some [ entry ] | Some cs -> Some (entry :: cs) in
  t.cancel_connecting <- HE.Waiter_map.update id fn t.cancel_connecting

exception Connection_failed of [ `host ] Domain_name.t * string

let empty = Printexc.get_callstack 0
let connection_failed host reason = (Connection_failed (host, reason), empty)

let handle_one_action t ~prms action =
  match action with
  | HE.Connect (host, id, attempt, addr) -> connect t ~prms host id attempt addr
  | HE.Connect_failed (host, id, reason) ->
      let cancel_connecting, others =
        HE.Waiter_map.find_and_remove id t.cancel_connecting
      in
      t.cancel_connecting <- cancel_connecting;
      let fn (_, prm) = Miou.cancel prm in
      List.iter fn (Option.value ~default:[] others);
      let waiters, waiter = HE.Waiter_map.find_and_remove id t.waiters in
      t.waiters <- waiters;
      let trans waiter =
        let err = connection_failed host reason in
        ignore (Miou.Computation.try_cancel waiter err)
      in
      Option.iter trans waiter
  | _ -> assert false

let to_event t = function
  | `Connection_failed ((id, attempt, host, addr), msg) ->
      let fold = function
        | None as none -> none
        | Some cs -> begin
            match List.filter (fun (att, _) -> not (att = attempt)) cs with
            | [] -> None
            | cs -> Some cs
          end
      in
      t.cancel_connecting <- HE.Waiter_map.update id fold t.cancel_connecting;
      HE.Connection_failed (host, id, addr, msg)
  | `Connected ((id, attempt, host, addr), flow) ->
      let cancel_connecting, others =
        HE.Waiter_map.find_and_remove id t.cancel_connecting
      in
      t.cancel_connecting <- cancel_connecting;
      let fn (att, prm) = if att <> attempt then Miou.cancel prm in
      List.iter fn (Option.value ~default:[] others);
      let waiters, waiter = HE.Waiter_map.find_and_remove id t.waiters in
      t.waiters <- waiters;
      begin match waiter with
      | None -> Mnet.TCP.close flow
      | Some waiter ->
          let set = Miou.Computation.try_return waiter (addr, flow) in
          if not set then Mnet.TCP.close flow
      end;
      Happy_eyeballs.Connected (host, id, addr)
  | _ -> assert false

let now () = Int64.of_int (Mkernel.clock_monotonic ())

let to_actions t he user's_actions =
  let fold (he, actions) = function
    | `Connect_ip { aaaa_timeout; connect_delay; connect_timeout; state; addrs }
      ->
        let waiters, id = HE.Waiter_map.register state t.waiters in
        t.waiters <- waiters;
        let he, actions' =
          HE.connect_ip he (now ()) ?aaaa_timeout ?connect_delay
            ?connect_timeout ~id addrs
        in
        (he, actions @ actions')
        (* TODO(dinosaure): [List.rev_append]? *)
    | `Connect
        {
          aaaa_timeout
        ; connect_delay
        ; connect_timeout
        ; resolve_timeout
        ; resolve_retries
        ; state
        ; host
        ; ports
        } ->
        let waiters, id = HE.Waiter_map.register state t.waiters in
        t.waiters <- waiters;
        let he, actions' =
          HE.connect he (now ()) ?aaaa_timeout ?connect_delay ?connect_timeout
            ?resolve_timeout ?resolve_retries ~id host ports
        in
        (* TODO(dinosaure): [List.rev_append]? *)
        (he, actions @ actions')
  in
  List.fold_left fold (he, []) user's_actions

let await_actions_or_events t =
  Miou.Mutex.protect t.mutex @@ fun () ->
  while Queue.is_empty t.queue do
    Miou.Condition.wait t.condition t.mutex
  done;
  let seq = Queue.to_seq t.queue in
  let lst = List.of_seq seq in
  Queue.clear t.queue; `Queue lst

exception Timeout

let with_timeout ~timeout:ts fn =
  let prm0 = Miou.async @@ fun () -> Mkernel.sleep ts; raise Timeout in
  let prm1 = Miou.async fn in
  match Miou.await_first [ prm0; prm1 ] with
  | Error Timeout -> `Timeout
  | Error exn -> `Exn exn
  | Ok v -> v

let continue t cont he =
  let fn () =
    match cont with
    | `Act ->
        let fn () = await_actions_or_events t in
        with_timeout ~timeout:t.timer_interval fn
    | `Suspend -> await_actions_or_events t
  in
  match fn () with
  | `Timeout -> (he, [], [])
  | `Queue actions_and_events ->
      let user's_actions, events =
        let fn = function
          | #action as action -> Either.Left action
          | #event as event -> Either.Right event
        in
        List.partition_map fn actions_and_events
      in
      let he, actions = to_actions t he user's_actions in
      (he, actions, events)
  | `Exn exn -> raise exn

let rec clean_up prms =
  match Miou.care prms with
  | Some (Some prm) ->
      let _ = Miou.await prm in
      clean_up prms
  | Some None | None -> Miou.yield ()

let rec go t ~prms he =
  clean_up prms;
  let he, cont, actions = HE.timer he (now ()) in
  List.iter (handle_one_action ~prms t) actions;
  let he, actions, events = continue t cont he in
  let he, actions =
    let fn (he, actions) event =
      let he, actions' = HE.event he (now ()) (to_event t event) in
      (he, List.rev_append actions actions')
    in
    List.fold_left fn (he, actions) events
  in
  List.iter (handle_one_action ~prms t) actions;
  go t ~prms he

let unknown _ domain_name = error_msgf "%a not found" Domain_name.pp domain_name

let create ?happy_eyeballs:(he = HE.create (now ()))
    ?(timer_interval = 10_000_000) ?(getaddrinfo = unknown) tcp =
  let cancel_connecting = HE.Waiter_map.empty in
  let waiters = HE.Waiter_map.empty in
  let condition = Miou.Condition.create () in
  let mutex = Miou.Mutex.create () in
  let queue = Queue.create () in
  let set = false in
  let t =
    {
      cancel_connecting
    ; waiters
    ; condition
    ; mutex
    ; queue
    ; set
    ; tcp
    ; getaddrinfo
    ; timer_interval
    }
  in
  let prm = Miou.async @@ fun () -> go t ~prms:(Miou.orphans ()) he in
  (prm, t)

let kill = Miou.cancel

let connect_ip ?aaaa_timeout ?connect_delay ?connect_timeout t addrs =
  let state = Miou.Computation.create () in
  let connect_ip =
    { aaaa_timeout; connect_delay; connect_timeout; state; addrs }
  in
  Miou.Mutex.protect t.mutex @@ fun () ->
  Queue.push (`Connect_ip connect_ip) t.queue;
  state

let connect_ip ?aaaa_timeout ?connect_delay ?connect_timeout t ips =
  let state = connect_ip ?aaaa_timeout ?connect_delay ?connect_timeout t ips in
  match Miou.Computation.await state with
  | Ok _ as value -> value
  | Error (Connection_failed (_host, msg), _) -> Error (`Msg msg)
  | Error (exn, bt) -> Printexc.raise_with_backtrace exn bt

let connect_host ?aaaa_timeout ?connect_delay ?connect_timeout ?resolve_timeout
    ?resolve_retries t host ports =
  let state = Miou.Computation.create () in
  begin
    Miou.Mutex.protect t.mutex @@ fun () ->
    let connect =
      {
        aaaa_timeout
      ; connect_delay
      ; connect_timeout
      ; resolve_timeout
      ; resolve_retries
      ; state
      ; host
      ; ports
      }
    in
    Queue.push (`Connect connect) t.queue;
    Miou.Condition.signal t.condition
  end;
  match Miou.Computation.await state with
  | Ok _ as value -> value
  | Error (Connection_failed (_host, msg), _) -> Error (`Msg msg)
  | Error (exn, bt) -> Printexc.raise_with_backtrace exn bt

let connect ?aaaa_timeout ?connect_delay ?connect_timeout ?resolve_timeout
    ?resolve_retries t str ports =
  match Ipaddr.of_string str with
  | Ok ipaddr ->
      connect_ip ?aaaa_timeout ?connect_delay ?connect_timeout t
        (List.map (fun port -> (ipaddr, port)) ports)
  | Error _ -> begin
      match Result.bind (Domain_name.of_string str) Domain_name.host with
      | Ok domain_name ->
          connect_host ?aaaa_timeout ?connect_delay ?connect_timeout
            ?resolve_timeout ?resolve_retries t domain_name ports
      | Error _ -> error_msgf "Invalid endpoint: %S" str
    end
