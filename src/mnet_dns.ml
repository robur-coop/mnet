let pp_addr ppf (ipaddr, port) = Fmt.pf ppf "%a:%d" Ipaddr.pp ipaddr port
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let ( let* ) = Result.bind
let ( let@ ) finally fn = Fun.protect ~finally fn
let src = Logs.Src.create "mnet.dns"

module Log = (val Logs.src_log src : Logs.LOG)

module Ke = struct
  type t = {
      mutable rd: int
    ; mutable wr: int
    ; mutable ln: int
    ; mutable buf: bytes
  }

  let unsafe_create ln = { rd= 0; wr= 0; ln; buf= Bytes.create ln }
  let mask t v = v land (t.ln - 1)
  let shift t len = t.rd <- t.rd + len
  let available t = t.ln - (t.wr - t.rd)
  let length t = t.wr - t.rd

  let compress t =
    let len = length t in
    let mask = mask t t.rd in
    let pre = t.ln - mask in
    let rem = len - pre in
    if rem > 0 then
      if available t >= pre then begin
        Bytes.blit t.buf 0 t.buf pre rem;
        Bytes.blit t.buf mask t.buf 0 pre
      end
      else begin
        let tmp = Bytes.create pre in
        Bytes.blit t.buf mask tmp 0 pre;
        Bytes.blit t.buf 0 t.buf pre rem;
        Bytes.blit tmp 0 t.buf 0 pre
      end
    else Bytes.blit t.buf mask t.buf 0 len;
    t.rd <- 0;
    t.wr <- len

  let to_power_of_two v =
    let v = ref (pred v) in
    v := !v lor (!v lsr 1);
    v := !v lor (!v lsr 2);
    v := !v lor (!v lsr 4);
    v := !v lor (!v lsr 8);
    v := !v lor (!v lsr 16);
    succ !v

  let grow t want =
    let ln = to_power_of_two (Int.max 1 (Int.max want (length t))) in
    if ln <> Bytes.length t.buf then begin
      let dst = Bytes.create ln in
      let length = length t in
      let mask = mask t t.rd in
      let pre = t.ln - mask in
      let rem = length - pre in
      if rem > 0 then begin
        Bytes.blit t.buf mask dst 0 pre;
        Bytes.blit t.buf 0 dst pre rem
      end
      else Bytes.blit t.buf mask dst 0 length;
      t.buf <- dst;
      t.wr <- length;
      t.ln <- ln;
      t.rd <- 0
    end

  let push t str =
    let len = String.length str in
    if available t < len then grow t (len + length t);
    let mask = mask t t.wr in
    let pre = t.ln - mask in
    let rem = len - pre in
    if rem > 0 then begin
      Bytes.blit_string str 0 t.buf mask pre;
      Bytes.blit_string str pre t.buf 0 rem
    end
    else Bytes.blit_string str 0 t.buf mask len;
    t.wr <- t.wr + len

  let peek t =
    match length t with
    | 0 -> None
    | len ->
        let mask = mask t t.rd in
        let pre = t.ln - mask in
        let rem = len - pre in
        if rem > 0 then (
          let res = Bytes.create (pre + rem) in
          Bytes.blit t.buf mask res 0 pre;
          Bytes.blit t.buf 0 res pre rem;
          Some (Bytes.unsafe_to_string res))
        else Some (Bytes.sub_string t.buf mask len)
end

module Key = struct
  type t = Ipaddr.t * int

  let compare (ia, ka) (ib, kb) =
    let res = Ipaddr.compare ia ib in
    if res <> 0 then res else Int.compare ka kb
end

module UReqs = Map.Make (Key)
module Reqs = Map.Make (Int)
module Set = Set.Make (Int)

module Transport = struct
  (* NOTE(dinosaure): the implementation of the transport layer for [ocaml-dns]
     differs from [dns-client-miou-unix] where the goal here is to keep as long
     as we can one TCP/IP connection instead to instantiate one per queries. We
     have a daemon which keep its TCP/IP connection (if the user choose the
     TCP/TLS mode) and if, at one point, the connection is closed, we retry a
     new one. Then;
     - when it's about sending, [ocaml-dns] notifies the daemon that it would
       like to send a new query and the daemon send it with the current active
       TCP/IP connection.
     - when it's about receiving, our daemon has a background task which read
       indefinitely our active TCP/IP connection and triggers [ivar]s when it
       receive a new response.

     About UDP, the transport layer is much more simple, we have our daemon
     which listen all *)
  type context = {
      nameservers: io_addr list
    ; timeout: int
    ; mutable ports: Set.t
    ; mutable mode: [ `Tcp of Ipaddr.t * Ke.t | `Udp ] option
    ; mutable reqs: (string * ivar) Reqs.t
    ; mutable ureqs: ivar UReqs.t
    ; queries: string Queue.t
    ; uqueries: int Queue.t
    ; mutex: Miou.Mutex.t
    ; condition: Miou.Condition.t
    ; he: Mnet_happy_eyeballs.t
    ; udp: Mnet.UDP.state
  }

  and ivar = string Miou.Computation.t
  and t = context * unit Miou.t
  and +'a io = 'a
  and stack = Mnet.UDP.state * Mnet_happy_eyeballs.t

  and io_addr =
    [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]

  let kill (_, prm) = Miou.cancel prm
  let bind x fn = fn x
  let lift x = x
  let clock () = Int64.of_int (Mkernel.clock_monotonic ())
  let rng len = Mirage_crypto_rng.generate len
  let nsec_per_day = Int64.mul 86_400L 1_000_000_000L
  let ps_per_ns = 1_000L

  let time () =
    let nsec = Int64.of_int (Mkernel.clock_wall ()) in
    let days = Int64.div nsec nsec_per_day in
    let rem_ns = Int64.rem nsec nsec_per_day in
    let rem_ps = Int64.mul rem_ns ps_per_ns in
    Some (Ptime.v (Int64.to_int days, rem_ps))

  let uncensoreddns_org =
    let ipaddr = Ipaddr.of_string_exn "89.233.43.71" in
    let authenticator =
      X509.Authenticator.of_string
        "key-fp:SHA256:INSZEZpDoWKiavosV2/xVT8O83vk/RRwS+LTiL+IpHs="
    in
    let authenticator = Result.get_ok authenticator in
    let authenticator = authenticator time in
    let cfg = Tls.Config.client ~authenticator () in
    let cfg = Result.get_ok cfg in
    `Tls (cfg, ipaddr, 853)

  let nameservers ({ nameservers; mode; _ }, _) =
    let proto =
      match mode with Some `Udp -> `Udp | Some (`Tcp _) | None -> `Tcp
    in
    (proto, nameservers)

  exception Timeout

  let with_timeout ~timeout:ts fn =
    let prm0 = Miou.async @@ fun () -> Mkernel.sleep ts; raise Timeout in
    let prm1 = Miou.async fn in
    match Miou.await_first [ prm0; prm1 ] with
    | Error Timeout -> `Timeout
    | Ok value -> value
    | Error exn -> raise exn

  let generate_port =
    let tmp = Bytes.create 2 in
    fun t ->
      let rec go retries =
        if retries > 0 then begin
          Mirage_crypto_rng.generate_into tmp 2;
          let rnd = Bytes.get_uint16_be tmp 0 in
          let port = (1024 + rnd) mod (65536 - 1024) in
          if Set.mem port t.ports then go (retries - 1)
          else begin
            t.ports <- Set.add port t.ports;
            Ok port
          end
        end
        else error_msgf "Couldn't find a free UDP port"
      in
      go 32

  let to_pairs =
    let fn = function
      | `Plaintext (ipaddr, port) | `Tls (_, ipaddr, port) -> (ipaddr, port)
    in
    List.map fn

  let tls_config_of_nameserver ns (ipaddr, port) =
    let fn = function
      | `Tls (cfg, ipaddr', port') ->
          if Ipaddr.compare ipaddr ipaddr' = 0 && port = port' then Some cfg
          else None
      | _ -> None
    in
    List.find_map fn ns

  let rec connect_to_nameservers t nameservers =
    let ns = to_pairs nameservers in
    let connect_timeout = Int64.of_int t.timeout in
    let* addr, flow = Mnet_happy_eyeballs.connect_ip ~connect_timeout t.he ns in
    match tls_config_of_nameserver t.nameservers addr with
    | None -> Ok (addr, `Plain flow)
    | Some cfg -> try_tls_connection t nameservers cfg addr flow

  and try_tls_connection t nameservers cfg addr flow =
    match Mnet_tls.client_of_fd cfg flow with
    | flow -> Ok (addr, `TLS flow)
    | exception exn ->
        Log.warn (fun m ->
            m "Impossible to initiate a TLS connection with %a: %s" pp_addr addr
              (Printexc.to_string exn));
        let fn = function
          | `Tls (_, ipaddr, port) ->
              not (Ipaddr.compare ipaddr (fst addr) = 0 && port = snd addr)
          | _ -> true
        in
        let nameservers' = List.filter fn nameservers in
        if nameservers' = [] then error_msgf "No further nameservers configured"
        else connect_to_nameservers t nameservers'

  (* NOTE(dinosaure): Consume until we don't have enough to decode DNS packets.
     We trigger the [ivar]s associated with the [uid]s extracted from the
     packets. The ringbuffer [ke] should not grow more than 8192 bytes. *)
  let process ke reqs =
    let rec go () =
      match Ke.peek ke with
      | Some str when String.length str > 2 ->
          let len = String.get_uint16_be str 0 in
          if String.length str - 2 >= 2 then begin
            let packet = String.sub str 0 (len + 2) in
            let uid = String.get_uint16_be packet 2 in
            Log.debug (fun m -> m "New DNS response (uid:%02x)" uid);
            Log.debug (fun m ->
                m "Something waiting for this response? %b"
                  (Option.is_some (Reqs.find_opt uid reqs)));
            let fn (_tx, ivar) =
              assert (Miou.Computation.try_return ivar packet)
            in
            Option.iter fn (Reqs.find_opt uid reqs);
            Ke.shift ke (len + 2);
            go ()
          end
      | _ -> ()
    in
    go ()

  let rec read_from_tcp t ke buf flow =
    match Mnet.TCP.read flow buf with
    | (exception _) | 0 -> ()
    | len ->
        let str = Bytes.sub_string buf 0 len in
        Ke.push ke str;
        process ke t.reqs;
        read_from_tcp t ke buf flow

  let rec read_from_tls t ke buf flow =
    match Mnet_tls.read flow buf with
    | (exception _) | 0 -> ()
    | len ->
        let str = Bytes.sub_string buf 0 len in
        Ke.push ke str;
        process ke t.reqs;
        read_from_tls t ke buf flow

  let rec write_to_tcp t flow =
    let queries =
      Miou.Mutex.protect t.mutex @@ fun () ->
      while Queue.is_empty t.queries do
        Miou.Condition.wait t.condition t.mutex
      done;
      let queries = Queue.to_seq t.queries in
      let queries = List.of_seq queries in
      Queue.clear t.queries; queries
    in
    let fn query =
      match flow with
      | `Plain flow -> Mnet.TCP.write flow query
      | `TLS flow -> Mnet_tls.write flow query
    in
    List.iter fn queries; write_to_tcp t flow

  let read_from_tcp t ke =
    let finally = function
      | `Plain flow -> Mnet.TCP.close flow
      | `TLS flow -> Mnet_tls.close flow
    in
    let buf = Bytes.create 4096 in
    let rec go0 t flow =
      let resource = Miou.Ownership.create ~finally flow in
      Miou.Ownership.own resource;
      let prm0 =
        Miou.async @@ fun () ->
        match flow with
        | `Plain flow -> read_from_tcp t ke buf flow
        | `TLS flow -> read_from_tls t ke buf flow
      in
      let prm1 = Miou.async @@ fun () -> write_to_tcp t flow in
      let _ = Miou.await_first [ prm0; prm1 ] in
      Miou.Ownership.release resource;
      (* NOTE(dinosaure): Here, the connection was closed for whatever reason, we
         try to initiate a new connection and re-instantiate a reader loop. If we
         are not able to find a nameserver, we fail. *)
      match connect_to_nameservers t t.nameservers with
      | Ok (addr, flow) ->
          Log.debug (fun m -> m "Connected to %a" pp_addr addr);
          go0 t flow
      | Error _err -> t.mode <- None
    in
    (* NOTE(dinosaure): first try. *)
    match connect_to_nameservers t t.nameservers with
    | Ok (addr, flow) ->
        Log.debug (fun m -> m "Connected to %a" pp_addr addr);
        go0 t flow
    | Error _err -> t.mode <- None

  let read_from_udp t =
    let rec clean_up orphans =
      match Miou.care orphans with
      | None | Some None -> ()
      | Some (Some prm) ->
          let _ = Miou.await prm in
          clean_up orphans
    in
    let fn ~port =
     fun () ->
      let buf = Bytes.create 4096 in
      let rec go retries =
        let len, (peer, _) = Mnet.UDP.recvfrom t.udp ~port buf in
        let str = Bytes.sub_string buf 0 len in
        if len > 12 then begin
          let uid = String.get_uint16_be str 0 in
          match (UReqs.find_opt (peer, uid) t.ureqs, Set.mem port t.ports) with
          | Some ivar, _ -> assert (Miou.Computation.try_return ivar str)
          | None, true when retries > 0 -> go (pred retries) (* retry *)
          | _ -> ()
        end
        else if retries > 0 then go (pred retries)
      in
      go 32; `Terminate
    in
    let fn ~orphans ~port =
      Miou.async ~orphans @@ fun () ->
      with_timeout ~timeout:t.timeout (fn ~port)
    in
    let rec go orphans =
      clean_up orphans;
      let ports =
        Miou.Mutex.protect t.mutex @@ fun () ->
        while Queue.is_empty t.uqueries do
          Miou.Condition.wait t.condition t.mutex
        done;
        let ports = Queue.to_seq t.uqueries in
        let ports = List.of_seq ports in
        Queue.clear t.uqueries; ports
      in
      let fn port = ignore (fn ~orphans ~port) in
      List.iter fn ports; go orphans
    in
    go (Miou.orphans ())

  let daemon t =
    match t.mode with
    | Some `Udp -> read_from_udp t (* forever *)
    | Some (`Tcp (_, ke)) -> read_from_tcp t ke
    | None -> ()

  let create ?(nameservers = (`Tcp, [ uncensoreddns_org ])) ~timeout (udp, he) =
    let ports = Set.empty in
    let proto, nameservers = nameservers in
    let mode =
      match proto with
      | `Udp -> Some `Udp
      | `Tcp ->
          Log.debug (fun m -> m "Initiate a TCP connection to nameservers");
          let ipaddr = Ipaddr.(V4 V4.unspecified) in
          let ke = Ke.unsafe_create 8192 in
          Some (`Tcp (ipaddr, ke))
    in
    let reqs = Reqs.empty in
    let ureqs = UReqs.empty in
    let queries = Queue.create () in
    let uqueries = Queue.create () in
    let mutex = Miou.Mutex.create () in
    let condition = Miou.Condition.create () in
    let timeout = Int64.to_int timeout in
    let context =
      {
        nameservers
      ; timeout
      ; ports
      ; mode
      ; reqs
      ; ureqs
      ; queries
      ; uqueries
      ; mutex
      ; condition
      ; he
      ; udp
      }
    in
    let prm = Miou.async @@ fun () -> daemon context in
    (context, prm)

  let connect (t, _daemon) =
    match t.mode with
    | Some `Udp -> Ok (`Udp, t)
    | Some (`Tcp _) -> Ok (`Tcp, t)
    | None ->
        error_msgf "Impossible to initiate a TCP connection to nameservers"

  let close _ = ()

  let push_on_tcp t tx =
    Miou.Mutex.protect t.mutex @@ fun () ->
    Queue.push tx t.queries;
    Miou.Condition.signal t.condition

  let push_on_udp t port =
    Miou.Mutex.protect t.mutex @@ fun () ->
    Queue.push port t.uqueries;
    Miou.Condition.signal t.condition

  let send_recv t tx =
    if String.length tx > 4 then
      match t.mode with
      | Some `Udp ->
          let dst, dst_port =
            match t.nameservers with
            | `Plaintext (ipaddr, port) :: _ -> (ipaddr, port)
            | _ -> assert false
          in
          let uid = String.get_uint16_be tx 0 in
          let* port = generate_port t in
          let fn () =
            push_on_udp t port;
            let rx = Miou.Computation.create () in
            let finally _ =
              t.ports <- Set.remove port t.ports;
              t.ureqs <- UReqs.remove (dst, uid) t.ureqs
            in
            let resource = Miou.Ownership.create ~finally rx in
            Miou.Ownership.own resource;
            Mnet.UDP.sendto t.udp ~src_port:port ~dst ~port:dst_port tx
            |> Result.map_error (Fmt.str "%a" Mnet.UDP.pp_error)
            |> Result.error_to_failure;
            t.ureqs <- UReqs.add (dst, uid) rx t.ureqs;
            let@ () = fun () -> Miou.Ownership.release resource in
            match Miou.Computation.await rx with
            | Ok rx -> `Rx rx
            | Error exn -> `Exn exn
          in
          begin match with_timeout ~timeout:t.timeout fn with
          | exception Failure msg -> Error (`Msg msg)
          | `Timeout -> error_msgf "Request timeout"
          | `Exn (exn, _) -> raise exn
          | `Rx rx -> Ok rx
          end
      | Some (`Tcp _) ->
          let uid = String.get_uint16_be tx 2 in
          let fn () =
            let rx = Miou.Computation.create () in
            let finally _ = t.reqs <- Reqs.remove uid t.reqs in
            let resource = Miou.Ownership.create ~finally rx in
            Miou.Ownership.own resource;
            t.reqs <- Reqs.add uid (tx, rx) t.reqs;
            push_on_tcp t tx;
            let@ () = fun () -> Miou.Ownership.release resource in
            match Miou.Computation.await rx with
            | Ok rx -> `Rx rx
            | Error exn -> `Exn exn
          in
          begin match with_timeout ~timeout:t.timeout fn with
          | exception Failure msg -> Error (`Msg msg)
          | `Timeout -> error_msgf "Request timeout"
          | `Exn (exn, _) -> raise exn
          | `Rx rx -> Ok rx
          end
      | None -> error_msgf "No TCP/IP connection to resolver"
    else error_msgf "Invalid DNS transmit packet"
end

include Dns_client.Make (Transport)
