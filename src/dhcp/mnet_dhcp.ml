let src = Logs.Src.create "mnet.dhcp"

module Log = (val Logs.src_log src : Logs.LOG)
module Ethernet = Ethernet

let[@inline always] now () = Mkernel.clock_monotonic ()

(* Lease *)

type lease = Dhcp_wire.pkt

let opts (l : lease) = l.Dhcp_wire.options

let cidr l =
  let address = l.Dhcp_wire.yiaddr in
  match Dhcp_wire.find_subnet_mask (opts l) with
  | Some netmask -> Ipaddr.V4.Prefix.of_netmask_exn ~netmask ~address
  | None -> Ipaddr.V4.Prefix.make 32 address

let gateway l =
  match Dhcp_wire.collect_routers (opts l) with [] -> None | g :: _ -> Some g

let dns_servers l = Dhcp_wire.collect_dns_servers (opts l)

let domain_name l =
  let ( >>= ) = Result.bind in
  let value =
    Dhcp_wire.find_domain_name (opts l)
    |> Option.to_result ~none:`Not_found
    >>= Domain_name.of_string
    >>= Domain_name.host
  in
  Result.to_option value

let lease_time l = Dhcp_wire.find_ip_lease_time (opts l)
let options l = opts l
let pp_lease = Dhcp_wire.pp_pkt

(* Configuration *)

type decision = Accept | Reject

type config = {
    requests: Dhcp_wire.option_code list
  ; options: Dhcp_wire.dhcp_option list
  ; on_lease: previous:lease option -> lease -> decision
}

let accept_all =
  { requests= []; options= []; on_lease= (fun ~previous:_ _ -> Accept) }

let with_requests requests config = { config with requests }

(* Daemon *)

let retransmit = 4_000_000_000
let min_delay = 1_000_000_000

(* RFC 2131 (section 3.1.5): a client that declines an address SHOULD wait a
   minimum of ten seconds before restarting the configuration process. *)
let decline_backoff = 10_000_000_000
let default_lease = 3600 (* seconds *)

type phase =
  | Negotiating
  | Bound of int (* in nanoseconds *)
  | Backoff of int (* in nanoseconds *)

let pp_phase ppf = function
  | Negotiating -> Fmt.string ppf "negotiating"
  | Bound until -> Fmt.pf ppf "bound (renew at %d)" until
  | Backoff until -> Fmt.pf ppf "backoff (until %d)" until

type input =
  | Frame of Cstruct.t
  | Conflict of Ipaddr.V4.t * Macaddr.t
  | Timeout

let pp_input ppf = function
  | Frame _ -> Fmt.string ppf "frame"
  | Conflict (ip, mac) ->
      Fmt.pf ppf "conflict(%a is-at %a)" Ipaddr.V4.pp ip Macaddr.pp mac
  | Timeout -> Fmt.string ppf "timeout"

type action = Send of string | Apply of lease | Revoke

let pp_action ppf = function
  | Send _ -> Fmt.string ppf "send"
  | Apply lease -> Fmt.pf ppf "apply(%a)" Ipaddr.V4.pp lease.Dhcp_wire.yiaddr
  | Revoke -> Fmt.string ppf "revoke"

type dhcp = {
    client: Dhcp_client.t
  ; outstanding: string option
  ; lease: lease option
  ; phase: phase
}

type state = {
    eth: Ethernet.t
  ; mac: Macaddr.t
  ; config: config
  ; apply: lease -> unit
  ; revoke: unit -> unit
  ; mutable dhcp: dhcp
  ; mutex: Miou.Mutex.t
  ; condition: Miou.Condition.t
  ; queue: input Queue.t
}

let random_xid () =
  let str = Mirage_crypto_rng.generate 4 in
  String.get_int32_be str 0

let frame_of_pkt pkt = Cstruct.to_string (Dhcp_wire.buf_of_pkt pkt)

let renewal_delay l =
  let secs =
    match Dhcp_wire.find_renewal_t1 (options l) with
    | Some t1 -> Int32.to_int t1
    | None -> (
        match lease_time l with
        | Some lt -> Int32.to_int lt / 2
        | None -> default_lease)
  in
  let secs = if secs <= 0 then default_lease else secs in
  secs * 1_000_000_000

let decline ~xid ~mac ~requested ~server =
  {
    Dhcp_wire.srcmac= mac
  ; dstmac= Macaddr.broadcast
  ; srcip= Ipaddr.V4.any
  ; dstip= Ipaddr.V4.broadcast
  ; srcport= Dhcp_wire.client_port
  ; dstport= Dhcp_wire.server_port
  ; op= Dhcp_wire.BOOTREQUEST
  ; htype= Dhcp_wire.Ethernet_10mb
  ; hlen= 6
  ; hops= 0
  ; xid
  ; secs= 0
  ; flags= Dhcp_wire.Broadcast
  ; ciaddr= Ipaddr.V4.any
  ; yiaddr= Ipaddr.V4.any
  ; siaddr= Ipaddr.V4.any
  ; giaddr= Ipaddr.V4.any
  ; chaddr= mac
  ; sname= ""
  ; file= ""
  ; options=
      [
        Dhcp_wire.Message_type Dhcp_wire.DHCPDECLINE
      ; Dhcp_wire.Request_ip requested; Dhcp_wire.Server_identifier server
      ; Dhcp_wire.Client_id (Dhcp_wire.Hwaddr mac)
      ]
  }

let discover ?xid ~requests ~options mac =
  let xid = match xid with Some xid -> xid | None -> random_xid () in
  let client, discover = Dhcp_client.create ~requests ~options xid mac in
  let frame = frame_of_pkt discover in
  let dhcp =
    { client; outstanding= Some frame; lease= None; phase= Negotiating }
  in
  let outs = [ Send frame ] in
  (dhcp, outs)

let handle_conflict ~now ~mac dhcp ip mac' =
  match dhcp.lease with
  | Some lease when Ipaddr.V4.compare lease.Dhcp_wire.yiaddr ip = 0 ->
      Log.warn (fun m ->
          m "%a is also claimed by %a, declining the lease" Ipaddr.V4.pp ip
            Macaddr.pp mac');
      let server =
        match Dhcp_wire.find_server_identifier (opts lease) with
        | Some server -> server
        | None -> lease.Dhcp_wire.siaddr
      in
      let decl = decline ~xid:(random_xid ()) ~mac ~requested:ip ~server in
      let dhcp =
        {
          dhcp with
          lease= None
        ; outstanding= None
        ; phase= Backoff (now + decline_backoff)
        }
      in
      let outs = [ Send (frame_of_pkt decl); Revoke ] in
      (dhcp, outs)
  | Some _ | None ->
      (* NOTE(dinosaure): conflict too late! *)
      Log.debug (fun m ->
          m "ignoring conflict on %a (not our current lease)" Ipaddr.V4.pp ip);
      (dhcp, [])

let handle_new_lease ~now ~mac config dhcp ack =
  Log.debug (fun m -> m "received a new lease: %a" pp_lease ack);
  match config.on_lease ~previous:dhcp.lease ack with
  | Accept ->
      Log.info (fun m ->
          m "lease accepted: %a (gateway: %a)" Ipaddr.V4.Prefix.pp (cidr ack)
            Fmt.(option ~none:(any "none") Ipaddr.V4.pp)
            (gateway ack));
      let dhcp =
        {
          dhcp with
          lease= Some ack
        ; outstanding= None
        ; phase= Bound (now + renewal_delay ack)
        }
      in
      let outs = [ Apply ack ] in
      (dhcp, outs)
  | Reject ->
      Log.info (fun m ->
          m "lease rejected by the user, declining %a" Ipaddr.V4.pp
            ack.Dhcp_wire.yiaddr);
      let decl =
        decline ~xid:ack.Dhcp_wire.xid ~mac ~requested:ack.Dhcp_wire.yiaddr
          ~server:ack.Dhcp_wire.siaddr
      in
      let dhcp, outs =
        discover ~requests:config.requests ~options:config.options mac
      in
      (dhcp, Send (frame_of_pkt decl) :: outs)

let handle_frame ~now ~mac config dhcp cs =
  match Dhcp_client.input dhcp.client cs with
  | `Noop | `Not_dhcp -> (dhcp, [])
  | `Response (client, pkt) ->
      let frame = frame_of_pkt pkt in
      let outstanding = Some frame in
      let dhcp = { dhcp with client; outstanding; phase= Negotiating } in
      let outs = [ Send frame ] in
      (dhcp, outs)
  | `New_lease (client, ack) ->
      handle_new_lease ~now ~mac config { dhcp with client } ack

let handle_timeout ~mac config dhcp =
  match dhcp.phase with
  | Bound _ ->
      begin match Dhcp_client.renew dhcp.client with
      | `Response (client, pkt) ->
          Log.debug (fun m -> m "renewing the lease");
          let frame = frame_of_pkt pkt in
          let outstanding = Some frame in
          let dhcp = { dhcp with client; outstanding; phase= Negotiating } in
          let outs = [ Send frame ] in
          (dhcp, outs)
      | `Noop -> (dhcp, [])
      end
  | Negotiating ->
      begin match dhcp.outstanding with
      | Some frame -> (dhcp, [ Send frame ])
      | None -> (dhcp, [])
      end
  | Backoff _ ->
      Log.debug (fun m -> m "backoff expired, re-acquiring a configuration");
      discover ~requests:config.requests ~options:config.options mac

let transition ~now ~mac config dhcp = function
  | Frame cs -> handle_frame ~now ~mac config dhcp cs
  | Conflict (ip, mac') -> handle_conflict ~now ~mac dhcp ip mac'
  | Timeout -> handle_timeout ~mac config dhcp

let perform t = function
  | Send frame -> Ethernet.write_frame t.eth frame
  | Apply lease -> t.apply lease
  | Revoke -> t.revoke ()

let step t input =
  let now = now () in
  let dhcp, actions = transition ~now ~mac:t.mac t.config t.dhcp input in
  Log.debug (fun m ->
      m "%a: %a -> %a [@[<hov>%a@]]" pp_input input pp_phase t.dhcp.phase
        pp_phase dhcp.phase
        Fmt.(list ~sep:(any ",@ ") pp_action)
        actions);
  t.dhcp <- dhcp;
  List.iter (perform t) actions

let delay_of_phase t =
  match t.dhcp.phase with
  | Negotiating -> retransmit
  | Bound until | Backoff until ->
      let d = until - now () in
      if d < min_delay then min_delay else d

type event = Incoming of input Queue.t | Expired

let read_or_timeout ~delay t =
  let prm1 =
    Miou.async @@ fun () ->
    Miou.Mutex.protect t.mutex @@ fun () ->
    if Queue.is_empty t.queue then Miou.Condition.wait t.condition t.mutex;
    let queue = Queue.create () in
    Queue.transfer t.queue queue;
    Incoming queue
  in
  let prm0 = Miou.async @@ fun () -> Mkernel.sleep delay; Expired in
  match Miou.await_first [ prm0; prm1 ] with
  | Ok value -> value
  | Error exn ->
      Log.err (fun m -> m "unexpected exception: %s" (Printexc.to_string exn));
      Incoming (Queue.create ())

type daemon = unit Miou.t

let rec run t =
  match read_or_timeout ~delay:(delay_of_phase t) t with
  | Incoming queue ->
      Queue.iter (step t) queue;
      run t
  | Expired -> step t Timeout; run t

let create eth ~apply ~revoke ?xid config =
  let mac = Ethernet.macaddr eth in
  let dhcp, actions =
    discover ?xid ~requests:config.requests ~options:config.options mac
  in
  let t =
    {
      eth
    ; mac
    ; config
    ; apply
    ; revoke
    ; dhcp
    ; mutex= Miou.Mutex.create ()
    ; condition= Miou.Condition.create ()
    ; queue= Queue.create ()
    }
  in
  List.iter (perform t) actions;
  let daemon = Miou.async (fun () -> run t) in
  (daemon, t)

let is_dhcp_reply slice =
  Slice_bstr.length slice >= 28
  &&
  let ihl = Slice_bstr.get_uint8 slice 0 land 0x0f in
  let ip_hdr = ihl * 4 in
  ihl >= 5
  && Slice_bstr.length slice >= ip_hdr + 8
  && Slice_bstr.get_uint8 slice 9 = 17 (* UDP *)
  && Slice_bstr.get_uint16_be slice (ip_hdr + 2) = Dhcp_wire.client_port

let on_packet t (pkt : Slice_bstr.t Ethernet.packet) =
  match pkt.Ethernet.protocol with
  | Ethernet.IPv4 when is_dhcp_reply pkt.Ethernet.payload ->
      let { Slice.buf; off; len } = pkt.Ethernet.payload in
      (* off is the 14-byte Ethernet header; rebuild the full frame for
         [charrua], copying out of the shared receive buffer. *)
      let frame = Bstr.sub_string buf ~off:0 ~len:(off + len) in
      Miou.Mutex.protect t.mutex @@ fun () ->
      Queue.push (Frame (Cstruct.of_string frame)) t.queue;
      Miou.Condition.signal t.condition
  | _ -> Ethernet.uninteresting_packet ()

(* NOTE(dinosaure): this function is called from the ARP daemon (see
   [ARPv4.set_on_conflict]): handle the conflict into our DHCP daemon. *)
let conflict t ip mac =
  Miou.Mutex.protect t.mutex @@ fun () ->
  Queue.push (Conflict (ip, mac)) t.queue;
  Miou.Condition.signal t.condition

let current_lease t = t.dhcp.lease
let kill = Miou.cancel

module TCP = Mnet.TCP
module UDP = Mnet.UDP

let pp_error ppf = function
  | `MTU_too_small -> Fmt.string ppf "MTU too small"
  | `Exn exn -> Fmt.pf ppf "exception: %s" (Printexc.to_string exn)
  | `Destination_unreachable _ -> Fmt.string ppf "Destination unreachable"
  | `Packet_too_big -> Fmt.string ppf "Packet too big"

let ethernet_handler arpv4 ipv4 ipv6 =
  ();
  let handler pkt =
    match pkt.Ethernet.protocol with
    | Ethernet.ARPv4 -> ARPv4.transfer arpv4 pkt
    | Ethernet.IPv4 -> IPv4.input ipv4 pkt
    | Ethernet.IPv6 -> IPv6.input ipv6 pkt
  in
  handler

let ipv4_handler icmpv4 udp tcp =
  ();
  fun ((hdr, payload) as pkt) ->
    Log.debug (fun m ->
        m "receive IPv4 packet %a -> %a (protocol: %d)" Ipaddr.V4.pp
          hdr.IPv4.src Ipaddr.V4.pp hdr.IPv4.dst hdr.IPv4.protocol);
    match hdr.IPv4.protocol with
    | 1 -> ICMPv4.transfer icmpv4 pkt
    | 6 ->
        let payload =
          match payload with
          | IPv4.Slice slice ->
              let { Slice.buf; off; len } = slice in
              Bstr.sub ~off ~len buf
          | IPv4.String str -> Bstr.of_string str
        in
        let src = Ipaddr.V4 hdr.IPv4.src and dst = Ipaddr.V4 hdr.IPv4.dst in
        TCP.handler tcp src dst payload
    | 17 -> UDP.handler_ipv4 udp pkt
    | _ -> ()

let ipv6_handler ipv6 udp tcp =
  ();
  fun ~protocol src dst payload ->
    Log.debug (fun m ->
        m "receive IPv6 packet %a -> %a (protocol: %d)" Ipaddr.V6.pp src
          Ipaddr.V6.pp dst protocol);
    let payload =
      match payload with
      | IPv6.Slice slice ->
          let { Slice.buf; off; len } = slice in
          Bstr.sub ~off ~len buf
      | IPv6.String str -> Bstr.of_string str
    in
    match protocol with
    | 6 ->
        let src = Ipaddr.V6 src and dst = Ipaddr.V6 dst in
        TCP.handler tcp src dst payload
    | 17 -> UDP.handler_ipv6 udp src dst payload
    | 58 ->
        let len = Bstr.length payload in
        if len >= 8 then
          begin match Bstr.get_uint8 payload 0 with
          | 128 ->
              Log.debug (fun m ->
                  m "ICMPv6 Echo Request from %a" Ipaddr.V6.pp src);
              let src = dst and dst = src in
              let fn bstr =
                Bstr.set_uint8 bstr 0 129;
                Bstr.set_uint8 bstr 1 0;
                Bstr.set_uint16_be bstr 2 0;
                Bstr.blit payload ~src_off:4 bstr ~dst_off:4 ~len:(len - 4);
                let hdr = Bytes.create 40 in
                let src_octets = Ipaddr.V6.to_octets src in
                let dst_octets = Ipaddr.V6.to_octets dst in
                Bytes.blit_string src_octets 0 hdr 0 16;
                Bytes.blit_string dst_octets 0 hdr 16 16;
                Bytes.set_int32_be hdr 32 (Int32.of_int len);
                Bytes.set_int32_be hdr 36 58l;
                let hdr = Bytes.unsafe_to_string hdr in
                let payload = Bstr.sub_string bstr ~off:0 ~len in
                let chk = Utcp.Checksum.digest_strings [ hdr; payload ] in
                Bstr.set_uint16_be bstr 2 chk
              in
              let ok = Fun.id
              and error err =
                Log.warn (fun m ->
                    m "Impossible to pong %a: %a" Ipaddr.V6.pp dst pp_error err)
              in
              IPv6.write_directly ipv6 ~src dst ~protocol ~len fn
              |> Result.fold ~ok ~error
          | _ -> ()
          end
    | _ -> ()

type t = {
    ethd: Ethernet.daemon
  ; arpv4d: ARPv4.daemon
  ; icmpv4: ICMPv4.daemon
  ; udp: UDP.state
  ; ipv6d: IPv6.daemon
  ; tcpd: TCP.daemon
  ; dhcpd: daemon
  ; dhcp: state
  ; ipv4: IPv4.t
  ; ipv6: IPv6.t
}

let addresses t =
  let ipv4s = IPv4.addresses t.ipv4 in
  let ipv6s = IPv6.addresses t.ipv6 in
  let ipv4s = List.map (fun v -> Ipaddr.V4 v) ipv4s in
  let ipv6s = List.map (fun v -> Ipaddr.V6 v) ipv6s in
  List.rev_append ipv6s ipv4s

let current_lease t = current_lease t.dhcp
let tcp t = t.tcpd

let kill t =
  kill t.dhcpd;
  TCP.kill t.tcpd;
  IPv6.kill t.ipv6d;
  ICMPv4.kill t.icmpv4;
  ARPv4.kill t.arpv4d;
  Ethernet.kill t.ethd

let stack ~name ?(ipv6 = IPv6.EUI64) config =
  let fn (net, cfg) () =
    let connect mac =
      (* NOTE(dinosaure): see [Mnet.stack] to understand what we do here. *)
      let ( let* ) = Result.bind in
      let* ethd, eth = Ethernet.create ~mtu:cfg.Mkernel.Net.mtu mac net in
      let* arpv4d, arpv4 = ARPv4.create eth in
      let* ipv4 = IPv4.create eth arpv4 () in
      let* ipv6, ipv6d = IPv6.create eth ipv6 in
      let icmpv4 = ICMPv4.handler ipv4 in
      let tcpd, tcp = TCP.create ~name:"uniker.ml" ipv4 ipv6 in
      let udp = UDP.create ipv4 ipv6 in
      IPv4.set_handler ipv4 (ipv4_handler icmpv4 udp tcp);
      IPv6.set_handler ipv6 (ipv6_handler ipv6 udp tcp);
      let fn = ethernet_handler arpv4 ipv4 ipv6 in
      let ivar = Miou.Computation.create () in
      let apply lease =
        let cidr = cidr lease in
        IPv4.reconfigure ipv4 ?gateway:(gateway lease) cidr;
        ARPv4.set_ips arpv4 [ Ipaddr.V4.Prefix.address cidr ];
        ignore (Miou.Computation.try_return ivar lease)
      in
      let revoke () = IPv4.unconfigure ipv4; ARPv4.set_ips arpv4 [] in
      let dhcpd, dhcp = create eth ~apply ~revoke config in
      ARPv4.set_on_conflict arpv4 (conflict dhcp);
      (* NOTE(dinosaure): pre-shot DHCP packets, and then handle,
         as usual, IPv{4,6} and UDP/TCP packets. *)
      Ethernet.set_handler eth (on_packet dhcp);
      Ethernet.extend_handler_with eth fn;
      let stack =
        { ethd; arpv4d; icmpv4; udp; ipv6d; tcpd; dhcpd; dhcp; ipv4; ipv6 }
      in
      let lease = Miou.Computation.await_exn ivar in
      Ok (stack, tcp, udp, lease)
    in
    let mac = Macaddr.of_octets_exn (cfg.Mkernel.Net.mac :> string) in
    match connect mac with
    | Ok daemon -> daemon
    | Error err -> Fmt.failwith "%a" pp_error err
  in
  Mkernel.(map fn [ net name ])
