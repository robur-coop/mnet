let src = Logs.Src.create "mnet"

module Log = (val Logs.src_log src : Logs.LOG)
module IPv4 = IPv4
module IPv6 = IPv6
module UDP = UDP
module TCP = TCP

let pp_error ppf = function
  | `MTU_too_small -> Fmt.string ppf "MTU too small"
  | `Exn exn -> Fmt.pf ppf "exception: %s" (Printexc.to_string exn)
  | `Destination_unreachable _ -> Fmt.string ppf "Destination unreachable"
  | `Packet_too_big -> Fmt.string ppf "Packet too big"

let ethernet_handler arpv4 ipv4 ipv6 =
  ();
  (* NOTE(dinosaure): about the handler and the packet received. The latter is
     in the form of a [Bstr.t] that physically corresponds to the [Bstr.t] used
     by Solo5. So to speak, from Solo5 to this [handler], there is no copy
     and the [Bstr.t] given is exclusive to the current task. However, as soon
     as this task is finished or would like to interact with the scheduler (and
     produce an effect), the guarantee of exclusivity is no longer assured.

     Depending on what you want to do, it may or may not be necessary to make a
     copy of this [Bstr.t].

     Currently, we can recognize a "happy-path" focus on TCP/IP. That is to say
     that upon receipt of a TCP/IP packet, we would like to go as far as
     possible without interruptions (like [Miou.yield] or any effects) to the
     TCP layer. In this case, the IPv4 handler has no effect, it just tries to
     reassemble packets it can depending on whether they are fragmented or not.
     In short, the happy path corresponds to the moment when IPv4 returns a
     packet in the form of a [Bstr.t] — that is to say that we have just
     obtained a non-fragmented and complete packet and this packet still
     physically corresponds to the one written by Solo5. Otherwise, [IPv4]
     returns a packet in the form of a [string] which means that it has been
     fragmented.

     This choice to return 2 types of payloads corresponds to a simple split: it
     is expensive to copy a [Bstr.t]. If we were to copy the [Bstr.t] given by
     [Ethernet], it is always more worthwhile to finally transform it into a
     [string] rather than "pretending that we still have a [Bstr.t]" underneath.
     This distinction also clarifies another point: ownership. If you are
     manipulating a [Bstr.t], you have to pay close attention to ownership and
     always consider this "happy path" (without interruptions). Otherwise, you
     can just manipulate the strings without asking yourself this question. *)
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
        (* NOTE(dinosaure): µTCP does not take the ownership on [cs] but it does
           a copy (to strings). It's safe to transmit our [slice] to
           [Utcp.handle_buf] and be interrupted by the scheduler. We also can
           think about a [Utcp.handle_buf_string] which can avoid our
           [Cstruct.of_string] (but IPv4.String appears only when we have
           fragmented packets and it's not common).

           The use of [Cstruct.t]/[Slice.t]/[Bigarray.Array1.t] is opportunistic
           and it permits to perform "fast" checksum validation. *)
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

let ipv6_handler ipv6 tcp =
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
    | 58 ->
        let len = Bstr.length payload in
        if len >= 8 then begin
          match Bstr.get_uint8 payload 0 with
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

type stack = {
    ethd: Ethernet.daemon
  ; arpv4d: ARPv4.daemon
  ; icmpv4: ICMPv4.daemon
  ; udp: UDP.state
  ; ipv6d: IPv6.daemon
  ; tcpd: TCP.daemon
  ; ipv4: IPv4.t
  ; ipv6: IPv6.t
}

let addresses t =
  let ipv4s = IPv4.addresses t.ipv4 in
  let ipv6s = IPv6.addresses t.ipv6 in
  let ipv4s = List.map (fun v -> Ipaddr.V4 v) ipv4s in
  let ipv6s = List.map (fun v -> Ipaddr.V6 v) ipv6s in
  List.rev_append ipv6s ipv4s

let kill t =
  TCP.kill t.tcpd;
  IPv6.kill t.ipv6d;
  ICMPv4.kill t.icmpv4;
  ARPv4.kill t.arpv4d;
  Ethernet.kill t.ethd

let stack ~name ?gateway ?(ipv6 = IPv6.EUI64) cidr =
  let fn (net, cfg) () =
    let connect mac =
      let ( let* ) = Result.bind in
      let* ethd, eth = Ethernet.create ~mtu:cfg.Mkernel.Net.mtu mac net in
      let ipaddr = Ipaddr.V4.Prefix.address cidr in
      let* arpv4d, arpv4 = ARPv4.create ~ipaddr eth in
      let* ipv4 = IPv4.create eth arpv4 ?gateway cidr in
      let* ipv6, ipv6d = IPv6.create eth ipv6 in
      let icmpv4 = ICMPv4.handler ipv4 in
      let tcpd, tcp = TCP.create ~name:"uniker.ml" ipv4 ipv6 in
      let udp = UDP.create ipv4 ipv6 in
      IPv4.set_handler ipv4 (ipv4_handler icmpv4 udp tcp);
      IPv6.set_handler ipv6 (ipv6_handler ipv6 tcp);
      let fn = ethernet_handler arpv4 ipv4 ipv6 in
      Ethernet.set_handler eth fn;
      let stack = { ethd; arpv4d; udp; icmpv4; ipv6d; tcpd; ipv4; ipv6 } in
      Ok (stack, tcp, udp)
    in
    let mac = Macaddr.of_octets_exn (cfg.Mkernel.Net.mac :> string) in
    match connect mac with
    | Ok daemon -> daemon
    | Error err -> Fmt.failwith "%a" pp_error err
  in
  Mkernel.(map fn [ net name ])
