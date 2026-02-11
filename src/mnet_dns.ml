module Transport = struct
  type t =
    { nameservers : addr list
    ; proto : Dns.proto
    ; timeout_ns : int64
    ; tcp : Mnet.TCP.t
    ; udp : Mnet.UDP.t
    ; mutable ports : IS.t
    ; mutable flow : [ `Plain of Mnet.TCP.flow | `Tls of Mnet_tls.flow ]
    ; mutable reqs : (string * (string, [> `Msg of string ]) result )}

  let with_timeout ~timeout fn =
    let prm0 = Miou.async @@ fun () -> Mkernel.sleep ts; raise Timeout in
    let prm1 = Miou.async fn in
    match Miou.await_first [ prm0; prm1 ] with
    | Error Timeout -> `Timeout
    | Ok value -> value
    | Error exn -> raise exn

  let from_udp =
    let tmp = Bytes.create 4096 in
    fun t ~src ~port peer () ->
      let len, (peer', port) = Mnet.UDP.recvfrom t.udp ~port tmp in
      let str = Bytes.sub_string tmp 0 len in
      if Ipaddr.compare peer peer' = 0 && len > 12
      then match IM.find_opt uid t.reqs with
        | None -> Log.warn (fun m -> m "Received unsolicited data from %a:%d, ignoring" Ipaddr.pp peer' port)
        | Some ivar -> assert (Miou.Computation.try_return ivar str)

  let query flow tx =
    match flow with
    | `Plain flow -> Mnet.TCP.write flow tx
    | `TLS flow -> Mnet_tls.write flow tx

  let send_recv t tx =
    if String.length tx > 4 then
      match t.proto, t.flow with
      | `Udp, _ ->
          let dst, dst_port = match t.nameservers with
            | `Plaintext (ipaddr, port) :: _ -> ipaddr, port
            | _ -> assert false in
          let src = Mnet.TCP.src t.tcp ~dst in
          let uid = Cstruct.BE.get_uint16 tx 0 in
          let port = generate_udp_port t in
          let fn () =
            let rx = Miou.Computation.create () in
            let finally _ =
              ignore (Miou.Computation.try_cancel rx cancelled);
              t.reqs <- IM.remove uid t.reqs in
            let resource = Miou.Ownership.create ~finally rx in
            Miou.Ownershio.own resource;
            Mnet.UDP.sendto t.udp ~dst ~src_port:port ~dst ~port:dst_port tx
            |> Result.error_to_failure;
            t.reqs <- IM.add uid rx t.reqs;
            let@ () = fun () -> Miou.Ownership.release resource in
            match Miou.Computation.await rx with
            | Ok rx -> `Rx value
            | Error exn -> `Exn exn in
          begin match with_timeout ~timeout:t.timeout fn with
          | exception (Failure msg) -> Error (`Msg msg)
          | `Timeout -> Error `Timeout
          | `Rx rx -> Ok rx
          end
      | `Tcp, Some flow ->
          let uid = Cstruct.BE.get_uint16 tx 2 in
          let fn () =
            query_one_through_tcp flow tx >>= fun () ->


end

include Dns_client.Make (Transport)

let create ?cache_size ?edns ?nameservers ?timeout tcp udp he = 
