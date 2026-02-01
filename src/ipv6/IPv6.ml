module Packet = struct
  let unsafe_hdr_into ?(hop_limit = 64) src dst ~protocol ?(off = 0) bstr =
    Bstr.set_int32_be bstr (off + 0) 0x60000000l;
    Bstr.set_uint16_be bstr (off + 4) 0;
    Bstr.set_uint8 bstr (off + 6) protocol;
    Bstr.set_uint8 bstr (off + 7) hop_limit;
    let src = Ipaddr.V6.to_string src in
    Bstr.blit_from_string src ~src_off:0 bstr ~dst_off:(off + 8) ~len:16;
    let dst = Ipaddr.V6.to_string dst in
    Bstr.blit_from_string dst ~src_off:0 bstr ~dst_off:(off + 24) ~len:16
end

let ( let* ) = Result.bind

type t = { ndpv6: NDPv6.t }

let segment_and_coalesce ~mtu seq =
  (* NOTE(dinosaure): Here, the objective is to segment by chunks of [mtu - 48]
     bytes and coalesce what we are given. Then, we can introspect the returned
     [seq] to determine whether we should actually fragment (and send IPv6
     packets, 40 bytes, plus the 8-byte extension and payloads, everything is
     aligned) or simply send a single packet. *)
  let max = mtu - 48 in
  let rec go rem seq : _ Seq.t =
   fun () ->
    match seq () with
    | Seq.Nil when rem = "" -> Seq.Nil
    | Seq.Nil ->
        assert (String.length rem <= max);
        Seq.Cons (rem, Seq.empty)
    | Seq.Cons (str, next) ->
        let rem = rem ^ str in
        let len = String.length rem in
        if len = 0 then go String.empty next ()
        else if len <= max then go rem next ()
        else
          let chunk = String.sub rem 0 max in
          let rem = String.sub rem max (len - max) in
          Seq.Cons (chunk, go rem next)
  in
  go String.empty seq

let to_chunks ~mtu seq =
  let seq = segment_and_coalesce ~mtu seq in
  match seq () with
  | Seq.Nil -> None (* nothing to encode *)
  | Seq.Cons (x0, rem) -> begin
      assert (String.length x0 <= mtu - 48);
      match rem () with
      | Seq.Nil ->
          (* no fragmentation *)
          let len = String.length x0 in
          let fn bstr =
            Bstr.blit_from_string x0 ~src_off:0 bstr ~dst_off:0 ~len;
            len
          in
          Some (Seq.singleton fn)
      | Seq.Cons (x1, rem) when String.length x1 <= 8 && Seq.is_empty rem ->
          (* no fragmentation *)
          let len0 = String.length x0 in
          let len1 = String.length x1 in
          let fn bstr =
            Bstr.blit_from_string x0 ~src_off:0 bstr ~dst_off:0 ~len:len0;
            Bstr.blit_from_string x1 ~src_off:0 bstr ~dst_off:len0 ~len:len1;
            len0 + len1
          in
          Some (Seq.singleton fn)
      | Seq.Cons (x1, rem) ->
          (* fragmentation *)
          let seq = Seq.cons x0 (Seq.cons x1 rem) in
          let fn str =
            let len = String.length str in
            assert (len <= mtu - 48);
            let fn bstr =
              Bstr.blit_from_string str ~src_off:0 bstr ~dst_off:0 ~len;
              len
            in
            fn
          in
          Some (Seq.map fn seq)
    end

let into ~mtu ~protocol ~len user's_fn =
  if len > mtu - 40 then begin
    let bstr = Bstr.create len in
    let tmp = Bytes.create 4 in
    Mirage_crypto_rng.generate_into tmp ~off:0 4;
    let uid = Bytes.get_int32_ne tmp 0 in
    let len' = user's_fn bstr in
    assert (len = len');
    let max = mtu - 48 in
    let rec go acc src_off =
      if src_off - len <= 0 then List.rev acc
      else
        let filler dst =
          assert (Bstr.length dst >= max);
          let len = Int.min max (len - src_off) in
          let last = if src_off - len <= 0 then true else false in
          Bstr.set_uint8 dst 0 protocol;
          Bstr.set_uint8 dst 1 0;
          Bstr.set_uint16_be dst 2 0;
          Bstr.set_int32_be dst 4 uid;
          Bstr.blit bstr ~src_off:8 dst ~dst_off:0 ~len;
          len + 8
        in
        let size = Int.min max (len - src_off) in
        go ({ NDPv6.size; filler } :: acc) (src_off + max)
    in
    go [] 0
  end
  else [ { NDPv6.size= len; filler= user's_fn } ]

let write t ~now ?src dst ~protocol ~len user's_fn =
  let src = match src with Some src -> src | None -> NDPv6.src t.ndpv6 dst in
  let* ndpv6, next_hop, mtu = NDPv6.next_hop t.ndpv6 dst in
  match mtu with
  | None ->
      (* NOTE(dinosaure): we try with MTU=Link-MTU (generally, 1500). However,
         this PMTU may fail for the intended destination. The only valid PMTU in
         all cases is 1280. *)
      let mtu = t.lmtu in
      let pkts = into ~mtu ~protocol ~len user's_fn in
      let ndpv6, outs = NDPv6.send t.ndpv6 ~now next_hop pkts in
      assert false
  | Some mtu ->
      let pkts = into ~mtu ~protocol ~len user's_fn in
      let ndpv6, outs = NDPv6.send t.ndpv6 ~now next_hop pkts in
      assert false
