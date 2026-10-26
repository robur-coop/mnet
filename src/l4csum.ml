let offset = function 6 -> Some 16 | 17 -> Some 6 | _ -> None

let pseudo_v4 ~src ~dst ~protocol len =
  let buf = Bytes.make 12 '\000' in
  Bytes.set_int32_be buf 0 (Ipaddr.V4.to_int32 src);
  Bytes.set_int32_be buf 4 (Ipaddr.V4.to_int32 dst);
  Bytes.set_uint8 buf 9 protocol;
  Bytes.set_uint16_be buf 10 len;
  let str = Bytes.unsafe_to_string buf in
  Utcp.Checksum.feed_string ~off:0 ~len:12 0 str

let pseudo_v6 ~src ~dst ~protocol len =
  let buf = Bytes.make 40 '\000' in
  Bytes.blit_string (Ipaddr.V6.to_octets src) 0 buf 0 16;
  Bytes.blit_string (Ipaddr.V6.to_octets dst) 0 buf 16 16;
  Bytes.set_uint16_be buf 34 len;
  Bytes.set_uint8 buf 39 protocol;
  let str = Bytes.unsafe_to_string buf in
  Utcp.Checksum.feed_string ~off:0 ~len:40 0 str

let set_partial ~protocol ~sum bstr =
  match offset protocol with
  | Some off -> Bstr.set_uint16_be bstr off (Utcp.Checksum.fold sum)
  | None -> ()

let complete ~protocol bstr ~len =
  match offset protocol with
  | Some off ->
      let cs = Cstruct.of_bigarray ~off:0 ~len bstr in
      let chk = Utcp.Checksum.finally (Utcp.Checksum.feed_cstruct 0 cs) in
      Bstr.set_uint16_be bstr off chk
  | None -> ()
