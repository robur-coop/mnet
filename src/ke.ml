let failwithf fmt = Format.kasprintf failwith fmt
let invalid_argf fmt = Format.kasprintf invalid_arg fmt

type t = {
    mutable rd: int
  ; mutable wr: int
  ; mutable ln: int
  ; mutable buf: bytes
  ; limit: int option
}

let unsafe_create ?(limit = Some 0x2000) ln =
  { rd= 0; wr= 0; ln; buf= Bytes.create ln; limit }

let is_power_of_two x = x <> 0 && x land (lnot x + 1) = x

let create ?(limit = Some 0x2000) ln =
  if not (is_power_of_two ln) then
    invalid_argf "Ke.create: invalid length (it must be a power of two)";
  let fn limit =
    if (not (is_power_of_two limit)) || limit <= ln then
      invalid_argf
        "Ke.create: invalid limit (it must be a power of two and greater than \
         the initial size"
  in
  Option.iter fn limit; unsafe_create ~limit ln

let mask t v = v land (t.ln - 1)
let unsafe_shift t len = t.rd <- t.rd + len
let available t = t.ln - (t.wr - t.rd)
let length t = t.wr - t.rd

let shift t len =
  if t.rd + len > t.wr then invalid_argf "Ke.shift: you are going to far";
  unsafe_shift t len

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
  else if t.rd != 0 then Bytes.blit t.buf mask t.buf 0 len;
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

let max_ke_length =
  let rec go n = if n lsl 1 > Sys.max_string_length then n else go (n lsl 1) in
  go 1

let grow t want =
  let ln = to_power_of_two (Int.max 1 (Int.max want (length t))) in
  if ln <> Bytes.length t.buf && ln <= max_ke_length then begin
    if Option.fold ~none:false ~some:(fun limit -> ln > limit) t.limit then
      failwithf "Ke.grow: the buffer exceeds our limit (%d byte(s))"
        (Option.value ~default:0 t.limit);
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
  else if ln > max_ke_length then
    failwith "Ke.grow: cannot grow buffer (max queue length reached)"

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

let peek_into t fn =
  match length t with
  | 0 -> ()
  | len ->
      let mask = mask t t.rd in
      let pre = t.ln - mask in
      let rem = len - pre in
      if rem > 0 then begin
        fn t.buf ~off:mask ~len:pre;
        fn t.buf ~off:0 ~len:rem
      end
      else fn t.buf ~off:mask ~len

let peek_into_bytes t ?(off = 0) ?len dst =
  let dst_off = ref off in
  let dst_len =
    match len with Some len -> ref len | None -> ref (Bytes.length dst - off)
  in
  let fn src ~off:src_off ~len:src_len =
    if !dst_len > 0 then begin
      let len = Int.min !dst_len src_len in
      Bytes.blit src src_off dst !dst_off len;
      dst_off := !dst_off + len;
      dst_len := !dst_len - len
    end
  in
  peek_into t fn; !dst_off - off
