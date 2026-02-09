type l2 = { dst: Macaddr.t; len: int; fn: Bstr.t -> int }

type l3 = {
    src: Ipaddr.V6.t option
  ; dst: Ipaddr.V6.t
  ; protocol: int
  ; hop_limit: int
  ; len: int
  ; fn: Bstr.t -> int
}
