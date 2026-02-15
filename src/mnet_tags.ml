let mac = Logs.Tag.def ~doc:"MAC address" "mnet.mac" Macaddr.pp
let ipv4 = Logs.Tag.def ~doc:"IPv4 address" "mnet.ipv4" Ipaddr.V4.Prefix.pp
let ip = Logs.Tag.def ~doc:"IP address" "mnet.ip" Ipaddr.Prefix.pp
let pp_peer ppf (ipaddr, port) = Fmt.pf ppf "%a:%d" Ipaddr.pp ipaddr port
let tcp = Logs.Tag.def ~doc:"IP and port of a TCP peer" "mnet.tcp" pp_peer
