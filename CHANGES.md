### v0.0.5 (2026-08-28)

- We can close multiple times a TCP connection (@dinosaure, @hannesm,
  [!47][47])
- Use warning names instead of numbers (@hannesm, [!46][46])
- Remove doublon about Ethernet.mac{,addr} (spotted by @hannesm, @dinosaure,
  [!48][48])
- Fix how we select our router on IPv6 (@reynir, [!51][51])
- Upgrade `mnet` with `mkernel.0.0.4` (@hannesm, [!53][53])
- Use `Mkernel.finally` to finalize our daemon (@dinosaure, @reynir, [!54][54])
- Sync OPAM files with dune dependencies (@hannesm, [!55][55])
- Move command-line helpers to their own packages (@hannesm, @dinosaure,
  [!56][56])
- Introduce the new module `Mnet_dhcp.Or_static` which mix DHCP and our TCP/IP
  stack (@reynir, @hannesm, [!52][52])
- Be able to specify its own IPv6 gateway (instead of get them from RA)
  (@reynir, @hannesm, [!50][50])
- Improve the API of `Mnet.TCP` and provide a buffered flow and a direct flow

  **breaking change**
  `TCP.get` is renamed to `TCP.read` and
  `TCP.{really_,}read` to `TCP.{really_,}input`.

  (@dinosaure, @hannesm, [!58][58])
- Improve a bit our `mnet-dns` implementation and our interface (@dinosaure,
  [!59][59])

[46]: https://git.robur.coop/robur/mnet/pulls/46
[47]: https://git.robur.coop/robur/mnet/pulls/47
[48]: https://git.robur.coop/robur/mnet/pulls/48
[50]: https://git.robur.coop/robur/mnet/pulls/50
[51]: https://git.robur.coop/robur/mnet/pulls/51
[52]: https://git.robur.coop/robur/mnet/pulls/52
[53]: https://git.robur.coop/robur/mnet/pulls/53
[54]: https://git.robur.coop/robur/mnet/pulls/54
[55]: https://git.robur.coop/robur/mnet/pulls/55
[56]: https://git.robur.coop/robur/mnet/pulls/56
[58]: https://git.robur.coop/robur/mnet/pulls/58
[59]: https://git.robur.coop/robur/mnet/pulls/59

### v0.0.4 (2026-07-30)

- Add the support of DHCP and the new package `mnet-dhcp` (@dinosaure, @reynir,
  [!34][34])
- Add a basic implementation of the SSH client (@dinosaure, [!33][33])
- Fix the compilation for OCaml 5.5 (@dinosaure, @kit-ty-kate, [!36][36],
  [#3][g3])
- Use `Miou.Mutex.protect` when we want to signal a `Notify.t` value
  (@dinosaure, [!35][35])
- Replace our internal `Bstr.t` by bytes when it's about buffering on the TCP 
  stack (@dinosaure, [!38][38])
- Use the new interface of `utcp.0.0.6` (@dinosaure, [!38][38])
- Add `?ip` on `Mnet_tls.client_of_fd` (@hannesm, [!40][40])
- Add a hard limit for incoming passive TCP connections (@dinosaure, @hannesm,
  [!42][42])
- Improve throughput for `mnet-tls` (@dinosaure, @hannesm, [!39][39])
- Fix how we handle active connection and use `utcp.0.0.7` (@dinosaure,
  @hannesm, [!43][43])

[34]: https://git.robur.coop/robur/mnet/pulls/34
[33]: https://git.robur.coop/robur/mnet/pulls/33
[36]: https://git.robur.coop/robur/mnet/pulls/36
[g3]: https://github.com/robur-coop/mnet/issues/3
[38]: https://git.robur.coop/robur/mnet/pulls/38
[40]: https://git.robur.coop/robur/mnet/pulls/40
[42]: https://git.robur.coop/robur/mnet/pulls/42
[39]: https://git.robur.coop/robur/mnet/pulls/39
[43]: https://git.robur.coop/robur/mnet/pulls/43

### v0.0.3 (2026-06-09)

- Minor simplification of `mnet-tls` about handshake (@hannesm, [!28][28])
- Improve `mnet-cli` (add `setup_logs`) (@dinosaure, [!30][30])
- Be able to return the TCP daemon (and be able to kill it)
  (@dinosaure, [!31][30])
- Add a new `mnet-ssh` package which implements SSH for unikernels
  (@dinosaure, [!29][29])

[28]: https://git.robur.coop/robur/mnet/pulls/28
[29]: https://git.robur.coop/robur/mnet/pulls/29
[30]: https://git.robur.coop/robur/mnet/pulls/30
[31]: https://git.robur.coop/robur/mnet/pulls/31

### v0.0.2 (2026-05-06)

- Improve our unikernel example and our resolver, it's able to take a
  domain-name as an argument (@hannesm, [!14][14])
- Improve our IPv4 routing (@hannes, @reynir, @dinosaure, [!16][16])
- Improve `mnet-cli` and add titles for some options (@dinosaure, [!17][17])
- Catch exceptions when we read on TCP and/or TLS connections for DNS packets
  (@dinosaure, [!18][18])
- Fix how we try to instantiate a connection to nameservers (@dinosaure,
  @hannesm, [!19][19])
- Fix how we push new happy-eyeballs actions (@dinosaure, [!20][20])
- Add options for happy-eyeballs (@dinosaure, [!22][22])
- Fix our `mnet-tls` implementation and pass a flow after its handshake even if
  the flow was closed (on read and write side) (@dinosaure, [!23][23])
- Try to send TCP packets from our TCP timer directly without interruptions
  instead of push it into our queue (@dinosaure, [!24][24])
- Be able to resolve domain-name into our happy-eyeballs implementation
  (@dinosaure, [!25][25])
- Fix our `mnet-dns` implementation:
  + we fix how we read DNS packet from TCP and/or TLS connections
  + we fix how we try to instantiate a new connection to nameservers

  (@dinosaure, [!26][26])

[14]: https://git.robur.coop/robur/mnet/pulls/14
[16]: https://git.robur.coop/robur/mnet/pulls/16
[17]: https://git.robur.coop/robur/mnet/pulls/17
[18]: https://git.robur.coop/robur/mnet/pulls/18
[19]: https://git.robur.coop/robur/mnet/pulls/19
[20]: https://git.robur.coop/robur/mnet/pulls/20
[22]: https://git.robur.coop/robur/mnet/pulls/22
[23]: https://git.robur.coop/robur/mnet/pulls/23
[24]: https://git.robur.coop/robur/mnet/pulls/24
[25]: https://git.robur.coop/robur/mnet/pulls/25
[26]: https://git.robur.coop/robur/mnet/pulls/26

### v0.0.1 (2026-02-17)

- First public release of `mnet`
