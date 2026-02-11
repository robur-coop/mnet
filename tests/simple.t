  $ sudo ip link add name service type bridge
  $ sudo ip addr add 10.0.0.1/24 dev service
  $ sudo ip tuntap add name tap0 mode tap
  $ sudo ip tuntap add name tap1 mode tap
  $ sudo ip link set tap0 master service
  $ sudo ip link set tap1 master service
  $ sudo ip link set service up
  $ sudo ip link set tap0 up
  $ sudo ip link set tap1 up
  $ solo5-hvt --net:service=tap0 -- echo.hvt --solo5:quiet server --ipv4=10.0.0.2/24 --limit 2 &
  $ SERVER=$!
  $ solo5-hvt --net:service=tap1 -- echo.hvt --solo5:quiet client --ipv4=10.0.0.3/24 10.0.0.2 &
  $ CLIENT=$!
  $ wait $CLIENT
  $ solo5-hvt --net:service=tap1 -- echo.hvt --solo5:quiet client --ipv4=10.0.0.3/24 10.0.0.2 65536 &
  $ CLIENT=$!
  $ wait $CLIENT
  $ wait $SERVER
  $ sudo ip link del name service type bridge
  $ sudo ip tuntap del name tap0 mode tap
  $ sudo ip tuntap del name tap1 mode tap
