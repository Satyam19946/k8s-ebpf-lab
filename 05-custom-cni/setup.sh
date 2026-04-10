#!/bin/bash
set -e

echo "==> creating testpod network namespace"
ip netns add testpod

echo "==> creating veth pair"
ip link add vethabc123de type veth peer name eth0

echo "==> moving eth0 into testpod"
ip link set eth0 netns testpod

echo "==> assigning gateway IP to host-side veth"
ip addr add 10.244.1.1/32 dev vethabc123de

echo "==> bringing host-side veth up"
ip link set vethabc123de up

echo "==> configuring pod-side interface"
ip netns exec testpod ip addr add 10.244.1.2/24 dev eth0
ip netns exec testpod ip link set eth0 up
ip netns exec testpod ip link set lo up
ip netns exec testpod ip route add default via 10.244.1.1

echo "==> adding host route to pod IP"
ip route add 10.244.1.2/32 dev vethabc123de

echo "==> enabling proxy ARP on vethabc123de"
sysctl -w net.ipv4.conf.vethabc123de.proxy_arp=1

echo "==> adding route for ClusterIP VIP"
ip route add 10.96.0.10/32 dev lo

echo "==> done. current state:"
echo "--- host interfaces ---"
ip link show vethabc123de
echo "--- host routes ---"
ip route show | grep -E "10.244|10.96"
echo "--- pod interfaces ---"
ip netns exec testpod ip addr
echo "--- pod routes ---"
ip netns exec testpod ip route