#!/bin/bash
set -e

ip link add veth0 type veth peer name veth1

ip link set veth0 up
ip link set veth1 up

# Set MTU to 9000 to support Jumbo Frames testing
ip link set veth0 mtu 9000
ip link set veth1 mtu 9000

ethtool -K veth0 tx off rx off gso off tso off gro off
ethtool -K veth1 tx off rx off gso off tso off gro off

sysctl -w net.ipv6.conf.veth0.disable_ipv6=1
sysctl -w net.ipv6.conf.veth1.disable_ipv6=1

echo "Veth pair created: veth0 <-> veth1"
ip link show veth0
ip link show veth1
