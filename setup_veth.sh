#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (or via docker exec --privileged)" 
   exit 1
fi

ip link del veth0 2>/dev/null || true

echo "Setting up veth pair: veth0 <-> veth1"
ip link add veth0 type veth peer name veth1

echo "Bringing interfaces up"
ip link set veth0 up
ip link set veth1 up

echo "Veth setup complete."
echo "veth0: for ustack server"
echo "veth1: for ustack client"
