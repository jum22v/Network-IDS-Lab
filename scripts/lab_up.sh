#!/usr/bin/env bash
set -euo pipefail
# Reserve these names for this lab. Refuse to alter an existing setup.
for ns in ids-client ids-server; do
  if sudo ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
    echo "$ns already exists. Inspect/reuse it, or run lab_down.sh first."
    exit 1
  fi
done
sudo modprobe veth
sudo ip netns add ids-client
sudo ip netns add ids-server
sudo ip link add veth-client type veth peer name veth-server
sudo ip link set veth-client netns ids-client
sudo ip link set veth-server netns ids-server
sudo ip -n ids-client addr add 10.200.1.1/24 dev veth-client
sudo ip -n ids-server addr add 10.200.1.2/24 dev veth-server
sudo ip -n ids-client link set lo up
sudo ip -n ids-server link set lo up
sudo ip -n ids-client link set veth-client up
sudo ip -n ids-server link set veth-server up
sudo ip netns exec ids-client ping -c 4 10.200.1.2
