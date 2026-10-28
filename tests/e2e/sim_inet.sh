#!/usr/bin/env bash
# Simulated "internet" for end-to-end tests: a network namespace reachable via
# a routed veth, so agent traffic takes the real FORWARD path of the host.
#   203.0.113.0/24 (TEST-NET-3) addresses live in the namespace.
#   203.0.113.53 is an authoritative DNS server for *.test names.
# Usage: sim_inet.sh up|down
set -euo pipefail
NS=agw-inet
HERE="$(cd "$(dirname "$0")" && pwd)"

up() {
  ip netns add $NS
  ip link add agwsim0 type veth peer name agwsim1
  ip link set agwsim1 netns $NS
  ip addr add 10.254.0.1/30 dev agwsim0
  ip link set agwsim0 up
  ip netns exec $NS ip addr add 10.254.0.2/30 dev agwsim1
  ip netns exec $NS ip link set agwsim1 up
  ip netns exec $NS ip link set lo up
  for i in $(seq 10 20) 53; do ip netns exec $NS ip addr add 203.0.113.$i/32 dev lo; done
  ip netns exec $NS ip route add default via 10.254.0.1
  ip route add 203.0.113.0/24 via 10.254.0.2
  sysctl -qw net.ipv4.ip_forward=1
  ip netns exec $NS python3 "$HERE/sim_servers.py" >/tmp/agw-sim.log 2>&1 &
  echo $! > /tmp/agw-sim.pid
  sleep 1
}

down() {
  [ -f /tmp/agw-sim.pid ] && kill "$(cat /tmp/agw-sim.pid)" 2>/dev/null || true
  rm -f /tmp/agw-sim.pid
  ip route del 203.0.113.0/24 2>/dev/null || true
  ip link del agwsim0 2>/dev/null || true
  ip netns del $NS 2>/dev/null || true
}

"$1"
