#!/usr/bin/env bash
# One-time setup: create the agents network and .env. Idempotent; changes
# nothing on the host firewall (the gateway does that when it starts).
set -euo pipefail
cd "$(dirname "$0")/.."

NETWORK="${AGENTGW_NETWORK:-agentgw-agents}"
BRIDGE="${AGENTGW_BRIDGE:-br-agents}"
SUBNET4="${AGENTGW_SUBNET4:-172.30.0.0/24}"
GW4="${AGENTGW_GW4:-172.30.0.1}"
SUBNET6="${AGENTGW_SUBNET6:-}"

if docker network inspect "$NETWORK" >/dev/null 2>&1; then
  echo "network $NETWORK exists"
else
  args=(--driver bridge --subnet "$SUBNET4" --gateway "$GW4"
        -o "com.docker.network.bridge.name=$BRIDGE"
        --label agentgw.managed=true)
  if [ -n "$SUBNET6" ]; then
    args+=(--ipv6 --subnet "$SUBNET6")
  fi
  docker network create "${args[@]}" "$NETWORK"
  echo "created network $NETWORK (bridge $BRIDGE, $SUBNET4, gateway $GW4${SUBNET6:+, $SUBNET6})"
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "created .env from .env.example"
fi
gid="$(stat -c %g /var/run/docker.sock)"
if grep -q '^DOCKER_GID=' .env; then
  sed -i "s/^DOCKER_GID=.*/DOCKER_GID=$gid/" .env
else
  echo "DOCKER_GID=$gid" >> .env
fi

echo
echo "Next: docker compose up -d --build"
echo "Dashboard: ssh -L 8080:127.0.0.1:8080 <this host>, then open http://127.0.0.1:8080/"
