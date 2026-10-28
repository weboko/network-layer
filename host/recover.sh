#!/usr/bin/env bash
# Recovery helpers. Run on the VPS as root from the repository directory.
#
#   host/recover.sh status    what is loaded and running
#   host/recover.sh observe   stop blocking (record only); keeps explicit blocks
#   host/recover.sh open      remove all agentgw rules now (agents get plain
#                             Docker networking) and stop the gateway so it
#                             does not put them back
#   host/recover.sh restore   start the gateway again (re-applies the policy)
#
# None of these touch Docker's own chains, SSH, VPN or other containers:
# agentgw rules only ever match traffic on the agents bridge.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

case "${1:-status}" in
  status)
    if nft list table inet agentgw >/dev/null 2>&1; then
      if nft list set inet agentgw schema_v1 >/dev/null 2>&1; then
        echo "nftables: agentgw table loaded (gateway ruleset)"
      else
        echo "nftables: agentgw table loaded (boot fail-safe only: agents blocked)"
      fi
    else
      echo "nftables: no agentgw table (agents are NOT filtered)"
    fi
    docker compose ps
    docker compose exec -T controller python3 -m agentgw.admin status 2>/dev/null || echo "controller not reachable"
    ;;
  observe)
    docker compose exec -T controller python3 -m agentgw.admin mode observe
    ;;
  open)
    docker compose stop gateway
    nft delete table inet agentgw 2>/dev/null || true
    echo "agentgw rules removed; agents now have unfiltered Docker networking."
    echo "If the fail-safe unit is installed, the table returns at next boot (disable it to prevent that)."
    ;;
  restore)
    docker compose up -d gateway
    ;;
  *)
    sed -n '2,12p' "$0"
    exit 2
    ;;
esac
