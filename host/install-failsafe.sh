#!/usr/bin/env bash
# Installs the boot-time fail-closed rules (optional, recommended).
#
# What it changes on the host:
#   /etc/agentgw/failsafe.nft                   new file
#   /etc/systemd/system/agentgw-failsafe.service new unit, enabled (runs at boot)
# It does NOT load anything now: the running gateway already owns the table.
# Undo: systemctl disable agentgw-failsafe && rm -r /etc/agentgw /etc/systemd/system/agentgw-failsafe.service
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
nft -c -f agentgw-failsafe.nft   # syntax check only
install -d /etc/agentgw
install -m 0644 agentgw-failsafe.nft /etc/agentgw/failsafe.nft
install -m 0644 agentgw-failsafe.service /etc/systemd/system/agentgw-failsafe.service
systemctl daemon-reload
systemctl enable agentgw-failsafe.service
echo "installed; agents on br-agents get no new outbound connections at boot until the gateway starts"
