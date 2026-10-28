#!/usr/bin/env bash
# Read-only inspection of a Docker host before installing agentgw. Changes nothing.
# Paste the output when asking for help with deployment.
set -uo pipefail

section() { printf '\n== %s ==\n' "$1"; }

section "system"
uname -r
. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"
echo "ipv6: $( [ -d /proc/sys/net/ipv6 ] && echo enabled || echo 'disabled in kernel')"
echo "ip_forward: $(cat /proc/sys/net/ipv4/ip_forward)"

section "docker"
docker version --format 'engine {{.Server.Version}} api {{.Server.APIVersion}}' 2>&1
docker info --format 'firewall backend: {{.FirewallBackend.Driver}}' 2>/dev/null || docker info 2>/dev/null | grep -i firewall
docker info --format 'cgroup {{.CgroupVersion}} / userland-proxy: see daemon.json' 2>/dev/null
[ -f /etc/docker/daemon.json ] && { echo "daemon.json:"; cat /etc/docker/daemon.json; }

section "netfilter"
iptables --version 2>&1
nft --version 2>&1
echo "nft tables:"; nft list tables 2>&1
echo "DOCKER-USER:"; iptables -S DOCKER-USER 2>&1 | head -20
systemctl is-enabled nftables.service 2>/dev/null | sed 's/^/nftables.service: /'
command -v ufw >/dev/null && ufw status | head -5
command -v firewall-cmd >/dev/null && firewall-cmd --state

section "docker networks"
docker network ls --format '{{.Name}}\t{{.Driver}}' | while IFS=$'\t' read -r n d; do
  sub=$(docker network inspect "$n" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null)
  br=$(docker network inspect "$n" --format '{{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null)
  printf '%-30s %-8s %-35s %s\n' "$n" "$d" "$sub" "$br"
done

section "containers (network mode, networks, dns)"
docker ps --format '{{.Names}}' | while read -r c; do
  docker inspect "$c" --format '{{.Name}}  mode={{.HostConfig.NetworkMode}}  nets={{range $k, $v := .NetworkSettings.Networks}}{{$k}}({{$v.IPAddress}}) {{end}} dns={{.HostConfig.Dns}} privileged={{.HostConfig.Privileged}} caps={{.HostConfig.CapAdd}}'
  docker inspect "$c" --format '{{range .Mounts}}{{if eq .Source "/var/run/docker.sock"}}  WARNING: docker.sock mounted (full host control, bypasses any network policy){{end}}{{end}}'
done

section "listeners on port 53 / 8080 / 8081"
ss -lntup 2>/dev/null | grep -E ':(53|8080|8081)\s' || echo "none"

section "vpn"
command -v tailscale >/dev/null && tailscale ip 2>/dev/null | head -2
ip -br link 2>/dev/null | grep -E 'wg|tailscale' || true
