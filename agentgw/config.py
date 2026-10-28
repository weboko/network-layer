"""Static configuration from environment variables.

Runtime-changeable settings (mode, DNS behaviour, ...) live in the database, see
db.DEFAULT_SETTINGS. Everything here requires a restart to change because it
describes the network layout the nftables ruleset is built around.
"""

import ipaddress
import os
from dataclasses import dataclass, field


def _env(name, default):
    return os.environ.get(name, default)


def _resolv_conf_servers(path="/etc/resolv.conf"):
    servers = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    return servers


@dataclass
class Config:
    data_dir: str
    bridge: str
    network: str
    subnet4: ipaddress.IPv4Network
    gw4: ipaddress.IPv4Address
    subnet6: ipaddress.IPv6Network | None
    gw6: ipaddress.IPv6Address | None
    upstream_dns: list = field(default_factory=list)
    dns_port: int = 53
    agent_api_port: int = 8081
    admin_listen: str = "127.0.0.1:8080"
    admin_token: str = ""
    admin_hosts: list = field(default_factory=list)
    docker_sock: str = ""
    poll_interval: float = 2.0

    @property
    def db_path(self):
        return os.path.join(self.data_dir, "agentgw.db")


def load():
    subnet4 = ipaddress.IPv4Network(_env("AGENTGW_SUBNET4", "172.30.0.0/24"))
    gw4 = ipaddress.IPv4Address(_env("AGENTGW_GW4", str(next(subnet4.hosts()))))
    s6 = _env("AGENTGW_SUBNET6", "")
    subnet6 = ipaddress.IPv6Network(s6) if s6 else None
    g6 = _env("AGENTGW_GW6", "")
    gw6 = ipaddress.IPv6Address(g6) if g6 else (next(subnet6.hosts()) if subnet6 else None)
    upstream = [s for s in _env("AGENTGW_UPSTREAM_DNS", "").replace(",", " ").split() if s]
    if not upstream:
        # The gateway runs in the host network namespace, so the host's resolvers
        # (including a systemd-resolved stub on 127.0.0.53) are reachable.
        upstream = _resolv_conf_servers() or ["1.1.1.1", "8.8.8.8"]
    listen = _env("AGENTGW_ADMIN_LISTEN", "127.0.0.1:8080")
    hosts = [h for h in _env("AGENTGW_ADMIN_HOSTS", "").replace(",", " ").split() if h]
    return Config(
        data_dir=_env("AGENTGW_DATA", "/var/lib/agentgw"),
        bridge=_env("AGENTGW_BRIDGE", "br-agents"),
        network=_env("AGENTGW_NETWORK", "agentgw-agents"),
        subnet4=subnet4,
        gw4=gw4,
        subnet6=subnet6,
        gw6=gw6,
        upstream_dns=upstream,
        dns_port=int(_env("AGENTGW_DNS_PORT", "53")),
        agent_api_port=int(_env("AGENTGW_AGENT_API_PORT", "8081")),
        admin_listen=listen,
        admin_token=_env("AGENTGW_ADMIN_TOKEN", ""),
        admin_hosts=hosts,
        docker_sock=_env("AGENTGW_DOCKER_SOCK", "/run/agentgw-docker/docker.sock"),
        poll_interval=float(_env("AGENTGW_POLL_INTERVAL", "2")),
    )
