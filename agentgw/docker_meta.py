"""Read-only Docker metadata for attributing traffic to containers.

The gateway talks to a filtering socket proxy (GET on the agents network and
on container inspect only), never to the Docker socket itself.
"""

import http.client
import json
import socket


class _UnixConn(http.client.HTTPConnection):
    def __init__(self, path, timeout=5):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.path)
        self.sock = s


def _get(sock_path, url):
    c = _UnixConn(sock_path)
    try:
        c.request("GET", url)
        r = c.getresponse()
        body = r.read()
        if r.status != 200:
            raise OSError(f"docker API {url}: HTTP {r.status} {body[:200]!r}")
        return json.loads(body)
    finally:
        c.close()


def agent_containers(sock_path, network, gw_ips):
    """{ip: {"name", "cid", "warnings": [...], "networks": [...], "dns": [...]}}"""
    net = _get(sock_path, f"/networks/{network}")
    out = {}
    for cid, c in (net.get("Containers") or {}).items():
        info = {"name": c.get("Name", cid[:12]), "cid": cid[:12], "warnings": [], "networks": [], "dns": []}
        try:
            insp = _get(sock_path, f"/containers/{cid}/json")
            nets = list((insp.get("NetworkSettings") or {}).get("Networks", {}).keys())
            dns = (insp.get("HostConfig") or {}).get("Dns") or []
            info.update(networks=nets, dns=dns)
            others = [n for n in nets if n != network]
            if others:
                info["warnings"].append(
                    "also attached to " + ", ".join(others) + ": traffic routed via those networks bypasses the gateway")
            if not any(d in gw_ips for d in dns):
                info["warnings"].append(
                    "DNS not set to the gateway (dns: " + ", ".join(gw_ips) + "): queries go through the host "
                    "resolver, so hostnames are unknown and the DNS channel is not controlled; "
                    "connections are still enforced by IP")
        except (OSError, ValueError) as e:
            info["warnings"].append(f"inspect failed: {e}")
        for key in ("IPv4Address", "IPv6Address"):
            addr = (c.get(key) or "").split("/")[0]
            if addr:
                out[addr] = info
    return out
