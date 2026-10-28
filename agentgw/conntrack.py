"""Listing and deleting conntrack entries (conntrack-tools CLI).

Deleting an entry is how existing connections are interrupted: the next
packet of that flow no longer matches an established entry, is evaluated as a
new connection by the forward chain and gets rejected (TCP reset / ICMP
admin-prohibited) if the policy no longer admits it.
"""

import ipaddress
import re
import subprocess

_KV = re.compile(r"(\w+)=(\S+)")


def list_from(subnet):
    """Entries whose original source is inside `subnet` (an ip_network)."""
    fam = "ipv4" if subnet.version == 4 else "ipv6"
    p = subprocess.run(["conntrack", "-L", "-f", fam, "-s", str(subnet.network_address),
                        "--mask-src", str(subnet.netmask)],
                       text=True, capture_output=True)
    entries = []
    for line in p.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        proto = parts[0] if not parts[0].startswith("ipv") else parts[2]
        kv = _KV.findall(line)
        orig = {}
        for k, v in kv:
            if k in orig:  # the second src=/dst= group is the reply tuple
                break
            orig[k] = v
        if "src" not in orig or "dst" not in orig:
            continue
        entries.append({
            "proto": proto,
            "src": orig["src"], "dst": orig["dst"],
            "sport": int(orig["sport"]) if "sport" in orig else None,
            "dport": int(orig["dport"]) if "dport" in orig else None,
        })
    return entries


def delete(entry):
    args = ["conntrack", "-D", "-p", entry["proto"], "-s", entry["src"], "-d", entry["dst"]]
    if entry.get("sport") is not None:
        args += ["--sport", str(entry["sport"]), "--dport", str(entry["dport"])]
    if ipaddress.ip_address(entry["src"]).version == 6:
        args += ["-f", "ipv6"]
    return subprocess.run(args, text=True, capture_output=True).returncode == 0
