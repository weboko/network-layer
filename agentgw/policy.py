"""Policy model: rule validation, matching and the YAML snapshot format.

A rule is a dict:
    {"action": "allow"|"deny", "kind": "host"|"ip", "value": str,
     "ports": ["*"] | ["tcp/443", "udp/443", ...], "note": str,
     "expires_at": float|None}

Semantics (mirrored by the nftables ruleset in nft.py):
  * deny beats allow, for both hostnames and IPs;
  * a hostname rule "example.com" matches exactly that name; "*.example.com"
    matches any subdomain but not the apex;
  * hostname rules are enforced through DNS: only IPs that the gateway's own
    resolver returned for an allowed name are admitted, for that rule's ports;
  * "ip" rules take a single address or a CIDR and are enforced directly;
  * ports "*" means any TCP/UDP port (and, for other protocols such as ICMP,
    the destination as a whole).
"""

import ipaddress
import re
import time

import yaml

ACTIONS = ("allow", "deny")
PROTOS = ("tcp", "udp")
DEFAULT_PORTS = ["tcp/443", "tcp/80"]

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


class PolicyError(ValueError):
    pass


def normalize_host(name):
    name = (name or "").strip().lower().rstrip(".")
    if not name:
        raise PolicyError("empty hostname")
    wildcard = name.startswith("*.")
    base = name[2:] if wildcard else name
    if len(base) > 253:
        raise PolicyError(f"hostname too long: {name!r}")
    if "." not in base and not wildcard:
        # Single-label names are almost always mistakes.
        raise PolicyError(f"hostname must contain a dot: {name!r}")
    for label in base.split("."):
        if not _LABEL.match(label):
            raise PolicyError(f"invalid hostname: {name!r}")
    return ("*." if wildcard else "") + base


def normalize_ip(value):
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as e:
        raise PolicyError(f"invalid IP/CIDR: {value!r}") from e
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


def guess_kind(value):
    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return "ip"
    except ValueError:
        return "host"


def normalize_ports(ports):
    if ports is None or ports == [] or ports == "*":
        return ["*"]
    if isinstance(ports, str):
        ports = [p for p in re.split(r"[\s,]+", ports) if p]
    out = set()
    for p in ports:
        p = str(p).strip().lower()
        if p in ("*", "any"):
            return ["*"]
        if "/" not in p:
            # A bare number means TCP, the overwhelmingly common case.
            p = "tcp/" + p
        proto, _, num = p.partition("/")
        if proto not in PROTOS:
            raise PolicyError(f"unsupported protocol in {p!r} (use tcp/N or udp/N)")
        try:
            n = int(num)
        except ValueError as e:
            raise PolicyError(f"invalid port in {p!r}") from e
        if not 1 <= n <= 65535:
            raise PolicyError(f"port out of range in {p!r}")
        out.add(f"{proto}/{n}")
    return sorted(out, key=lambda s: (s.split("/")[0], int(s.split("/")[1])))


def validate_rule(rule):
    action = rule.get("action")
    if action not in ACTIONS:
        raise PolicyError(f"action must be allow or deny, got {action!r}")
    value = str(rule.get("value", ""))
    kind = rule.get("kind") or guess_kind(value)
    if kind == "host":
        value = normalize_host(value)
    elif kind == "ip":
        value = normalize_ip(value)
    else:
        raise PolicyError(f"kind must be host or ip, got {kind!r}")
    # A deny always covers the whole destination; partial denies would be
    # surprising next to a default-deny policy.
    ports = ["*"] if action == "deny" else normalize_ports(rule.get("ports"))
    expires = rule.get("expires_at")
    if expires is not None:
        expires = float(expires)
    return {
        "action": action,
        "kind": kind,
        "value": value,
        "ports": ports,
        "note": str(rule.get("note") or "")[:500],
        "expires_at": expires,
    }


def host_matches(pattern, name):
    name = name.lower().rstrip(".")
    if pattern.startswith("*."):
        return name.endswith(pattern[1:])
    return name == pattern


def port_set(ports):
    """None means any port; otherwise a set of (proto, port) tuples."""
    if not ports or "*" in ports:
        return None
    return {(p.split("/")[0], int(p.split("/")[1])) for p in ports}


def covers(ports, proto, port):
    ps = port_set(ports)
    return ps is None or (proto, port) in ps


class Policy:
    """The active rule set, with lookups used by the gateway and the UI."""

    def __init__(self, rules, now=None):
        now = time.time() if now is None else now
        self.rules = [r for r in rules if not r.get("expires_at") or r["expires_at"] > now]
        self.allow_hosts = [r for r in self.rules if r["action"] == "allow" and r["kind"] == "host"]
        self.deny_hosts = [r for r in self.rules if r["action"] == "deny" and r["kind"] == "host"]
        self.allow_nets = [(ipaddress.ip_network(r["value"]), r) for r in self.rules
                           if r["action"] == "allow" and r["kind"] == "ip"]
        self.deny_nets = [(ipaddress.ip_network(r["value"]), r) for r in self.rules
                          if r["action"] == "deny" and r["kind"] == "ip"]

    @staticmethod
    def _best(rules, name):
        # Most specific match wins: exact beats wildcard, longer suffix beats shorter.
        hits = [r for r in rules if host_matches(r["value"], name)]
        if not hits:
            return None
        return max(hits, key=lambda r: (not r["value"].startswith("*."), len(r["value"])))

    def host_decision(self, name):
        """('deny'|'allow'|None, rule) for a DNS name."""
        r = self._best(self.deny_hosts, name)
        if r:
            return "deny", r
        r = self._best(self.allow_hosts, name)
        if r:
            return "allow", r
        return None, None

    def host_allow_rules(self, name):
        """All allow rules that match a name (their ports are unioned)."""
        if self._best(self.deny_hosts, name):
            return []
        return [r for r in self.allow_hosts if host_matches(r["value"], name)]

    def ip_decision(self, ip, proto=None, port=None):
        """Static IP rules only; DNS-derived allowances are tracked by the gateway."""
        addr = ipaddress.ip_address(ip)
        for net, r in self.deny_nets:
            if addr.version == net.version and addr in net:
                return "deny", r
        for net, r in self.allow_nets:
            if addr.version == net.version and addr in net:
                if proto is None or covers(r["ports"], proto, port):
                    return "allow", r
        return None, None

    def dest_status(self, dest, ports=()):
        """Review status of an aggregated destination (hostname or IP)."""
        if guess_kind(dest) == "ip":
            d, r = self.ip_decision(dest)
            if d == "deny":
                return "denied"
            if d == "allow":
                missing = [p for p in ports if not covers(r["ports"], *_split(p))]
                return "partial" if missing else "approved"
            return "unreviewed"
        d, r = self.host_decision(dest)
        if d == "deny":
            return "denied"
        if d == "allow":
            rules = self.host_allow_rules(dest)
            missing = [p for p in ports if not any(covers(x["ports"], *_split(p)) for x in rules)]
            return "partial" if missing else "approved"
        return "unreviewed"


def _split(p):
    proto, _, port = p.partition("/")
    return proto, int(port)


# --- YAML snapshot format -------------------------------------------------

FORMAT_VERSION = 1


def to_yaml(rules, name="", note="", meta=None):
    entries = []
    for r in sorted(rules, key=lambda r: (r["action"], r["kind"], r["value"])):
        e = {r["action"]: r["value"]}
        if r["action"] == "allow":
            e["ports"] = list(r["ports"])
        if r.get("note"):
            e["note"] = r["note"]
        if r.get("expires_at"):
            e["expires"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r["expires_at"]))
        entries.append(e)
    doc = {
        "agentgw_policy": FORMAT_VERSION,
        "name": name,
        "note": note,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if meta:
        doc.update(meta)
    doc["rules"] = entries
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, allow_unicode=True)


def from_yaml(text):
    """Parse a policy document. Returns (rules, metadata). Raises PolicyError."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyError(f"invalid YAML: {e}") from e
    if not isinstance(doc, dict) or "rules" not in doc:
        raise PolicyError("not an agentgw policy document (missing 'rules')")
    if doc.get("agentgw_policy", FORMAT_VERSION) != FORMAT_VERSION:
        raise PolicyError(f"unsupported policy format version {doc.get('agentgw_policy')}")
    rules, seen = [], set()
    for i, e in enumerate(doc.get("rules") or []):
        if not isinstance(e, dict):
            raise PolicyError(f"rule {i + 1}: expected a mapping")
        actions = [a for a in ACTIONS if a in e]
        if len(actions) != 1:
            raise PolicyError(f"rule {i + 1}: needs exactly one of 'allow' or 'deny'")
        action = actions[0]
        expires = e.get("expires")
        if expires:
            try:
                expires = time.mktime(time.strptime(str(expires), "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
            except ValueError as err:
                raise PolicyError(f"rule {i + 1}: bad expires {expires!r}") from err
        try:
            r = validate_rule({"action": action, "value": str(e[action]), "ports": e.get("ports"),
                               "note": e.get("note"), "expires_at": expires or None})
        except PolicyError as err:
            raise PolicyError(f"rule {i + 1}: {err}") from err
        key = (r["kind"], r["value"])
        if key in seen:
            raise PolicyError(f"rule {i + 1}: duplicate destination {r['value']}")
        seen.add(key)
        rules.append(r)
    meta = {k: v for k, v in doc.items() if k != "rules"}
    return rules, meta
