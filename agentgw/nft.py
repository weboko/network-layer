"""nftables ruleset for the agents bridge.

Everything lives in one table, `inet agentgw`, which Docker never touches.
Docker documents adding separate tables as the way to filter alongside its own
rules: a drop/reject in any base chain is final, while our "return"/accept only
hands the packet on to Docker's own chains, so Docker networking keeps working.

Hooks used (all matched on the agents bridge name, nothing else is affected):
  forward  - egress policy for new connections + per-flow accounting
  input    - agents may reach only the gateway resolver and agent API on the host
  prerouting/nat - any DNS (port 53) a container sends elsewhere is redirected
                   to the gateway resolver

Design rules that matter for safety:
  * accounting `update @set` statements are never combined with a verdict in
    one rule: if a set is full the update fails and the rest of that rule is
    skipped, which must not skip a reject;
  * policy changes are single `nft -f` transactions (all-or-nothing);
  * the table is left in place when the gateway stops, so enforcement does not
    fail open when the process dies.
"""

import ipaddress
import json
import subprocess

TABLE = "agentgw"
SCHEMA = "schema_v1"   # bump when set/chain definitions change incompatibly

FAMILIES = {
    # suffix: (nft address family keyword, address type, nfproto)
    "4": ("ip", "ipv4_addr", "ipv4"),
    "6": ("ip6", "ipv6_addr", "ipv6"),
}

ACCT_L4 = ("conn", "tx", "rx", "unmatched", "blocked", "denied")
ACCT_OTHER = ("other", "other_blocked")
STATIC_SETS = ("allow{}_any", "allow{}_port", "deny{}", "threat{}")
DYN_SETS = ("dyn{}_any", "dyn{}_port")
ACCT_TIMEOUT = "2h"
ACCT_SIZE = 65536


class NftError(RuntimeError):
    pass


def run(script, check=True):
    p = subprocess.run(["nft", "-f", "-"], input=script, text=True, capture_output=True)
    if check and p.returncode != 0:
        raise NftError(p.stderr.strip() or f"nft exited {p.returncode}")
    return p


def list_json(*args):
    p = subprocess.run(["nft", "-j", "list", *args], text=True, capture_output=True)
    if p.returncode != 0:
        raise NftError(p.stderr.strip())
    return json.loads(p.stdout)


def table_exists():
    p = subprocess.run(["nft", "list", "table", "inet", TABLE], text=True, capture_output=True)
    return p.returncode == 0


def table_schema_ok():
    p = subprocess.run(["nft", "list", "set", "inet", TABLE, SCHEMA], text=True, capture_output=True)
    return p.returncode == 0


# --- rendering ------------------------------------------------------------

def _skeleton():
    lines = [f"table inet {TABLE} {{", f"  set {SCHEMA} {{ type ipv4_addr; }}"]
    for s, (_, atype, _) in FAMILIES.items():
        lines += [
            f"  set allow{s}_any {{ type {atype}; flags interval; }}",
            f"  set allow{s}_port {{ type {atype} . inet_proto . inet_service; flags interval; }}",
            f"  set deny{s} {{ type {atype}; flags interval; }}",
            f"  set threat{s} {{ type {atype}; flags interval; }}",
            f"  set dyn{s}_any {{ type {atype}; flags timeout; }}",
            f"  set dyn{s}_port {{ type {atype} . inet_proto . inet_service; flags timeout; }}",
        ]
        for name in ACCT_L4:
            lines.append(f"  set {name}{s} {{ type {atype} . {atype} . inet_proto . inet_service; "
                         f"flags dynamic,timeout; timeout {ACCT_TIMEOUT}; size {ACCT_SIZE}; counter; }}")
        for name in ACCT_OTHER:
            lines.append(f"  set {name}{s} {{ type {atype} . {atype} . inet_proto; "
                         f"flags dynamic,timeout; timeout {ACCT_TIMEOUT}; size {ACCT_SIZE}; counter; }}")
    lines += [
        "  chain forward { type filter hook forward priority filter - 5; policy accept; }",
        "  chain input { type filter hook input priority filter - 5; policy accept; }",
        "  chain dns_redirect { type nat hook prerouting priority dstnat - 5; policy accept; }",
        "  chain egress { }", "  chain ingress { }", "  chain reject_now { }",
    ]
    for s in FAMILIES:
        lines += [f"  chain new{s} {{ }}", f"  chain new{s}_l4 {{ }}", f"  chain new{s}_other {{ }}",
                  f"  chain nomatch{s}_l4 {{ }}", f"  chain nomatch{s}_other {{ }}"]
    lines.append("}")
    return "\n".join(lines) + "\n"


def _rules(cfg):
    """(chain, [rule, ...]) for every chain except the mode-dependent ones."""
    b = json.dumps(cfg.bridge)
    out = {}
    out["forward"] = [
        f"iifname {b} oifname != {b} jump egress",
        f"oifname {b} iifname != {b} jump ingress",
    ]
    ingress, egress = [], ["ct state invalid drop"]
    for s, (fam, _, nfp) in FAMILIES.items():
        ingress.append(f"ct direction reply meta nfproto {nfp} meta l4proto {{ tcp, udp }} "
                       f"update @rx{s} {{ {fam} daddr . {fam} saddr . meta l4proto . th sport }}")
        egress.append(f"ct direction original meta nfproto {nfp} meta l4proto {{ tcp, udp }} "
                      f"update @tx{s} {{ {fam} saddr . {fam} daddr . meta l4proto . th dport }}")
    # Everything that is not part of an already-admitted connection goes
    # through the policy: new, and also untracked packets.
    egress.append("ct state established,related return")
    for s, (_, _, nfp) in FAMILIES.items():
        egress.append(f"meta nfproto {nfp} jump new{s}")
    out["ingress"], out["egress"] = ingress, egress

    for s, (fam, _, _) in FAMILIES.items():
        key4 = f"{{ {fam} saddr . {fam} daddr . meta l4proto . th dport }}"
        key3 = f"{{ {fam} saddr . {fam} daddr . meta l4proto }}"
        dport = f"{fam} daddr . meta l4proto . th dport"
        out[f"new{s}"] = [f"meta l4proto {{ tcp, udp }} goto new{s}_l4", f"goto new{s}_other"]
        out[f"new{s}_l4"] = [
            f"update @conn{s} {key4}",
            f"{fam} daddr @deny{s} update @denied{s} {key4}",
            f"{fam} daddr @deny{s} goto reject_now",
            f"{fam} daddr @threat{s} update @denied{s} {key4}",
            f"{fam} daddr @threat{s} goto reject_now",
            f"{fam} daddr @allow{s}_any return",
            f"{dport} @allow{s}_port return",
            f"{fam} daddr @dyn{s}_any return",
            f"{dport} @dyn{s}_port return",
            f"goto nomatch{s}_l4",
        ]
        out[f"new{s}_other"] = [
            f"update @other{s} {key3}",
            f"{fam} daddr @deny{s} goto reject_now",
            f"{fam} daddr @threat{s} goto reject_now",
            f"{fam} daddr @allow{s}_any return",
            f"{fam} daddr @dyn{s}_any return",
            f"goto nomatch{s}_other",
        ]
    out["reject_now"] = ["meta l4proto tcp reject with tcp reset", "reject with icmpx admin-prohibited"]

    inp = [f"iifname != {b} return", "ct state established,related return", "ct state invalid drop",
           f"ip daddr {cfg.gw4} meta l4proto {{ udp, tcp }} th dport {cfg.dns_port} return",
           f"ip daddr {cfg.gw4} tcp dport {cfg.agent_api_port} return",
           f"ip daddr {cfg.gw4} icmp type echo-request return",
           # IPv6 neighbour discovery must work for any IPv6 on the bridge.
           "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } return"]
    if cfg.gw6:
        inp += [f"ip6 daddr {cfg.gw6} meta l4proto {{ udp, tcp }} th dport {cfg.dns_port} return",
                f"ip6 daddr {cfg.gw6} tcp dport {cfg.agent_api_port} return",
                f"ip6 daddr {cfg.gw6} icmpv6 type echo-request return"]
    # Anything else from an agent to the host itself (SSH, admin UI, Docker
    # published ports on host IPs, metadata services...) is refused.
    inp.append("goto reject_now")
    out["input"] = inp

    dns = [f"iifname {b} meta nfproto ipv4 meta l4proto {{ udp, tcp }} th dport 53 "
           f"fib daddr type != local dnat ip to {cfg.gw4}:{cfg.dns_port}"]
    if cfg.gw6:
        dns.append(f"iifname {b} meta nfproto ipv6 meta l4proto {{ udp, tcp }} th dport 53 "
                   f"fib daddr type != local dnat ip6 to [{cfg.gw6}]:{cfg.dns_port}")
    out["dns_redirect"] = dns
    return out


def _mode_rules(mode):
    out = {}
    for s, (fam, _, _) in FAMILIES.items():
        key4 = f"{{ {fam} saddr . {fam} daddr . meta l4proto . th dport }}"
        key3 = f"{{ {fam} saddr . {fam} daddr . meta l4proto }}"
        if mode == "enforce":
            out[f"nomatch{s}_l4"] = [f"update @blocked{s} {key4}", "goto reject_now"]
            out[f"nomatch{s}_other"] = [f"update @other_blocked{s} {key3}", "goto reject_now"]
        else:
            out[f"nomatch{s}_l4"] = [f"update @unmatched{s} {key4}"]
            out[f"nomatch{s}_other"] = []
    return out


def _chains_script(chains):
    lines = []
    for chain, rules in chains.items():
        lines.append(f"flush chain inet {TABLE} {chain}")
        lines += [f"add rule inet {TABLE} {chain} {r}" for r in rules]
    return "\n".join(lines) + "\n"


def _collapse(nets):
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    return list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))


def _fmt_net(n):
    return str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n)


def render_static(static):
    """static: {'allow_any': [net], 'allow_port': [(net, proto, port)], 'deny': [net], 'threat': [net]}"""
    lines = []
    for s in FAMILIES:
        for tmpl in STATIC_SETS:
            lines.append(f"flush set inet {TABLE} {tmpl.format(s)}")
    ver = {"4": 4, "6": 6}

    def add(setname, elems):
        if elems:
            lines.append(f"add element inet {TABLE} {setname} {{ {', '.join(elems)} }}")

    for s, v in ver.items():
        for kind in ("allow_any", "deny", "threat"):
            nets = _collapse([n for n in static.get(kind, []) if n.version == v])
            name = {"allow_any": f"allow{s}_any", "deny": f"deny{s}", "threat": f"threat{s}"}[kind]
            add(name, [_fmt_net(n) for n in nets])
        groups = {}
        for net, proto, port in static.get("allow_port", []):
            if net.version == v:
                groups.setdefault((proto, port), []).append(net)
        elems = [f"{_fmt_net(n)} . {proto} . {port}"
                 for (proto, port), nets in sorted(groups.items()) for n in _collapse(nets)]
        add(f"allow{s}_port", elems)
    return "\n".join(lines) + "\n"


def apply_full(cfg, static, mode):
    """Create/refresh the whole table in one transaction.

    Existing dynamic and accounting sets are kept when the schema matches, so a
    gateway restart neither forgets DNS-derived allowances nor resets counters.
    """
    script = _skeleton() + _chains_script({**_rules(cfg), **_mode_rules(mode)}) + render_static(static)
    if table_exists() and not table_schema_ok():
        script = f"delete table inet {TABLE}\n" + script
    try:
        run(script)
    except NftError:
        if not table_exists():
            raise
        # Set or chain definitions changed in an incompatible way: rebuild.
        run(f"delete table inet {TABLE}\n" + script)


def apply_policy(static, mode):
    """Swap static sets and mode chains atomically."""
    run(render_static(static) + _chains_script(_mode_rules(mode)))


def dyn_add(elems, refresh=()):
    """elems: [(setname, element_text, timeout_seconds)]. Elements listed in
    `refresh` already exist; they are deleted and re-added in the same
    transaction so the timeout is extended on kernels that do not refresh the
    timeout of an existing element on add."""
    if not elems:
        return
    lines = []
    for setname, elem, timeout in elems:
        if (setname, elem) in refresh:
            lines.append(f"delete element inet {TABLE} {setname} {{ {elem} }}")
        lines.append(f"add element inet {TABLE} {setname} {{ {elem} timeout {int(timeout)}s }}")
    try:
        run("\n".join(lines) + "\n")
    except NftError:
        # An element we believed present had expired; plain adds still work.
        run("\n".join(f"add element inet {TABLE} {s} {{ {e} timeout {int(t)}s }}" for s, e, t in elems) + "\n")


def dyn_delete(elems):
    """elems: [(setname, element_text)]; missing elements are ignored."""
    for setname, elem in elems:
        run(f"delete element inet {TABLE} {setname} {{ {elem} }}\n", check=False)


# --- reading --------------------------------------------------------------

def _val(v):
    if isinstance(v, dict):
        if "concat" in v:
            return tuple(_val(x) for x in v["concat"])
        if "prefix" in v:
            return f"{v['prefix']['addr']}/{v['prefix']['len']}"
        if "range" in v:
            return tuple(v["range"])
    return v


def dump_sets():
    """{setname: [(key, packets, bytes, expires)]} for the whole table."""
    out = {}
    for item in list_json("table", "inet", TABLE).get("nftables", []):
        s = item.get("set")
        if not s:
            continue
        elems = []
        for e in s.get("elem", []):
            if isinstance(e, dict) and "elem" in e:
                inner = e["elem"]
                c = inner.get("counter") or {}
                elems.append((_val(inner["val"]), c.get("packets", 0), c.get("bytes", 0), inner.get("expires")))
            else:
                elems.append((_val(e), 0, 0, None))
        out[s["name"]] = elems
    return out


def delete_table():
    run(f"delete table inet {TABLE}\n", check=False)
