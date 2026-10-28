"""The privileged gateway process.

Runs in the host network namespace with CAP_NET_ADMIN. Responsibilities:
  * keep the nftables table in sync with the policy in the database;
  * resolve DNS for the agents and admit the returned IPs of allowed names;
  * interrupt existing connections the policy no longer admits;
  * turn kernel counters into aggregated flow records;
  * attribute traffic to containers (read-only Docker metadata).

It has no network-facing API apart from the DNS listener on the bridge.
"""

import ipaddress
import json
import logging
import os
import queue
import signal
import sys
import threading
import time

from dnslib import DNSRecord, QTYPE

from . import config, conntrack, db, dnsproxy, docker_meta, nft
from .policy import Policy, PolicyError, covers, normalize_host, port_set

log = logging.getLogger("agentgw.gateway")

CONTAINER_REFRESH = 10
HOUSEKEEPING = 3600


def _fam(ip):
    return "4" if ipaddress.ip_address(ip).version == 4 else "6"


class Gateway:
    def __init__(self, cfg):
        self.cfg = cfg
        self.conn = db.connect(cfg.db_path)
        db.init(self.conn)
        self.gw_ips = [str(cfg.gw4)] + ([str(cfg.gw6)] if cfg.gw6 else [])
        self.subnets = [cfg.subnet4] + ([cfg.subnet6] if cfg.subnet6 else [])
        self.upstream = dnsproxy.Upstream(cfg.upstream_dns)

        self.lock = threading.RLock()      # policy/settings/names snapshot
        self.dyn_lock = threading.Lock()   # dynamic set membership (serialises nft writes)
        self.policy = Policy([])
        self.settings = db.get_settings(self.conn)
        self.threat_nets, self.threat_domains = [], set()
        # (setname, element) -> {"expires", "names", "ip", "proto", "port"}
        self.dyn = {}
        self.names = {}       # ip -> {name: last_seen} (from our own DNS answers)
        self.src_names = {}   # (src_ip, ip) -> name
        self.containers = {}  # ip -> metadata
        self.events = queue.SimpleQueue()
        self.counters = {}
        self._touched = set()
        self.baselined = False
        self.next_expiry = None
        self.applied_version = 0

    # --- policy ---------------------------------------------------------

    def _threat_lists(self, settings):
        if not settings.get("auto_block_malicious"):
            return [], set()
        path = os.path.join(self.cfg.data_dir, "intel", "blocklist.json")
        try:
            with open(path) as f:
                bl = json.load(f)
        except (OSError, ValueError):
            return [], set()
        nets = []
        for v in bl.get("ips", []):
            try:
                nets.append(ipaddress.ip_network(v, strict=False))
            except ValueError:
                pass
        return nets, {d.lower() for d in bl.get("domains", [])}

    def _denied_host_ips(self, policy):
        """IPs our resolver returned for hostnames that are now denied, unless
        the same IP also serves an allowed name. Blocking a hostname must also
        stop new connections made with a cached address, in either mode."""
        out = []
        with self.lock:
            for ip, names in self.names.items():
                denied = any(policy.host_decision(n)[0] == "deny" for n in names)
                allowed = any(policy.host_decision(n)[0] == "allow" for n in names)
                if denied and not allowed:
                    out.append(ipaddress.ip_network(ip))
        return out

    def _static(self, policy, threat_nets):
        static = {"allow_any": [], "allow_port": [], "deny": [], "threat": threat_nets}
        for net, r in policy.allow_nets:
            ps = port_set(r["ports"])
            if ps is None:
                static["allow_any"].append(net)
            else:
                static["allow_port"] += [(net, proto, port) for proto, port in ps]
        static["deny"] = [net for net, _ in policy.deny_nets] + self._denied_host_ips(policy)
        return static

    def apply(self, full=False):
        t0 = time.time()
        version = int(db.get_meta(self.conn, "policy_version", "1"))
        now = time.time()
        rules = db.load_rules(self.conn)
        expired = [r for r in rules if r["expires_at"] and r["expires_at"] <= now]
        if expired:
            with db.tx(self.conn) as c:
                for r in expired:
                    db.delete_rule(c, r["id"], "gateway", event="expire")
                version = db.bump_policy(c)
            rules = db.load_rules(self.conn)
        settings = db.get_settings(self.conn)
        policy = Policy(rules, now)
        threat_nets, threat_domains = self._threat_lists(settings)
        try:
            static = self._static(policy, threat_nets)
            if full:
                nft.apply_full(self.cfg, static, settings["mode"])
            else:
                nft.apply_policy(static, settings["mode"])
        except nft.NftError as e:
            log.error("policy v%d not applied: %s", version, e)
            db.set_meta(self.conn, "apply_error", f"v{version}: {e}")
            db.set_meta(self.conn, "applied_version", version)  # don't retry in a loop
            self.applied_version = version
            return
        with self.lock:
            self.policy, self.settings = policy, settings
            self.threat_nets, self.threat_domains = threat_nets, threat_domains
        self.reconcile_dyn(policy, settings)
        killed = self.revoke(policy, settings)
        expiries = [r["expires_at"] for r in rules if r["expires_at"]]
        self.next_expiry = min(expiries) if expiries else None
        db.set_meta(self.conn, "applied_version", version)
        db.set_meta(self.conn, "applied_at", time.time())
        db.set_meta(self.conn, "apply_error", "")
        db.set_meta(self.conn, "last_revoked", killed)
        self.applied_version = version
        log.info("applied policy v%d: %d rules, mode=%s, %d connections interrupted (%.0f ms)",
                 version, len(policy.rules), settings["mode"], killed, (time.time() - t0) * 1000)

    # --- DNS-derived allowances -------------------------------------------

    def _elems_for(self, ip, rules):
        s = _fam(ip)
        sets = [port_set(r["ports"]) for r in rules]
        if any(ps is None for ps in sets):
            return {(f"dyn{s}_any", ip): (None, None)}
        out = {}
        for ps in sets:
            for proto, port in ps:
                out[(f"dyn{s}_port", f"{ip} . {proto} . {port}")] = (proto, port)
        return out

    def admit(self, name, ips, ttl, policy, settings):
        rules = policy.host_allow_rules(name)
        if not rules:
            return
        now = time.time()
        timeout = max(settings["dns_min_ttl"], min(ttl or 0, settings["dns_max_ttl"]))
        with self.dyn_lock:
            to_add, refresh = [], set()
            for ip in ips:
                for key, (proto, port) in self._elems_for(ip, rules).items():
                    cur = self.dyn.get(key)
                    if cur and cur["expires"] > now + 5:
                        cur["names"].add(name)
                        if cur["expires"] >= now + timeout / 2:
                            continue  # still fresh: skip the nft call
                        refresh.add(key)
                    to_add.append((key[0], key[1], timeout))
                    self.dyn[key] = {"expires": now + timeout,
                                     "names": (cur["names"] if cur else set()) | {name},
                                     "ip": ip, "proto": proto, "port": port}
            if to_add:
                nft.dyn_add(to_add, refresh)

    def reconcile_dyn(self, policy, settings):
        """Drop allowances whose names are no longer allowed; pre-admit known
        IPs of newly allowed names (so a retry with a cached address works)."""
        now = time.time()
        with self.dyn_lock:
            stale = []
            for key, ent in list(self.dyn.items()):
                if ent["expires"] <= now:
                    del self.dyn[key]
                    continue
                ok = False
                for n in ent["names"]:
                    rules = policy.host_allow_rules(n)
                    if ent["proto"] is None:
                        ok = any(port_set(r["ports"]) is None for r in rules)
                    else:
                        ok = any(covers(r["ports"], ent["proto"], ent["port"]) for r in rules)
                    if ok:
                        break
                if not ok:
                    stale.append(key)
                    del self.dyn[key]
            nft.dyn_delete(stale)
        with self.lock:
            known = [(ip, n) for ip, names in self.names.items() for n, seen in names.items()
                     if now - seen < settings["dns_max_ttl"]]
        by_name = {}
        for ip, n in known:
            by_name.setdefault(n, []).append(ip)
        for n, ips in by_name.items():
            self.admit(n, ips, settings["dns_min_ttl"], policy, settings)

    def load_dyn_from_kernel(self):
        """After a restart: re-learn the kernel's dynamic sets, keyed back to
        names via the persisted ip_names table. Unknown entries get dropped by
        the next reconcile (fail closed)."""
        try:
            sets = nft.dump_sets()
        except nft.NftError:
            return
        now = time.time()
        for row in self.conn.execute("SELECT ip, name, last_seen FROM ip_names WHERE last_seen > ?",
                                     (now - self.settings["dns_max_ttl"],)):
            self.names.setdefault(row["ip"], {})[row["name"]] = row["last_seen"]
        for s in ("4", "6"):
            for key, _, _, expires in sets.get(f"dyn{s}_any", []):
                self.dyn[(f"dyn{s}_any", key)] = {"expires": now + (expires or 0), "ip": key,
                                                  "proto": None, "port": None,
                                                  "names": set(self.names.get(key, {}))}
            for key, _, _, expires in sets.get(f"dyn{s}_port", []):
                ip, proto, port = key
                self.dyn[(f"dyn{s}_port", f"{ip} . {proto} . {port}")] = {
                    "expires": now + (expires or 0), "ip": ip, "proto": proto, "port": int(port),
                    "names": set(self.names.get(ip, {}))}

    # --- existing connections ---------------------------------------------

    def flow_allowed(self, policy, mode, e):
        ip, proto, port = e["dst"], e["proto"], e["dport"]
        addr = ipaddress.ip_address(ip)
        if policy.ip_decision(ip)[0] == "deny":
            return False
        if any(addr.version == n.version and addr in n for n in self.threat_nets):
            return False
        with self.lock:
            names = list(self.names.get(ip, {}))
        decisions = [policy.host_decision(n)[0] for n in names]
        if "deny" in decisions and "allow" not in decisions:
            return False
        if mode != "enforce":
            return True
        l4 = proto in ("tcp", "udp") and port is not None
        if l4 and policy.ip_decision(ip, proto, port)[0] == "allow":
            return True
        if not l4 and any(net.version == addr.version and addr in net and port_set(r["ports"]) is None
                          for net, r in policy.allow_nets):
            return True
        for n in names:
            rules = policy.host_allow_rules(n)
            if l4 and any(covers(r["ports"], proto, port) for r in rules):
                return True
            if not l4 and any(port_set(r["ports"]) is None for r in rules):
                return True
        return False

    def revoke(self, policy, settings):
        killed = 0
        for subnet in self.subnets:
            for e in conntrack.list_from(subnet):
                try:
                    dst = ipaddress.ip_address(e["dst"])
                except ValueError:
                    continue
                if dst in subnet or e["dst"] in self.gw_ips or e["dport"] == 53:
                    continue
                if not self.flow_allowed(policy, settings["mode"], e):
                    if conntrack.delete(e):
                        killed += 1
        return killed

    # --- DNS ---------------------------------------------------------------

    def _threat_domain(self, name, domains):
        parts = name.split(".")
        return any(".".join(parts[i:]) in domains for i in range(len(parts) - 1))

    def handle_dns(self, src, data):
        try:
            req = DNSRecord.parse(data)
        except Exception:
            return None
        if not req.questions:
            return None
        q = req.questions[0]
        qname = str(q.qname).rstrip(".").lower()
        qtype = QTYPE.get(q.qtype, str(q.qtype))
        now = time.time()
        with self.lock:
            policy, settings, threat_domains = self.policy, self.settings, self.threat_domains
        try:
            normalize_host(qname)
            decision, _ = policy.host_decision(qname)
        except PolicyError:
            decision = None
        if decision == "deny" or (threat_domains and self._threat_domain(qname, threat_domains)):
            self.events.put(("dns", src, qname, qtype, "denied", "NXDOMAIN", [], now))
            return dnsproxy.blocked_reply(req, "blocked by agentgw policy")
        if decision is None and settings["mode"] == "enforce" and settings["unapproved_dns"] == "refuse":
            self.events.put(("dns", src, qname, qtype, "refused", "NXDOMAIN", [], now))
            if qtype in ("A", "AAAA", "HTTPS", "SVCB", "CNAME"):
                self.events.put(("request", qname, "host", "dns-refused", None, src, now))
            return dnsproxy.blocked_reply(
                req, f"not approved; ask the operator or POST http://{self.cfg.gw4}:{self.cfg.agent_api_port}/v1/request")
        try:
            resp = self.upstream.query(data)
        except OSError as e:
            log.warning("upstream DNS failed for %s: %s", qname, e)
            self.events.put(("dns", src, qname, qtype, "error", "SERVFAIL", [], now))
            return dnsproxy.servfail(req)
        try:
            r = DNSRecord.parse(resp)
        except Exception:
            return resp
        ips, ttl = [], None
        for rr in r.rr:
            if rr.rtype in (1, 28):
                ips.append(str(rr.rdata))
                ttl = rr.ttl if ttl is None else min(ttl, rr.ttl)
        if ips:
            with self.lock:
                for ip in ips:
                    self.names.setdefault(ip, {})[qname] = now
                    self.src_names[(src, ip)] = qname
            self.events.put(("names", qname, ips, now))
            if decision == "allow":
                try:
                    # Must complete before the client sees the answer, or its
                    # first connection could race the set update.
                    self.admit(qname, ips, ttl, policy, settings)
                except nft.NftError as e:
                    log.error("could not admit %s: %s", qname, e)
        verdict = "allowed" if decision == "allow" else "unapproved"
        self.events.put(("dns", src, qname, qtype, verdict, RCODE_NAMES.get(r.header.rcode, str(r.header.rcode)),
                         ips, now))
        return resp

    # --- accounting --------------------------------------------------------

    def _delta(self, setname, key, value):
        k = (setname, key)
        prev = self.counters.get(k)
        self.counters[k] = value
        self._touched.add(k)
        if prev is None:
            return 0 if not self.baselined else value
        return value if value < prev else value - prev

    def hostname_for(self, src, dst):
        with self.lock:
            n = self.src_names.get((src, dst))
            if n:
                return n
            names = self.names.get(dst)
            return max(names, key=names.get) if names else None

    def poll(self):
        try:
            sets = nft.dump_sets()
        except nft.NftError as e:
            log.error("cannot read counters: %s", e)
            return
        flows = {}

        def add(key, **inc):
            d = flows.setdefault(key, {})
            for f, v in inc.items():
                if v:
                    d[f] = d.get(f, 0) + v

        for s in ("4", "6"):
            for name, field in (("conn", "conns"), ("blocked", "blocked"), ("unmatched", "unmatched"),
                                ("denied", "denied")):
                for key, pkts, _, _ in sets.get(f"{name}{s}", []):
                    add((key[0], key[1], str(key[2]), int(key[3])),
                        **{field: self._delta(f"{name}{s}", key, pkts)})
            for name in ("tx", "rx"):
                for key, pkts, byts, _ in sets.get(f"{name}{s}", []):
                    add((key[0], key[1], str(key[2]), int(key[3])),
                        **{f"{name}_pkts": self._delta(f"{name}{s}p", key, pkts),
                           f"{name}_bytes": self._delta(f"{name}{s}b", key, byts)})
            for name, field in (("other", "conns"), ("other_blocked", "blocked")):
                for key, pkts, _, _ in sets.get(f"{name}{s}", []):
                    add((key[0], key[1], str(key[2]), 0), **{field: self._delta(f"{name}{s}", key, pkts)})
        self.baselined = True
        # Forget counters of elements that have expired from the kernel sets.
        self.counters = {k: v for k, v in self.counters.items() if k in self._touched}
        self._touched = set()
        if flows:
            self.write_flows(flows)

    def write_flows(self, flows):
        now = time.time()
        with db.tx(self.conn) as c:
            for (src, dst, proto, port), d in flows.items():
                if not d:
                    continue
                host = self.hostname_for(src, dst)
                blocked = d.get("blocked", 0)
                c.execute(
                    "INSERT INTO flows (src_ip, dst_ip, proto, port, hostname, conns, blocked, unmatched, denied, "
                    "tx_bytes, tx_pkts, rx_bytes, rx_pkts, first_seen, last_seen, last_blocked) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT (src_ip, dst_ip, proto, port) DO UPDATE SET "
                    "hostname = COALESCE(excluded.hostname, flows.hostname), "
                    "conns = flows.conns + excluded.conns, blocked = flows.blocked + excluded.blocked, "
                    "unmatched = flows.unmatched + excluded.unmatched, denied = flows.denied + excluded.denied, "
                    "tx_bytes = flows.tx_bytes + excluded.tx_bytes, tx_pkts = flows.tx_pkts + excluded.tx_pkts, "
                    "rx_bytes = flows.rx_bytes + excluded.rx_bytes, rx_pkts = flows.rx_pkts + excluded.rx_pkts, "
                    "last_seen = excluded.last_seen, "
                    "last_blocked = COALESCE(excluded.last_blocked, flows.last_blocked)",
                    (src, dst, proto, port, host, d.get("conns", 0), blocked, d.get("unmatched", 0),
                     d.get("denied", 0), d.get("tx_bytes", 0), d.get("tx_pkts", 0), d.get("rx_bytes", 0),
                     d.get("rx_pkts", 0), now, now, now if blocked else None))
                if blocked:
                    dest = host or dst
                    pspec = f"{proto}/{port}" if proto in ("tcp", "udp") else proto
                    self._request(c, dest, "host" if host else "ip", "blocked", pspec, src, now, blocked)

    def _request(self, c, dest, kind, source, port, src, ts, attempts=1):
        row = c.execute("SELECT * FROM requests WHERE dest = ?", (dest,)).fetchone()
        if row:
            ports = set(json.loads(row["ports"]))
            ctrs = set(json.loads(row["containers"]))
            if port:
                ports.add(port)
            ctrs.add(src)
            src_kind = row["source"] if row["source"] == source else "blocked"
            c.execute("UPDATE requests SET last_seen = ?, attempts = attempts + ?, ports = ?, containers = ?, "
                      "source = ?, dismissed_at = NULL WHERE dest = ?",
                      (ts, attempts, json.dumps(sorted(ports)), json.dumps(sorted(ctrs)), src_kind, dest))
        else:
            c.execute("INSERT INTO requests (dest, kind, source, first_seen, last_seen, attempts, ports, containers) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (dest, kind, source, ts, ts, attempts, json.dumps([port] if port else []),
                       json.dumps([src])))

    def drain_events(self):
        items = []
        while True:
            try:
                items.append(self.events.get_nowait())
            except queue.Empty:
                break
        if not items:
            return
        with db.tx(self.conn) as c:
            for ev in items:
                if ev[0] == "dns":
                    _, src, qname, qtype, verdict, rcode, ips, ts = ev
                    c.execute("INSERT INTO dns (src_ip, qname, qtype, verdict, rcode, answers, count, first_seen, "
                              "last_seen) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?) "
                              "ON CONFLICT (src_ip, qname, qtype) DO UPDATE SET verdict = excluded.verdict, "
                              "rcode = excluded.rcode, answers = CASE WHEN excluded.answers = '[]' "
                              "THEN dns.answers ELSE excluded.answers END, count = dns.count + 1, "
                              "last_seen = excluded.last_seen",
                              (src, qname, qtype, verdict, rcode, json.dumps(ips), ts, ts))
                elif ev[0] == "names":
                    _, qname, ips, ts = ev
                    for ip in ips:
                        c.execute("INSERT INTO ip_names (ip, name, last_seen) VALUES (?, ?, ?) "
                                  "ON CONFLICT (ip, name) DO UPDATE SET last_seen = excluded.last_seen",
                                  (ip, qname, ts))
                elif ev[0] == "request":
                    _, dest, kind, source, port, src, ts = ev
                    self._request(c, dest, kind, source, port, src, ts)

    # --- containers & housekeeping -------------------------------------------

    def refresh_containers(self):
        if not os.path.exists(self.cfg.docker_sock):
            return
        try:
            found = docker_meta.agent_containers(self.cfg.docker_sock, self.cfg.network, self.gw_ips)
        except (OSError, ValueError) as e:
            log.warning("docker metadata unavailable: %s", e)
            return
        now = time.time()
        self.containers = found
        with db.tx(self.conn) as c:
            for ip, info in found.items():
                c.execute("INSERT INTO containers (ip, name, cid, info, first_seen, last_seen) "
                          "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (ip) DO UPDATE SET name = excluded.name, "
                          "cid = excluded.cid, info = excluded.info, last_seen = excluded.last_seen",
                          (ip, info["name"], info["cid"], json.dumps(info), now, now))

    def housekeeping(self):
        days = self.settings.get("retention_days", 30)
        cutoff = time.time() - days * 86400
        with db.tx(self.conn) as c:
            c.execute("DELETE FROM dns WHERE last_seen < ?", (cutoff,))
            c.execute("DELETE FROM flows WHERE last_seen < ?", (cutoff,))
            c.execute("DELETE FROM ip_names WHERE last_seen < ?", (cutoff,))
            c.execute("DELETE FROM requests WHERE last_seen < ?", (cutoff,))
            c.execute("DELETE FROM agent_notes WHERE ts < ?", (cutoff,))
        horizon = time.time() - 2 * self.settings["dns_max_ttl"]
        with self.lock:
            for ip in list(self.names):
                self.names[ip] = {n: t for n, t in self.names[ip].items() if t > horizon}
                if not self.names[ip]:
                    del self.names[ip]
            self.src_names = {k: v for k, v in self.src_names.items() if k[1] in self.names}

    # --- main loop -----------------------------------------------------------

    def start_dns(self):
        addrs = list(self.gw_ips)
        while True:
            try:
                dnsproxy.DNSServer(addrs, self.cfg.dns_port, self.handle_dns).start()
                return
            except OSError as e:
                # The bridge may not exist yet (network not created): retry.
                log.warning("DNS listener not up (%s); is network %s created? retrying", e, self.cfg.network)
                time.sleep(3)

    def prepare_socket_dir(self):
        # The socket proxy runs as an unprivileged uid and creates its socket
        # in a volume shared only between it and this container.
        d = os.path.dirname(self.cfg.docker_sock)
        try:
            os.makedirs(d, exist_ok=True)
            os.chmod(d, 0o1777)
        except OSError as e:
            log.warning("cannot prepare %s: %s", d, e)

    def run(self):
        self.prepare_socket_dir()
        self.load_dyn_from_kernel()
        self.apply(full=True)
        try:
            dnsproxy.DNSServer(self.gw_ips, self.cfg.dns_port, self.handle_dns).start()
        except OSError:
            threading.Thread(target=self.start_dns, daemon=True).start()
        last_poll = last_ctr = last_hk = 0
        while True:
            now = time.time()
            try:
                version = int(db.get_meta(self.conn, "policy_version", "1"))
                if version != self.applied_version or (self.next_expiry and now >= self.next_expiry):
                    self.apply()
                if now - last_ctr >= CONTAINER_REFRESH:
                    last_ctr = now
                    if not nft.table_schema_ok():
                        # Someone flushed the ruleset (e.g. `nft flush ruleset`
                        # or a firewall reload): put enforcement back.
                        log.error("nftables table missing; re-applying policy")
                        self.dyn.clear()
                        self.apply(full=True)
                    self.refresh_containers()
                # DNS events are flushed every iteration so agent hooks see a
                # refusal right away; kernel counters are polled less often.
                self.drain_events()
                if now - last_poll >= self.cfg.poll_interval:
                    last_poll = now
                    self.poll()
                    db.set_meta(self.conn, "gateway_heartbeat", now)
                if now - last_hk >= HOUSEKEEPING:
                    last_hk = now
                    self.housekeeping()
            except Exception:
                log.exception("gateway loop error")
            time.sleep(0.05)  # policy changes are picked up within ~50 ms


RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def main():
    logging.basicConfig(level=os.environ.get("AGENTGW_LOG", "INFO"),
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    cfg = config.load()
    gw = Gateway(cfg)
    # Leave the nftables table in place on exit: stopping the gateway must not
    # open the network. Removal is an explicit operator action (see README).
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log.info("gateway starting: bridge=%s subnet=%s gw=%s upstream=%s",
             cfg.bridge, cfg.subnet4, cfg.gw4, ",".join(cfg.upstream_dns))
    gw.run()


if __name__ == "__main__":
    main()
