"""The controller: admin dashboard/API and the agent API. Unprivileged.

Two listeners:
  admin  (AGENTGW_ADMIN_LISTEN, default 127.0.0.1:8080) - dashboard + /api/*.
         Reach it over SSH port-forwarding, Tailscale or WireGuard; do not
         expose it publicly. Optional bearer token (AGENTGW_ADMIN_TOKEN).
  agent  (gateway bridge IP, port 8081) - what agents may ask: which of their
         connections were blocked, request access with a reason, wait for a
         decision. It cannot approve anything.

Policy changes are written to the database; the gateway applies them and the
API waits (briefly) for confirmation so the UI shows applied/not applied.
"""

import ipaddress
import json
import logging
import mimetypes
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import config, db, intel as intel_mod
from .policy import (DEFAULT_PORTS, Policy, PolicyError, from_yaml, guess_kind, normalize_host,
                     normalize_ip, normalize_ports, to_yaml, validate_rule)

log = logging.getLogger("agentgw.web")
STATIC = os.path.join(os.path.dirname(__file__), "static")
APPLY_WAIT = 5.0


class Controller:
    def __init__(self, cfg):
        self.cfg = cfg
        self.local = threading.local()
        db.init(self.db())
        self.intel = intel_mod.Intel(cfg.data_dir, os.environ.get("ABUSECH_AUTH_KEY", ""))
        self.intel_cache = {}
        self._policy = (None, None)
        self.rate = {}
        self.waiting = {}  # src ip -> open /v1/wait long-polls
        self.wait_lock = threading.Lock()

    def db(self):
        c = getattr(self.local, "conn", None)
        if c is None:
            c = self.local.conn = db.connect(self.cfg.db_path)
        return c

    def policy(self):
        """Policy object for the current rules (cached per policy version)."""
        v = db.get_meta(self.db(), "policy_version")
        if self._policy[0] != v:
            self._policy = (v, Policy(db.load_rules(self.db())))
        return self._policy[1]

    def containers(self):
        return {r["ip"]: dict(r, info=json.loads(r["info"] or "{}"))
                for r in self.db().execute("SELECT * FROM containers")}

    def commit_policy(self, conn):
        """Bump the version inside the caller's transaction."""
        return db.bump_policy(conn)

    def wait_applied(self, version):
        deadline = time.time() + APPLY_WAIT
        c = self.db()
        while time.time() < deadline:
            applied = int(db.get_meta(c, "applied_version", "0"))
            if applied >= version:
                err = db.get_meta(c, "apply_error", "")
                return {"applied": not err, "version": version, "error": err or None}
            time.sleep(0.1)
        return {"applied": False, "version": version,
                "error": "gateway has not confirmed yet (is the gateway running?)"}

    # --- intel ---------------------------------------------------------------

    def intel_loop(self):
        while True:
            try:
                self.refresh_intel()
            except Exception:
                log.exception("intel refresh failed")
            time.sleep(3600)

    def refresh_intel(self, force=False):
        s = db.get_settings(self.db())
        self.intel.refresh(s["intel_feeds"], s["geoip"], force=force)
        self.intel_cache.clear()
        bl = self.intel.blocklist()
        path = os.path.join(self.intel.dir, "blocklist.json")
        old = None
        try:
            with open(path) as f:
                old = json.load(f)
        except (OSError, ValueError):
            pass
        if bl != old:
            with open(path + ".tmp", "w") as f:
                json.dump(bl, f)
            os.replace(path + ".tmp", path)
            if s["auto_block_malicious"]:
                with db.tx(self.db()) as c:
                    db.bump_policy(c)

    def assess(self, dest, ips, ports):
        hit = self.intel_cache.get(dest)
        if hit and time.time() - hit[0] < 300:
            return hit[1]
        s = db.get_settings(self.db())
        res = self.intel.assess(dest, ips, ports, s["watch_countries"])
        self.intel_cache[dest] = (time.time(), res)
        return res

    # --- views ------------------------------------------------------------------

    def status(self):
        c = self.db()
        hb = float(db.get_meta(c, "gateway_heartbeat", "0") or 0)
        ctrs = self.containers()
        return {
            "settings": db.get_settings(c),
            "policy_version": int(db.get_meta(c, "policy_version", "1")),
            "applied_version": int(db.get_meta(c, "applied_version", "0")),
            "applied_at": float(db.get_meta(c, "applied_at", "0") or 0),
            "apply_error": db.get_meta(c, "apply_error", "") or None,
            "last_revoked": int(db.get_meta(c, "last_revoked", "0") or 0),
            "gateway_heartbeat": hb,
            "gateway_alive": time.time() - hb < 15,
            "rules": c.execute("SELECT COUNT(*) FROM rules").fetchone()[0],
            "pending": len(self.queue()),
            "containers": [{"ip": ip, "name": v["name"], "warnings": v["info"].get("warnings", []),
                            "last_seen": v["last_seen"]} for ip, v in sorted(ctrs.items())],
            "intel": self.intel.status,
            "gw4": str(self.cfg.gw4),
            "agent_api": f"http://{self.cfg.gw4}:{self.cfg.agent_api_port}",
        }

    def destinations(self, hours=24.0, q=""):
        c = self.db()
        since = time.time() - hours * 3600
        names = {ip: v["name"] for ip, v in self.containers().items()}
        policy = self.policy()
        rows = {}
        for r in c.execute(
                "SELECT COALESCE(hostname, dst_ip) AS dest, dst_ip, src_ip, proto, port, conns, blocked, "
                "unmatched, denied, tx_bytes, rx_bytes, rx_pkts, first_seen, last_seen, last_blocked "
                "FROM flows WHERE last_seen > ?", (since,)):
            d = rows.setdefault(r["dest"], {
                "dest": r["dest"], "kind": guess_kind(r["dest"]), "ips": set(), "containers": set(),
                "ports": set(), "conns": 0, "blocked": 0, "unmatched": 0, "denied": 0, "dns_refused": 0,
                "tx_bytes": 0, "rx_bytes": 0, "rx_pkts": 0, "first_seen": r["first_seen"],
                "last_seen": r["last_seen"], "last_blocked": None})
            d["ips"].add(r["dst_ip"])
            d["containers"].add(names.get(r["src_ip"], r["src_ip"]))
            d["ports"].add(f"{r['proto']}/{r['port']}" if r["proto"] in ("tcp", "udp") else r["proto"])
            for k in ("conns", "blocked", "unmatched", "denied", "tx_bytes", "rx_bytes", "rx_pkts"):
                d[k] += r[k]
            d["first_seen"] = min(d["first_seen"], r["first_seen"])
            d["last_seen"] = max(d["last_seen"], r["last_seen"])
            if r["last_blocked"]:
                d["last_blocked"] = max(d["last_blocked"] or 0, r["last_blocked"])
        for r in c.execute("SELECT qname, src_ip, verdict, SUM(count) AS n, MIN(first_seen) AS f, "
                           "MAX(last_seen) AS l FROM dns WHERE verdict IN ('refused', 'denied') "
                           "AND last_seen > ? GROUP BY qname, src_ip", (since,)):
            d = rows.setdefault(r["qname"], {
                "dest": r["qname"], "kind": "host", "ips": set(), "containers": set(), "ports": set(),
                "conns": 0, "blocked": 0, "unmatched": 0, "denied": 0, "dns_refused": 0, "tx_bytes": 0,
                "rx_bytes": 0, "rx_pkts": 0, "first_seen": r["f"], "last_seen": r["l"], "last_blocked": None})
            d["dns_refused"] += r["n"]
            d["containers"].add(names.get(r["src_ip"], r["src_ip"]))
            d["last_seen"] = max(d["last_seen"], r["l"])
            d["last_blocked"] = max(d["last_blocked"] or 0, r["l"])
        out = []
        q = q.lower().strip()
        for d in rows.values():
            if q and q not in d["dest"].lower() and not any(q in ip for ip in d["ips"]):
                continue
            l4 = sorted(p for p in d["ports"] if "/" in p)
            d["status"] = policy.dest_status(d["dest"], l4)
            # Outcome of the most recent activity, not of the whole history:
            # a destination approved after being blocked reads "ok".
            if d["last_blocked"] and d["last_blocked"] >= d["last_seen"] - 1:
                d["outcome"] = "last attempt blocked"
            elif d["rx_pkts"]:
                d["outcome"] = "ok"
            elif d["conns"]:
                d["outcome"] = "no reply"
            else:
                d["outcome"] = "-"
            d["would_block"] = d["status"] in ("unreviewed", "partial")
            d["intel"] = self.assess(d["dest"], d["ips"], d["ports"])
            for k in ("ips", "containers", "ports"):
                d[k] = sorted(d[k])
            out.append(d)
        out.sort(key=lambda d: -d["last_seen"])
        return out

    def queue(self):
        c = self.db()
        policy = self.policy()
        names = {ip: v["name"] for ip, v in self.containers().items()}
        items = []
        for r in c.execute("SELECT * FROM requests WHERE dismissed_at IS NULL ORDER BY last_seen DESC"):
            ports = json.loads(r["ports"])
            l4 = [p for p in ports if "/" in p]
            status = policy.dest_status(r["dest"], l4)
            if status in ("approved", "denied"):
                continue
            notes = [dict(n) for n in c.execute(
                "SELECT container, necessity, reason, task, port, ts FROM agent_notes WHERE dest = ? "
                "ORDER BY ts DESC LIMIT 20", (r["dest"],))]
            ips = [x["dst_ip"] for x in c.execute(
                "SELECT DISTINCT dst_ip FROM flows WHERE hostname = ? OR dst_ip = ?", (r["dest"], r["dest"]))]
            if not ips and r["kind"] == "host":
                ips = [x["ip"] for x in c.execute("SELECT ip FROM ip_names WHERE name = ?", (r["dest"],))]
            necessity = ("required" if any(n["necessity"] == "required" for n in notes) else
                         "optional" if notes else "unknown")
            items.append({
                "dest": r["dest"], "kind": r["kind"], "source": r["source"], "status": status,
                "first_seen": r["first_seen"], "last_seen": r["last_seen"], "attempts": r["attempts"],
                "ports": ports, "containers": sorted({names.get(x, x) for x in json.loads(r["containers"])}),
                "notes": notes, "necessity": necessity, "ips": ips,
                "intel": self.assess(r["dest"], ips, ports),
            })
        order = {"required": 0, "unknown": 1, "optional": 2}
        items.sort(key=lambda i: (order[i["necessity"]], -i["last_seen"]))
        return items

    def destination_detail(self, dest):
        c = self.db()
        names = {ip: v["name"] for ip, v in self.containers().items()}
        flows = [dict(r, container=names.get(r["src_ip"], r["src_ip"])) for r in c.execute(
            "SELECT * FROM flows WHERE hostname = ? OR dst_ip = ? ORDER BY last_seen DESC LIMIT 200", (dest, dest))]
        dns = [dict(r, answers=json.loads(r["answers"] or "[]"), container=names.get(r["src_ip"], r["src_ip"]))
               for r in c.execute("SELECT * FROM dns WHERE qname = ? ORDER BY last_seen DESC LIMIT 100", (dest,))]
        notes = [dict(r) for r in c.execute("SELECT * FROM agent_notes WHERE dest = ? ORDER BY ts DESC", (dest,))]
        history = [dict(r) for r in c.execute("SELECT * FROM history WHERE value = ? ORDER BY ts DESC", (dest,))]
        rule = c.execute("SELECT * FROM rules WHERE value = ?", (dest,)).fetchone()
        ips = sorted({f["dst_ip"] for f in flows} | {a for d in dns for a in d["answers"]})
        ports = sorted({f"{f['proto']}/{f['port']}" for f in flows if f["proto"] in ("tcp", "udp")})
        return {"dest": dest, "flows": flows, "dns": dns, "notes": notes, "history": history,
                "rule": db.row_to_rule(rule) if rule else None, "status": self.policy().dest_status(dest, ports),
                "intel": self.intel.assess(dest, ips, ports, db.get_settings(c)["watch_countries"])}

    # --- decisions ----------------------------------------------------------------

    def observed_ports(self, dest):
        c = self.db()
        ports = set()
        for r in c.execute("SELECT DISTINCT proto, port FROM flows WHERE (hostname = ? OR dst_ip = ?) "
                           "AND proto IN ('tcp', 'udp')", (dest, dest)):
            ports.add(f"{r['proto']}/{r['port']}")
        row = c.execute("SELECT ports FROM requests WHERE dest = ?", (dest,)).fetchone()
        if row:
            ports |= {p for p in json.loads(row["ports"]) if "/" in p}
        for r in c.execute("SELECT port FROM agent_notes WHERE dest = ? AND port IS NOT NULL", (dest,)):
            try:
                ports |= set(normalize_ports(r["port"]))
            except PolicyError:
                pass
        ports.discard("*")
        return sorted(ports)

    def decide(self, body, actor="dashboard"):
        dest = str(body.get("dest") or "").strip()
        action = body.get("action")
        if not dest or action not in ("approve", "block", "dismiss"):
            raise PolicyError("need dest and action approve|block|dismiss")
        if action == "dismiss":
            with db.tx(self.db()) as c:
                c.execute("UPDATE requests SET dismissed_at = ? WHERE dest = ?", (time.time(), dest))
                db.log_history(c, actor, "dismiss", guess_kind(dest), dest)
            return {"applied": True}
        value = str(body.get("value") or dest).strip()
        expires_at = None
        if body.get("expires_hours"):
            expires_at = time.time() + float(body["expires_hours"]) * 3600
        if action == "approve":
            ports = body.get("ports")
            if not ports:
                ports = self.observed_ports(dest) or list(DEFAULT_PORTS)
            rule = validate_rule({"action": "allow", "value": value, "ports": ports,
                                  "note": body.get("note") or "", "expires_at": expires_at})
            existing = self.db().execute("SELECT * FROM rules WHERE kind = ? AND value = ? AND action = 'allow'",
                                         (rule["kind"], rule["value"])).fetchone()
            if existing and not body.get("ports"):
                # Approving more ports for an approved destination extends the rule.
                old = json.loads(existing["ports"])
                rule["ports"] = normalize_ports(["*"] if "*" in old else old + rule["ports"])
                if not body.get("expires_hours"):
                    rule["expires_at"] = existing["expires_at"]
                rule["note"] = rule["note"] or existing["note"]
        else:
            rule = validate_rule({"action": "deny", "value": value, "note": body.get("note") or "",
                                  "expires_at": expires_at})
        with db.tx(self.db()) as c:
            db.upsert_rule(c, rule, actor)
            version = self.commit_policy(c)
        return dict(self.wait_applied(version), rule=rule)

    def add_rule(self, body, actor="dashboard"):
        expires_at = time.time() + float(body["expires_hours"]) * 3600 if body.get("expires_hours") else None
        rule = validate_rule({"action": body.get("action"), "value": body.get("value"), "ports": body.get("ports"),
                              "note": body.get("note"), "expires_at": expires_at})
        with db.tx(self.db()) as c:
            if body.get("id"):
                old = c.execute("SELECT * FROM rules WHERE id = ?", (int(body["id"]),)).fetchone()
                if not old:
                    raise PolicyError("no such rule")
                if (old["kind"], old["value"]) != (rule["kind"], rule["value"]):
                    db.delete_rule(c, old["id"], actor, event="edit")
                if body.get("keep_expiry") and not body.get("expires_hours"):
                    rule["expires_at"] = old["expires_at"]
            db.upsert_rule(c, rule, actor)
            version = self.commit_policy(c)
        return dict(self.wait_applied(version), rule=rule)

    def delete_rule(self, rid, actor="dashboard"):
        with db.tx(self.db()) as c:
            if not db.delete_rule(c, rid, actor):
                raise PolicyError("no such rule")
            version = self.commit_policy(c)
        return self.wait_applied(version)

    def update_settings(self, body, actor="dashboard"):
        c = self.db()
        cur = db.get_settings(c)
        changes = {}
        for k, v in body.items():
            if k not in db.DEFAULT_SETTINGS:
                raise PolicyError(f"unknown setting {k}")
            if k == "mode" and v not in ("observe", "enforce"):
                raise PolicyError("mode must be observe or enforce")
            if k == "unapproved_dns" and v not in ("refuse", "resolve"):
                raise PolicyError("unapproved_dns must be refuse or resolve")
            if k in ("dns_min_ttl", "dns_max_ttl", "default_temp_hours", "retention_days"):
                v = int(v)
                if v < 1:
                    raise PolicyError(f"{k} must be positive")
            if k in ("auto_block_malicious", "geoip"):
                v = bool(v)
            if k == "watch_countries":
                v = sorted({str(x).strip().upper() for x in (v if isinstance(v, list) else str(v).split(","))
                            if re.fullmatch(r"\s*[A-Za-z]{2}\s*", str(x))})
            if k == "intel_feeds":
                v = {name: bool(v.get(name, cur["intel_feeds"].get(name))) for name in intel_mod.FEEDS}
            if v != cur[k]:
                changes[k] = v
        if not changes:
            return {"applied": True, "changes": {}}
        with db.tx(c) as t:
            for k, v in changes.items():
                db.set_setting(t, k, v)
            db.log_history(t, actor, "settings", detail={k: {"from": cur[k], "to": v} for k, v in changes.items()})
            version = db.bump_policy(t) if any(k in db.GATEWAY_SETTINGS for k in changes) else None
        if "intel_feeds" in changes or "geoip" in changes:
            threading.Thread(target=self.refresh_intel, daemon=True).start()
        res = self.wait_applied(version) if version else {"applied": True}
        return dict(res, changes=changes)

    # --- snapshots / import / export ----------------------------------------------

    def export_yaml(self, name="current"):
        c = self.db()
        s = db.get_settings(c)
        return to_yaml(db.load_rules(c), name=name, meta={"mode_at_export": s["mode"]})

    def import_yaml(self, text, mode="replace", actor="dashboard", event="import"):
        rules, meta = from_yaml(text)
        with db.tx(self.db()) as c:
            if mode == "replace":
                db.replace_rules(c, rules, actor, event)
            else:
                for r in rules:
                    db.upsert_rule(c, r, actor)
                db.log_history(c, actor, event + "-merge", detail={"rule_count": len(rules)})
            version = self.commit_policy(c)
        # Rules only: pending review items are never turned into approvals
        # here, and the observe/enforce mode is left as it is.
        return dict(self.wait_applied(version), rule_count=len(rules), meta=meta)

    def save_snapshot(self, name, note="", actor="dashboard"):
        c = self.db()
        name = (name or "").strip() or time.strftime("snapshot %Y-%m-%d %H:%M")
        text = self.export_yaml(name)
        n = c.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        with db.tx(c) as t:
            cur = t.execute("INSERT INTO snapshots (name, note, created_at, rule_count, yaml) VALUES (?, ?, ?, ?, ?)",
                            (name[:200], (note or "")[:1000], time.time(), n, text))
            db.log_history(t, actor, "snapshot", detail={"id": cur.lastrowid, "name": name})
        return {"id": cur.lastrowid, "name": name, "rule_count": n}

    def restore_snapshot(self, sid, actor="dashboard"):
        row = self.db().execute("SELECT * FROM snapshots WHERE id = ?", (sid,)).fetchone()
        if not row:
            raise PolicyError("no such snapshot")
        backup = self.save_snapshot(f"auto: before restoring '{row['name']}'", actor=actor)
        res = self.import_yaml(row["yaml"], "replace", actor, event="restore")
        return dict(res, backup_snapshot=backup["id"])

    # --- agent API ------------------------------------------------------------------

    def agent_status(self, dest, port=None):
        policy = self.policy()
        ports = [port] if port else []
        st = policy.dest_status(dest, ports)
        return {"approved": "approved", "denied": "denied"}.get(st, "pending")

    def agent_blocked(self, src, since):
        c = self.db()
        out = {}
        for r in c.execute("SELECT COALESCE(hostname, dst_ip) AS dest, proto, port, SUM(blocked) AS n, "
                           "MAX(last_blocked) AS t FROM flows WHERE src_ip = ? AND last_blocked > ? "
                           "GROUP BY dest, proto, port", (src, since)):
            d = out.setdefault(r["dest"], {"dest": r["dest"], "ports": set(), "attempts": 0, "last": 0,
                                           "how": "connection rejected"})
            if r["proto"] in ("tcp", "udp"):
                d["ports"].add(f"{r['proto']}/{r['port']}")
            d["attempts"] += r["n"]
            d["last"] = max(d["last"], r["t"])
        for r in c.execute("SELECT qname, verdict, SUM(count) AS n, MAX(last_seen) AS t FROM dns WHERE src_ip = ? "
                           "AND verdict IN ('refused', 'denied') AND last_seen > ? GROUP BY qname, verdict",
                           (src, since)):
            d = out.setdefault(r["qname"], {"dest": r["qname"], "ports": set(), "attempts": 0, "last": 0,
                                            "how": "DNS answered NXDOMAIN by the gateway"})
            d["attempts"] += r["n"]
            d["last"] = max(d["last"], r["t"])
        res = []
        for d in sorted(out.values(), key=lambda d: -d["last"]):
            d["ports"] = sorted(d["ports"])
            d["status"] = self.agent_status(d["dest"], d["ports"][0] if len(d["ports"]) == 1 else None)
            res.append(d)
        return res

    def agent_request(self, src, body):
        now = time.time()
        hits = [t for t in self.rate.get(src, []) if now - t < 60]
        if len(hits) >= 30:
            raise PolicyError("rate limited: at most 30 requests per minute")
        self.rate[src] = hits + [now]
        dest = str(body.get("dest") or "").strip().lower().rstrip(".")
        kind = guess_kind(dest)
        dest = normalize_ip(dest) if kind == "ip" else normalize_host(dest)
        if dest.startswith("*."):
            raise PolicyError("request a concrete hostname, not a wildcard")
        port = body.get("port")
        if port:
            port = normalize_ports([port])[0]
        necessity = body.get("necessity") if body.get("necessity") in ("required", "optional") else None
        ctr = self.containers().get(src, {}).get("name") or src
        with db.tx(self.db()) as c:
            row = c.execute("SELECT * FROM requests WHERE dest = ?", (dest,)).fetchone()
            if row:
                ports = set(json.loads(row["ports"])) | ({port} if port else set())
                ctrs = set(json.loads(row["containers"])) | {src}
                c.execute("UPDATE requests SET last_seen = ?, ports = ?, containers = ?, dismissed_at = NULL "
                          "WHERE dest = ?", (now, json.dumps(sorted(ports)), json.dumps(sorted(ctrs)), dest))
            else:
                c.execute("INSERT INTO requests (dest, kind, source, first_seen, last_seen, attempts, ports, "
                          "containers) VALUES (?, ?, 'agent', ?, ?, 0, ?, ?)",
                          (dest, kind, now, now, json.dumps([port] if port else []), json.dumps([src])))
            c.execute("INSERT INTO agent_notes (dest, container, src_ip, ts, necessity, reason, task, port) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (dest, ctr, src, now, necessity, str(body.get("reason") or "")[:500],
                       str(body.get("task") or "")[:200], port))
        return {"dest": dest, "status": self.agent_status(dest, port)}


# --- HTTP plumbing ------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "agentgw"
    ctl = None
    routes = []

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else (
            body.encode() if isinstance(body, str) else json.dumps(body, default=_json_default).encode())
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 2_000_000:
            raise PolicyError("request too large")
        return self.rfile.read(n) if n else b""

    def _json(self):
        raw = self._body()
        try:
            return json.loads(raw or b"{}")
        except ValueError as e:
            raise PolicyError("invalid JSON") from e

    def _dispatch(self, method):
        url = urlparse(self.path)
        q = {k: v[-1] for k, v in parse_qs(url.query).items()}
        for m, pattern, fn in self.routes:
            if m != method:
                continue
            match = re.fullmatch(pattern, url.path)
            if match:
                try:
                    if not self.authorize(method, url.path):
                        return
                    return fn(self, q, *match.groups())
                except PolicyError as e:
                    return self._send(400, {"error": str(e)})
                except Exception as e:
                    log.exception("handler error")
                    return self._send(500, {"error": str(e)})
        self._send(404, {"error": "not found"})

    def authorize(self, method, path):
        return True

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")


def _json_default(o):
    if isinstance(o, set):
        return sorted(o)
    raise TypeError(type(o))


class AdminHandler(Handler):
    allowed_hosts = set()
    token = ""

    def authorize(self, method, path):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        if "*" not in self.allowed_hosts and host not in self.allowed_hosts:
            # Defends against DNS rebinding from a browser on the admin's machine.
            self._send(403, {"error": f"host {host!r} not allowed (set AGENTGW_ADMIN_HOSTS)"})
            return False
        if not path.startswith("/api/"):
            return True
        if self.token and self.headers.get("Authorization") != f"Bearer {self.token}":
            self._send(401, {"error": "missing or wrong token"})
            return False
        if method != "GET" and self.headers.get("X-AgentGW") != "1":
            # Custom header => cross-site forms cannot trigger changes (no CORS is ever granted).
            self._send(403, {"error": "missing X-AgentGW header"})
            return False
        return True


def _admin_routes():
    def static(h, q, name=""):
        name = name or "index.html"
        path = os.path.realpath(os.path.join(STATIC, name))
        if not path.startswith(os.path.realpath(STATIC) + os.sep) or not os.path.isfile(path):
            return h._send(404, {"error": "not found"})
        with open(path, "rb") as f:
            h._send(200, f.read(), mimetypes.guess_type(path)[0] or "application/octet-stream",
                    {"Content-Security-Policy": "default-src 'self'; style-src 'self'; script-src 'self'"})

    c = lambda h: h.ctl  # noqa: E731

    def snapshot_get(h, q, sid):
        row = c(h).db().execute("SELECT yaml, name FROM snapshots WHERE id = ?", (int(sid),)).fetchone()
        if not row:
            return h._send(404, {"error": "no such snapshot"})
        fn = re.sub(r"[^A-Za-z0-9_.-]+", "_", row["name"]) + ".yaml"
        h._send(200, row["yaml"], "application/yaml", {"Content-Disposition": f'attachment; filename="{fn}"'})

    def history(h, q):
        rows = c(h).db().execute("SELECT * FROM history ORDER BY id DESC LIMIT ?", (int(q.get("limit", 300)),))
        h._send(200, [dict(r, detail=json.loads(r["detail"]) if r["detail"] else None) for r in rows])

    def rules(h, q):
        now = time.time()
        h._send(200, [dict(r, expired=bool(r["expires_at"] and r["expires_at"] <= now))
                      for r in db.load_rules(c(h).db())])

    def intel_refresh(h, q):
        threading.Thread(target=c(h).refresh_intel, kwargs={"force": True}, daemon=True).start()
        h._send(202, {"started": True})

    return [
        ("GET", r"/", static),
        ("GET", r"/static/([A-Za-z0-9_.-]+)", static),
        ("GET", r"/api/status", lambda h, q: h._send(200, c(h).status())),
        ("GET", r"/api/destinations", lambda h, q: h._send(
            200, c(h).destinations(float(q.get("hours", 24)), q.get("q", "")))),
        ("GET", r"/api/destination", lambda h, q: h._send(200, c(h).destination_detail(q.get("dest", "")))),
        ("GET", r"/api/queue", lambda h, q: h._send(200, c(h).queue())),
        ("POST", r"/api/decide", lambda h, q: h._send(200, c(h).decide(h._json()))),
        ("GET", r"/api/rules", rules),
        ("POST", r"/api/rules", lambda h, q: h._send(200, c(h).add_rule(h._json()))),
        ("PUT", r"/api/rules/(\d+)", lambda h, q, rid: h._send(200, c(h).add_rule(dict(h._json(), id=int(rid))))),
        ("DELETE", r"/api/rules/(\d+)", lambda h, q, rid: h._send(200, c(h).delete_rule(int(rid)))),
        ("GET", r"/api/history", history),
        ("GET", r"/api/settings", lambda h, q: h._send(200, db.get_settings(c(h).db()))),
        ("POST", r"/api/settings", lambda h, q: h._send(200, c(h).update_settings(h._json()))),
        ("GET", r"/api/policy/export", lambda h, q: h._send(
            200, c(h).export_yaml(), "application/yaml",
            {"Content-Disposition": 'attachment; filename="agentgw-policy.yaml"'})),
        ("POST", r"/api/policy/import", lambda h, q: h._send(
            200, c(h).import_yaml(h._body().decode("utf-8"), q.get("mode", "replace")))),
        ("GET", r"/api/snapshots", lambda h, q: h._send(200, [dict(r) for r in c(h).db().execute(
            "SELECT id, name, note, created_at, rule_count FROM snapshots ORDER BY id DESC")])),
        ("POST", r"/api/snapshots", lambda h, q: h._send(200, c(h).save_snapshot(**{
            k: v for k, v in h._json().items() if k in ("name", "note")}))),
        ("GET", r"/api/snapshots/(\d+)", snapshot_get),
        ("POST", r"/api/snapshots/(\d+)/restore", lambda h, q, sid: h._send(200, c(h).restore_snapshot(int(sid)))),
        ("DELETE", r"/api/snapshots/(\d+)", lambda h, q, sid: (
            c(h).db().execute("DELETE FROM snapshots WHERE id = ?", (int(sid),)), h._send(200, {"ok": True}))),
        ("POST", r"/api/intel/refresh", intel_refresh),
    ]


AGENT_HELP = """agentgw agent API (read-only view of your own blocked traffic, plus access requests)

GET  /v1/blocked?since=<unix-ts>      destinations this container was blocked from
GET  /v1/check?dest=<host|ip>[&port=tcp/443]
POST /v1/request  {"dest": "...", "port": "tcp/443", "necessity": "required|optional",
                   "reason": "why the task needs it", "task": "short task name"}
GET  /v1/wait?dest=<host|ip>[&port=tcp/443]&timeout=<seconds, max 600>

Add ?format=text for plain text. Requests only inform the operator; they never grant access.
"""


class AgentHandler(Handler):
    def text(self, q):
        return q.get("format") == "text"


def _agent_routes():
    c = lambda h: h.ctl  # noqa: E731

    def blocked(h, q):
        since = float(q.get("since") or (time.time() - 3600))
        items = c(h).agent_blocked(h.client_address[0], since)
        if h.text(q):
            if not items:
                return h._send(200, "no blocked destinations\n", "text/plain")
            lines = [f"{i['dest']}\t{','.join(i['ports']) or '-'}\t{i['status']}\t{i['how']}" for i in items]
            return h._send(200, "\n".join(lines) + "\n", "text/plain")
        h._send(200, {"blocked": items})

    def check(h, q):
        dest = q.get("dest", "")
        port = normalize_ports([q["port"]])[0] if q.get("port") else None
        st = c(h).agent_status(dest, port)
        h._send(200, st + "\n" if h.text(q) else {"dest": dest, "status": st}, "text/plain" if h.text(q) else
                "application/json")

    def request(h, q):
        res = c(h).agent_request(h.client_address[0], h._json())
        h._send(200, res)

    def wait(h, q):
        dest = q.get("dest", "")
        port = normalize_ports([q["port"]])[0] if q.get("port") else None
        deadline = time.time() + min(float(q.get("timeout", 300)), 600)
        ctl, src = c(h), h.client_address[0]
        with ctl.wait_lock:
            if ctl.waiting.get(src, 0) >= 8:
                return h._send(429, {"error": "too many concurrent waits from this container"})
            ctl.waiting[src] = ctl.waiting.get(src, 0) + 1
        try:
            while True:
                st = ctl.agent_status(dest, port)
                if st != "pending" or time.time() >= deadline:
                    break
                time.sleep(1)
        finally:
            with ctl.wait_lock:
                ctl.waiting[src] -= 1
        h._send(200, st + "\n" if h.text(q) else {"dest": dest, "status": st}, "text/plain" if h.text(q) else
                "application/json")

    return [
        ("GET", r"/(?:v1/help)?", lambda h, q: h._send(200, AGENT_HELP, "text/plain")),
        ("GET", r"/v1/blocked", blocked),
        ("GET", r"/v1/check", check),
        ("POST", r"/v1/request", request),
        ("GET", r"/v1/wait", wait),
    ]


def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()


def main():
    logging.basicConfig(level=os.environ.get("AGENTGW_LOG", "INFO"),
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    cfg = config.load()
    ctl = Controller(cfg)
    host, _, port = cfg.admin_listen.rpartition(":")
    host = host.strip("[]")
    AdminHandler.ctl = AgentHandler.ctl = ctl
    AdminHandler.routes = _admin_routes()
    AgentHandler.routes = _agent_routes()
    AdminHandler.token = cfg.admin_token
    AdminHandler.allowed_hosts = {h.lower() for h in cfg.admin_hosts} | {"localhost", "127.0.0.1", "::1", host}
    admin = ThreadingHTTPServer((host, int(port)), AdminHandler)
    admin.daemon_threads = True
    _serve(admin)
    log.info("admin dashboard on http://%s:%s/", host, port)
    threading.Thread(target=ctl.intel_loop, daemon=True).start()
    while True:
        try:
            agent = ThreadingHTTPServer((str(cfg.gw4), cfg.agent_api_port), AgentHandler)
            agent.daemon_threads = True
            _serve(agent)
            log.info("agent API on http://%s:%d/", cfg.gw4, cfg.agent_api_port)
            break
        except OSError as e:
            log.warning("agent API not up (%s); retrying", e)
            time.sleep(3)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
