"""Destination context from public data: country/ASN and threat indicators.

Everything is offline lookups against files refreshed in the background, so
destinations are never sent to a third-party API.

Sources (each can be disabled in Settings; see docs/THREAT-INTEL.md):
  geo       DB-IP "Lite" country + ASN databases (CC BY 4.0, monthly, no
            account). Any MaxMind-format .mmdb dropped into the intel dir as
            country.mmdb / asn.mmdb (e.g. GeoLite2) is used instead.
  feodo     abuse.ch Feodo Tracker botnet C2 IPs           -> malicious
  urlhaus   abuse.ch URLhaus malware distribution hosts    -> malicious
  threatfox abuse.ch ThreatFox IOC hosts                   -> malicious
  spamhaus_drop  Spamhaus DROP hijacked/criminal netblocks -> malicious
  tor_exits Tor Project exit relay list                    -> info only

"malicious" means a curated list of verified indicators. Everything else
(watched countries, direct-IP use, unusual ports, punycode) is a weak signal
for human review and never blocks anything.
"""

import bisect
import gzip
import ipaddress
import json
import logging
import os
import time
import urllib.request

log = logging.getLogger("agentgw.intel")

FEEDS = {
    "feodo": {"urls": ["https://feodotracker.abuse.ch/downloads/ipblocklist.txt"], "kind": "ip",
              "strength": "malicious", "label": "Feodo Tracker botnet C2", "abusech": True},
    "urlhaus": {"urls": ["https://urlhaus.abuse.ch/downloads/hostfile/"], "kind": "domain",
                "strength": "malicious", "label": "URLhaus malware distribution host", "abusech": True},
    "threatfox": {"urls": ["https://threatfox.abuse.ch/downloads/hostfile/"], "kind": "domain",
                  "strength": "malicious", "label": "ThreatFox IOC", "abusech": True},
    "spamhaus_drop": {"urls": ["https://www.spamhaus.org/drop/drop_v4.json",
                               "https://www.spamhaus.org/drop/drop_v6.json"], "kind": "cidr",
                      "strength": "malicious", "label": "Spamhaus DROP netblock"},
    "tor_exits": {"urls": ["https://check.torproject.org/torbulkexitlist"], "kind": "ip",
                  "strength": "info", "label": "Tor exit relay"},
}
FEED_MAX_AGE = 12 * 3600
GEO_MAX_AGE = 14 * 86400
COMMON_PORTS = {"tcp/80", "tcp/443", "udp/443", "tcp/22", "udp/123", "tcp/53", "udp/53"}


def parse_feed(kind, text):
    """Return a list of normalized entries (domains or IP/CIDR strings)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("{"):  # Spamhaus NDJSON: {"cidr": ..., "sblid": ...}
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            line = obj.get("cidr") or ""
            if not line:
                continue
        token = line.split()[-1] if kind == "domain" else line.split()[0].split(";")[0]
        if kind == "domain":
            token = token.lower().rstrip(".")
            if token in ("localhost",) or "." not in token:
                continue
            try:
                ipaddress.ip_address(token)
                continue  # hostfile entries that are IPs
            except ValueError:
                out.append(token)
        else:
            try:
                out.append(str(ipaddress.ip_network(token, strict=False)))
            except ValueError:
                continue
    return out


class NetIndex:
    """Sorted-interval lookup for many CIDRs."""

    def __init__(self, nets):
        self.idx = {4: [], 6: []}
        for n in nets:
            n = ipaddress.ip_network(n)
            self.idx[n.version].append((int(n.network_address), int(n.broadcast_address)))
        for v in self.idx:
            self.idx[v].sort()
        self.starts = {v: [s for s, _ in self.idx[v]] for v in self.idx}

    def __contains__(self, ip):
        a = ipaddress.ip_address(ip)
        i = bisect.bisect_right(self.starts[a.version], int(a)) - 1
        return i >= 0 and self.idx[a.version][i][1] >= int(a)


class Intel:
    def __init__(self, data_dir, abusech_key=""):
        self.dir = os.path.join(data_dir, "intel")
        os.makedirs(self.dir, exist_ok=True)
        self.abusech_key = abusech_key
        self.feeds = {}   # name -> {"set"|"index", "fetched_at", "error", "count"}
        self.geo = {}     # "country"/"asn" -> maxminddb reader
        self.status = {}
        self.load_cached()

    # --- storage ------------------------------------------------------------

    def _feed_path(self, name):
        return os.path.join(self.dir, f"feed-{name}.json")

    def _install(self, name, entries, fetched_at):
        spec = FEEDS[name]
        if spec["kind"] == "domain":
            self.feeds[name] = {"set": set(entries), "fetched_at": fetched_at, "count": len(entries)}
        else:
            self.feeds[name] = {"index": NetIndex(entries), "fetched_at": fetched_at, "count": len(entries)}

    def load_cached(self):
        for name in FEEDS:
            try:
                with open(self._feed_path(name)) as f:
                    d = json.load(f)
                self._install(name, d["entries"], d["fetched_at"])
            except (OSError, ValueError, KeyError):
                pass
        self._open_geo()

    def _open_geo(self):
        try:
            import maxminddb
        except ImportError:
            return
        for kind in ("country", "asn"):
            path = os.path.join(self.dir, f"{kind}.mmdb")
            if os.path.exists(path):
                try:
                    self.geo[kind] = maxminddb.open_database(path)
                except (OSError, ValueError) as e:
                    self.status[f"geo-{kind}"] = f"cannot open {path}: {e}"

    # --- refresh --------------------------------------------------------------

    def _fetch(self, url, abusech=False):
        req = urllib.request.Request(url, headers={"User-Agent": "agentgw/0.1"})
        if abusech and self.abusech_key:
            req.add_header("Auth-Key", self.abusech_key)
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read()

    def refresh(self, enabled, geo_enabled=True, force=False):
        """Download stale feeds. Returns {name: status string}."""
        now = time.time()
        for name, spec in FEEDS.items():
            if not enabled.get(name):
                self.feeds.pop(name, None)
                self.status[name] = "disabled"
                continue
            cur = self.feeds.get(name)
            if cur and not force and now - cur["fetched_at"] < FEED_MAX_AGE:
                continue
            try:
                entries = []
                for url in spec["urls"]:
                    entries += parse_feed(spec["kind"], self._fetch(url, spec.get("abusech")).decode("utf-8", "replace"))
                if not entries:
                    raise ValueError("feed returned no entries")
                with open(self._feed_path(name) + ".tmp", "w") as f:
                    json.dump({"fetched_at": now, "entries": entries}, f)
                os.replace(self._feed_path(name) + ".tmp", self._feed_path(name))
                self._install(name, entries, now)
                self.status[name] = f"ok: {len(entries)} entries"
            except Exception as e:  # network, HTTP 401/403 (missing Auth-Key), parse errors
                hint = " (set ABUSECH_AUTH_KEY)" if spec.get("abusech") and not self.abusech_key else ""
                self.status[name] = f"error: {e}{hint}"
                log.warning("feed %s: %s%s", name, e, hint)
        if geo_enabled:
            self._refresh_geo(force)
        return dict(self.status)

    def _refresh_geo(self, force):
        for kind, slug in (("country", "country"), ("asn", "asn")):
            path = os.path.join(self.dir, f"{kind}.mmdb")
            if os.path.exists(path) and not force and time.time() - os.path.getmtime(path) < GEO_MAX_AGE:
                continue
            if os.path.exists(path + ".manual"):
                continue  # operator-provided database (e.g. GeoLite2): never overwrite
            t = time.gmtime()
            months = [(t.tm_year, t.tm_mon), (t.tm_year - (t.tm_mon == 1), (t.tm_mon - 2) % 12 + 1)]
            err = None
            for y, m in months:
                url = f"https://download.db-ip.com/free/dbip-{slug}-lite-{y:04d}-{m:02d}.mmdb.gz"
                try:
                    data = gzip.decompress(self._fetch(url))
                    with open(path + ".tmp", "wb") as f:
                        f.write(data)
                    os.replace(path + ".tmp", path)
                    self.status[f"geo-{kind}"] = f"ok: DB-IP lite {y:04d}-{m:02d}"
                    err = None
                    break
                except Exception as e:
                    err = e
            if err:
                self.status[f"geo-{kind}"] = f"error: {err}"
        self._open_geo()

    def blocklist(self):
        """Verified-malicious indicators for the gateway's optional auto-block."""
        ips, domains = [], []
        for name, f in self.feeds.items():
            if FEEDS[name]["strength"] != "malicious":
                continue
            if "set" in f:
                domains += sorted(f["set"])
            else:
                for v in (4, 6):
                    for s, e in f["index"].idx[v]:
                        first = ipaddress.ip_address(s)
                        last = ipaddress.ip_address(e)
                        ips += [str(n) for n in ipaddress.summarize_address_range(first, last)]
        return {"ips": ips, "domains": domains}

    # --- lookups ---------------------------------------------------------------

    def geo_lookup(self, ip):
        out = {}
        try:
            c = self.geo.get("country")
            if c:
                rec = c.get(ip) or {}
                country = rec.get("country") or rec.get("registered_country") or {}
                out["country"] = country.get("iso_code")
                out["country_name"] = (country.get("names") or {}).get("en")
            a = self.geo.get("asn")
            if a:
                rec = a.get(ip) or {}
                out["asn"] = rec.get("autonomous_system_number")
                out["as_org"] = rec.get("autonomous_system_organization")
        except ValueError:
            pass
        return out

    def domain_hits(self, name):
        hits = []
        parts = name.lower().split(".")
        candidates = {".".join(parts[i:]) for i in range(len(parts) - 1)}
        for fname, f in self.feeds.items():
            if "set" in f:
                if name in f["set"]:
                    hits.append({"strength": FEEDS[fname]["strength"], "source": fname,
                                 "detail": FEEDS[fname]["label"]})
                elif candidates & f["set"]:
                    hits.append({"strength": "suspicious", "source": fname,
                                 "detail": f"parent domain listed by {FEEDS[fname]['label']}"})
        return hits

    def ip_hits(self, ip):
        hits = []
        for fname, f in self.feeds.items():
            if "index" in f and ip in f["index"]:
                hits.append({"strength": FEEDS[fname]["strength"], "source": fname, "detail": FEEDS[fname]["label"]})
        return hits

    def assess(self, dest, ips, ports, watch_countries):
        """Context for one aggregated destination (hostname or IP)."""
        is_ip = _is_ip(dest)
        indicators = [] if is_ip else self.domain_hits(dest)
        geo = []
        for ip in sorted(set(ips))[:16]:
            g = self.geo_lookup(ip)
            g["ip"] = ip
            geo.append(g)
            for h in self.ip_hits(ip):
                h = dict(h, detail=f"{h['detail']} ({ip})")
                indicators.append(h)
        signals = []
        countries = sorted({g["country"] for g in geo if g.get("country")})
        watched = [c for c in countries if c in set(watch_countries)]
        if watched:
            signals.append(f"hosted in watched country: {', '.join(watched)}")
        if is_ip:
            signals.append("direct IP connection (no DNS name seen)")
        elif any(label.startswith("xn--") for label in dest.split(".")):
            signals.append("internationalized (punycode) hostname")
        odd = sorted(p for p in ports if p not in COMMON_PORTS)
        if odd:
            signals.append("uncommon port: " + ", ".join(odd[:5]))
        level = "malicious" if any(h["strength"] == "malicious" for h in indicators) else (
            "suspicious" if any(h["strength"] == "suspicious" for h in indicators) else (
                "review" if watched else "none"))
        return {"level": level, "indicators": indicators, "signals": signals, "countries": countries,
                "asns": sorted({f"AS{g['asn']} {g.get('as_org') or ''}".strip() for g in geo if g.get("asn")}),
                "geo": geo}


def _is_ip(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False
