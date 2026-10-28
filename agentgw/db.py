"""SQLite storage shared by the gateway (privileged) and controller (web).

The database is the only interface between the two processes:
  * the controller writes rules/settings and bumps meta.policy_version;
  * the gateway notices the bump, applies the policy atomically to nftables and
    records meta.applied_version (or meta.apply_error);
  * the gateway writes observations (flows, DNS, containers, requests).
"""

import json
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL CHECK (action IN ('allow', 'deny')),
    kind TEXT NOT NULL CHECK (kind IN ('host', 'ip')),
    value TEXT NOT NULL,
    ports TEXT NOT NULL DEFAULT '["*"]',
    note TEXT NOT NULL DEFAULT '',
    expires_at REAL,
    created_at REAL NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated_at REAL NOT NULL,
    UNIQUE (kind, value)
);
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, actor TEXT NOT NULL, event TEXT NOT NULL,
    kind TEXT, value TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS containers (
    ip TEXT PRIMARY KEY, name TEXT, cid TEXT, info TEXT,
    first_seen REAL, last_seen REAL
);
CREATE TABLE IF NOT EXISTS dns (
    src_ip TEXT NOT NULL, qname TEXT NOT NULL, qtype TEXT NOT NULL,
    verdict TEXT NOT NULL, rcode TEXT, answers TEXT,
    count INTEGER NOT NULL DEFAULT 0, first_seen REAL, last_seen REAL,
    PRIMARY KEY (src_ip, qname, qtype)
);
CREATE TABLE IF NOT EXISTS ip_names (
    ip TEXT NOT NULL, name TEXT NOT NULL, last_seen REAL NOT NULL,
    PRIMARY KEY (ip, name)
);
CREATE TABLE IF NOT EXISTS flows (
    src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, proto TEXT NOT NULL, port INTEGER NOT NULL,
    hostname TEXT,
    conns INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0,
    unmatched INTEGER NOT NULL DEFAULT 0, denied INTEGER NOT NULL DEFAULT 0,
    tx_bytes INTEGER NOT NULL DEFAULT 0, tx_pkts INTEGER NOT NULL DEFAULT 0,
    rx_bytes INTEGER NOT NULL DEFAULT 0, rx_pkts INTEGER NOT NULL DEFAULT 0,
    first_seen REAL, last_seen REAL, last_blocked REAL,
    PRIMARY KEY (src_ip, dst_ip, proto, port)
);
CREATE INDEX IF NOT EXISTS flows_host ON flows (hostname);
CREATE INDEX IF NOT EXISTS flows_dst ON flows (dst_ip);
CREATE TABLE IF NOT EXISTS requests (
    dest TEXT PRIMARY KEY, kind TEXT NOT NULL,
    source TEXT NOT NULL, first_seen REAL, last_seen REAL,
    attempts INTEGER NOT NULL DEFAULT 0, ports TEXT NOT NULL DEFAULT '[]',
    containers TEXT NOT NULL DEFAULT '[]', dismissed_at REAL
);
CREATE TABLE IF NOT EXISTS agent_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dest TEXT NOT NULL, container TEXT, src_ip TEXT, ts REAL NOT NULL,
    necessity TEXT, reason TEXT, task TEXT, port TEXT
);
CREATE INDEX IF NOT EXISTS agent_notes_dest ON agent_notes (dest);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, note TEXT, created_at REAL NOT NULL,
    rule_count INTEGER NOT NULL, yaml TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS intel (key TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at REAL NOT NULL);
"""

DEFAULT_SETTINGS = {
    # observe: record everything, block only explicit deny rules.
    # enforce: default deny; only allow rules pass.
    "mode": "observe",
    # In enforce mode, what the resolver does for names with no rule:
    #   refuse  - answer NXDOMAIN without asking upstream (closes the DNS
    #             exfiltration channel; the review item has no port yet)
    #   resolve - resolve normally; the connection is then blocked and the
    #             review item shows the port (upstream sees the query)
    "unapproved_dns": "refuse",
    # DNS-derived allowances live at least this long (apps cache DNS longer
    # than record TTLs) and at most dns_max_ttl after the last lookup.
    "dns_min_ttl": 3600,
    "dns_max_ttl": 86400,
    "auto_block_malicious": False,
    "watch_countries": ["CN", "RU", "KP", "IR"],
    "geoip": True,
    "intel_feeds": {"feodo": True, "urlhaus": True, "threatfox": True,
                    "spamhaus_drop": True, "tor_exits": True},
    "default_temp_hours": 24,
    "retention_days": 30,
}

# Settings the gateway applies to the kernel/resolver. Changing them bumps
# the policy version so the gateway picks them up.
GATEWAY_SETTINGS = ("mode", "unapproved_dns", "dns_min_ttl", "dns_max_ttl", "auto_block_malicious")


def connect(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init(conn):
    conn.executescript(SCHEMA)
    conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('policy_version', '1')")


class tx:
    """BEGIN IMMEDIATE ... COMMIT, so read-modify-write sequences are atomic."""

    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def __exit__(self, exc_type, exc, tb):
        self.conn.execute("ROLLBACK" if exc_type else "COMMIT")
        return False


def get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn, key, value):
    conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) "
                 "ON CONFLICT (key) DO UPDATE SET value = excluded.value", (key, str(value)))


def bump_policy(conn):
    conn.execute("UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'policy_version'")
    return int(get_meta(conn, "policy_version"))


def get_settings(conn):
    s = json.loads(json.dumps(DEFAULT_SETTINGS))
    for row in conn.execute("SELECT key, value FROM settings"):
        if row["key"] in s:
            s[row["key"]] = json.loads(row["value"])
    return s


def set_setting(conn, key, value):
    conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                 "ON CONFLICT (key) DO UPDATE SET value = excluded.value", (key, json.dumps(value)))


def row_to_rule(row):
    r = dict(row)
    r["ports"] = json.loads(r["ports"])
    return r


def load_rules(conn):
    return [row_to_rule(r) for r in conn.execute("SELECT * FROM rules ORDER BY id")]


def log_history(conn, actor, event, kind=None, value=None, detail=None):
    conn.execute("INSERT INTO history (ts, actor, event, kind, value, detail) VALUES (?, ?, ?, ?, ?, ?)",
                 (time.time(), actor, event, kind, value, json.dumps(detail) if detail is not None else None))


def upsert_rule(conn, rule, actor):
    """Insert or replace the rule for (kind, value). Caller bumps the policy."""
    now = time.time()
    old = conn.execute("SELECT * FROM rules WHERE kind = ? AND value = ?",
                       (rule["kind"], rule["value"])).fetchone()
    if old:
        conn.execute("UPDATE rules SET action = ?, ports = ?, note = ?, expires_at = ?, updated_at = ?, "
                     "created_by = ? WHERE id = ?",
                     (rule["action"], json.dumps(rule["ports"]), rule["note"], rule["expires_at"], now,
                      actor, old["id"]))
        rid = old["id"]
    else:
        cur = conn.execute("INSERT INTO rules (action, kind, value, ports, note, expires_at, created_at, "
                           "created_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (rule["action"], rule["kind"], rule["value"], json.dumps(rule["ports"]),
                            rule["note"], rule["expires_at"], now, actor, now))
        rid = cur.lastrowid
    log_history(conn, actor, rule["action"], rule["kind"], rule["value"],
                {"ports": rule["ports"], "expires_at": rule["expires_at"], "note": rule["note"],
                 "previous": dict(old) if old else None})
    return rid


def delete_rule(conn, rid, actor, event="remove"):
    old = conn.execute("SELECT * FROM rules WHERE id = ?", (rid,)).fetchone()
    if not old:
        return False
    conn.execute("DELETE FROM rules WHERE id = ?", (rid,))
    log_history(conn, actor, event, old["kind"], old["value"], {"previous": dict(old)})
    return True


def replace_rules(conn, rules, actor, event):
    """Swap the whole rule set (snapshot restore / import-replace)."""
    conn.execute("DELETE FROM rules")
    now = time.time()
    for r in rules:
        conn.execute("INSERT INTO rules (action, kind, value, ports, note, expires_at, created_at, "
                     "created_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (r["action"], r["kind"], r["value"], json.dumps(r["ports"]), r["note"],
                      r["expires_at"], now, actor, now))
    log_history(conn, actor, event, detail={"rule_count": len(rules)})
