#!/usr/bin/env python3
"""End-to-end acceptance test on a real Docker host (run as root).

Brings up the real stack (docker compose), a simulated internet in a network
namespace (sim_inet.sh) and throwaway agent containers, then walks through the
acceptance criteria against the real kernel firewall. Nothing is mocked.

    sudo python3 tests/e2e/run.py            # builds the image first
    AGENTGW_E2E_NO_BUILD=1 sudo -E python3 tests/e2e/run.py

It refuses to run if a dashboard is already listening on 127.0.0.1:8080
(an agentgw stack that is not the test stack), and removes everything it
created at the end (pass --keep to leave it running for inspection).
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
E2E = os.path.join(ROOT, "tests", "e2e")
PROJECT = "agentgw-e2e"
COMPOSE = ["docker", "compose", "-p", PROJECT, "-f", os.path.join(ROOT, "docker-compose.yml"),
           "-f", os.path.join(E2E, "compose.e2e.yml")]
API = "http://127.0.0.1:8080"
AGENT_API = "http://172.30.0.1:8081"
AGENTS = ["e2e-agent-a", "e2e-agent-b", "e2e-agent-nodns"]
# The agent tools (agentgw-net, agentgw-hook) need curl in the agent image.
AGENT_IMAGE = os.environ.get("AGENTGW_E2E_AGENT_IMAGE", "agentgw:local")

results = []


def sh(*args, check=True, **kw):
    p = subprocess.run(args, text=True, capture_output=True, **kw)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} failed: {p.stderr.strip() or p.stdout.strip()}")
    return p


def check(ac, name, ok, detail=""):
    results.append((ac, name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  [{ac}] {name}" + (f"  -- {detail}" if detail and not ok else ""))


def api(path, body=None, method=None, raw=False):
    data = None
    headers = {"X-AgentGW": "1"}
    if body is not None:
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        headers["Content-Type"] = "application/yaml" if isinstance(body, str) else "application/json"
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method or ("POST" if data else "GET"))
    with urllib.request.urlopen(req, timeout=30) as r:
        text = r.read().decode()
        return text if raw else json.loads(text)


def probe(agent, *args):
    p = sh("docker", "exec", agent, "python3", "/e2e/probe.py", *args, check=False)
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"ok": False, "error": p.stderr.strip()}


def agent_curl(agent, path, body=None, timeout=30):
    code = ("import json,sys,urllib.request as u;"
            "d=sys.argv[2].encode() if sys.argv[2] else None;"
            "r=u.Request(sys.argv[1],data=d,headers={'Content-Type':'application/json'});"
            "print(u.urlopen(r,timeout=%d).read().decode())" % timeout)
    p = sh("docker", "exec", agent, "python3", "-c", code, AGENT_API + path, json.dumps(body) if body else "",
           check=False)
    try:
        return json.loads(p.stdout)
    except ValueError:
        return {"error": p.stderr.strip() or p.stdout}


def wait_for(fn, timeout=15, interval=0.5):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(interval)
    return fn()


def dest(name):
    return next((d for d in api("/api/destinations?hours=1") if d["dest"] == name), None)


def queue_item(name):
    return next((d for d in api("/api/queue") if d["dest"] == name), None)


def sim_queries():
    try:
        with open("/tmp/agw-sim.log") as f:
            return [line.split()[1] for line in f if line.startswith("query ")]
    except OSError:
        return []


# --- setup / teardown ---------------------------------------------------------

def setup():
    if os.geteuid() != 0:
        sys.exit("run as root (needs nft, ip netns, docker)")
    try:
        socket.create_connection(("127.0.0.1", 8080), timeout=1).close()
        if PROJECT not in sh("docker", "ps", "--format", "{{.Names}}").stdout:
            sys.exit("something already listens on 127.0.0.1:8080 (another agentgw stack?); stop it first")
    except OSError:
        pass
    print("setup: simulated internet, network, stack, agents")
    sh(os.path.join(E2E, "sim_inet.sh"), "down", check=False)
    sh(os.path.join(E2E, "sim_inet.sh"), "up")
    sh(os.path.join(ROOT, "scripts", "setup.sh"), cwd=ROOT)
    sh(*COMPOSE, "down", "-v", check=False)
    sh("nft", "delete", "table", "inet", "agentgw", check=False)
    if not os.environ.get("AGENTGW_E2E_NO_BUILD"):
        sh(*COMPOSE, "build")
    sh(*COMPOSE, "up", "-d")
    for a in AGENTS:
        sh("docker", "rm", "-f", a, check=False)
        args = ["docker", "run", "-d", "--name", a, "--network", "agentgw-agents",
                "-v", f"{E2E}:/e2e:ro",
                "-v", f"{ROOT}/agent/agentgw-net:/usr/local/bin/agentgw-net:ro",
                "-v", f"{ROOT}/agent/agentgw-hook:/usr/local/bin/agentgw-hook:ro",
                AGENT_IMAGE, "sleep", "infinity"]
        if a != "e2e-agent-nodns":
            args[5:5] = ["--dns", "172.30.0.1"]
        sh(*args)
    sh("docker", "rm", "-f", "e2e-unmanaged", check=False)
    sh("docker", "run", "-d", "--name", "e2e-unmanaged", "-v", f"{E2E}:/e2e:ro", "agentgw:local", "sleep", "infinity")
    wait_for(lambda: _status_ok(), timeout=30)
    wait_for(lambda: len(api("/api/status")["containers"]) >= 3, timeout=30)


def _status_ok():
    try:
        return api("/api/status")["gateway_alive"]
    except (urllib.error.URLError, OSError, ValueError):
        return False


def teardown():
    for a in AGENTS + ["e2e-unmanaged"]:
        sh("docker", "rm", "-f", a, check=False)
    sh(*COMPOSE, "down", "-v", check=False)
    sh("nft", "delete", "table", "inet", "agentgw", check=False)
    sh(os.path.join(E2E, "sim_inet.sh"), "down", check=False)


# --- scenarios -------------------------------------------------------------------

def observe_phase():
    print("\n1. observation mode")
    a, b = "e2e-agent-a", "e2e-agent-b"
    for _ in range(3):
        probe(a, "http", "allowed.test")
    probe(b, "http", "allowed.test")
    probe(a, "http", "other.test")
    probe(a, "udp", "udp.test", "5000")
    probe(a, "http", "cn-host.test")
    r = probe(a, "http", "203.0.113.13")
    check("AC1", "observe mode does not block unknown destinations", r["ok"], r)
    d = wait_for(lambda: (x := dest("allowed.test")) and x["conns"] >= 4 and x)
    check("AC2", "hostname aggregated across containers (one row, 4 conns)",
          d and d["conns"] >= 4 and set(d["containers"]) >= {a, b}, d)
    check("AC2", "port and protocol recorded", d and d["ports"] == ["tcp/80"], d and d["ports"])
    check("AC2", "traffic statistics recorded", d and d["tx_bytes"] > 0 and d["rx_bytes"] > 0)
    u = wait_for(lambda: dest("udp.test"))
    check("AC2", "UDP destination recorded", u and u["ports"] == ["udp/5000"], u)
    ip = wait_for(lambda: dest("203.0.113.13"))
    check("AC2", "direct IP connection visible without hostname", ip and ip["kind"] == "ip", ip)
    check("AC2", "observed destinations are unreviewed, not trusted", d and d["status"] == "unreviewed")
    st = api("/api/status")
    nodns = [c for c in st["containers"] if c["name"] == "e2e-agent-nodns"]
    check("AC2", "container without gateway DNS is flagged", nodns and any("DNS" in w for w in nodns[0]["warnings"]))


def enforce_phase():
    print("\n2. approve the profile and enforce")
    a, b = "e2e-agent-a", "e2e-agent-b"
    r1 = api("/api/decide", {"dest": "allowed.test", "action": "approve"})
    r2 = api("/api/decide", {"dest": "udp.test", "action": "approve"})
    r3 = api("/api/rules", {"action": "allow", "value": "stream.test", "ports": ["tcp/9000"]})
    check("AC3", "approvals applied by the gateway", r1["applied"] and r2["applied"] and r3["applied"], (r1, r2, r3))
    check("AC3", "approval takes the observed ports", r1["rule"]["ports"] == ["tcp/80"], r1["rule"])
    r = api("/api/settings", {"mode": "enforce"})
    check("AC3", "enforcement mode applied", r["applied"], r)
    check("AC4", "approved hostname still reachable", probe(a, "http", "allowed.test")["ok"])
    check("AC4", "approved UDP destination still reachable", probe(a, "udp", "udp.test", "5000")["ok"])
    before = len(sim_queries())
    r = probe(a, "http", "other.test")
    check("AC5", "unapproved hostname blocked (NXDOMAIN)", not r["ok"] and "gaierror" in r.get("error", ""), r)
    check("AC5", "refused name never sent upstream (no DNS exfiltration)", "other.test" not in sim_queries()[before:])
    r = probe(a, "dns", "x7f3a9.exfil.other.test")
    check("AC5", "arbitrary subdomain lookups also stay local",
          not r["ok"] and "x7f3a9.exfil.other.test" not in sim_queries()[before:])
    r = probe(a, "http", "203.0.113.11")
    check("AC14", "direct IP of unapproved host rejected", not r["ok"] and "Refused" in r.get("error", ""), r)
    r = probe(a, "http", "203.0.113.13")
    check("AC14", "hardcoded never-resolved IP rejected", not r["ok"], r)
    r = probe(a, "tcp", "203.0.113.10", "9000")
    check("AC14", "approved host's IP on unapproved port rejected", not r["ok"], r)
    r = probe(a, "dnsdirect", "other.test", "8.8.8.8")
    check("AC14", "DNS to an outside resolver is answered by the gateway", r.get("rcode") == 3, r)
    probe(b, "http", "other.test")
    q = wait_for(lambda: (x := queue_item("other.test")) and len(x["containers"]) >= 2 and x)
    check("AC6", "blocked destination appears once in the queue with both containers", q, q)
    check("AC6", "queue lists every blocked destination",
          wait_for(lambda: queue_item("203.0.113.13")) and wait_for(lambda: queue_item("allowed.test")))
    st = probe(a, "tcp", "172.30.0.1", "8080")
    check("SEC", "agents cannot reach the admin dashboard on the host", not st["ok"], st)
    r = probe("e2e-unmanaged", "http", "203.0.113.11")
    check("SEC", "containers outside the agents network are not affected", r["ok"], r)


def approve_flow():
    print("\n3. approve from the queue, agent retries without restart")
    a = "e2e-agent-a"
    agent_curl(a, "/v1/request", {"dest": "other.test", "port": "tcp/80", "necessity": "required",
                                  "reason": "fetch build docs", "task": "e2e"})
    q = queue_item("other.test")
    check("AC6", "agent reason and necessity shown with the queue item",
          q and q["necessity"] == "required" and q["notes"] and q["notes"][0]["reason"] == "fetch build docs", q)
    waiter = {}
    t = threading.Thread(target=lambda: waiter.update(agent_curl(a, "/v1/wait?dest=other.test&timeout=30", timeout=40)))
    t.start()
    time.sleep(1)
    t0 = time.time()
    r = api("/api/decide", {"dest": "other.test", "action": "approve"})
    check("AC7", "approve through the dashboard API applied", r["applied"], r)
    check("AC7", "approval applied within 2 seconds", time.time() - t0 < 2, time.time() - t0)
    r = probe(a, "http", "other.test")
    check("AC8", "container reaches the approved destination without restart", r["ok"], r)
    t.join(45)
    check("AC8", "agent API wait returns 'approved'", waiter.get("status") == "approved", waiter)
    check("AC6", "approved item leaves the queue", not queue_item("other.test"))


def revoke_flow():
    print("\n4. block an already connected destination")
    a = "e2e-agent-a"
    out = {}
    t = threading.Thread(target=lambda: out.update(probe(a, "stream", "stream.test", "9000", "10")))
    t.start()
    time.sleep(2.5)
    est = sh("conntrack", "-L", "-d", "203.0.113.14", check=False).stdout.count("ESTABLISHED")
    check("AC9", "long-lived connection established before block", est >= 1, est)
    t0 = time.time()
    r = api("/api/decide", {"dest": "stream.test", "action": "block"})
    took = time.time() - t0
    check("AC9", "block applied", r["applied"], r)
    t.join(20)
    check("AC10", "existing connection interrupted", not out.get("ok") and out.get("after", 99) < 8, out)
    check("AC10", "conntrack entry removed",
          sh("conntrack", "-L", "-d", "203.0.113.14", check=False).stdout.count("ESTABLISHED") == 0)
    check("AC10", "new connections by name fail", not probe(a, "tcp", "stream.test", "9000")["ok"])
    check("AC10", "new connections by cached IP fail", not probe(a, "tcp", "203.0.113.14", "9000")["ok"])
    check("AC9", "block saved and applied within 2 seconds", took < 2, f"{took:.2f}s")


def restart_flow():
    print("\n5. persistence across restarts and gateway failure")
    a = "e2e-agent-a"
    sh(*COMPOSE, "stop", "gateway")
    check("REL", "gateway stopped: unapproved still blocked (fail closed)", not probe(a, "http", "203.0.113.13")["ok"])
    check("REL", "gateway stopped: established approvals keep working", probe(a, "http", "203.0.113.10")["ok"])
    sh(*COMPOSE, "restart", "controller")
    started = time.time()
    sh(*COMPOSE, "start", "gateway")
    # The heartbeat in the database is stale until the new gateway writes one.
    wait_for(lambda: _status_ok() and api("/api/status")["gateway_heartbeat"] > started, timeout=30)
    rules = api("/api/rules")
    check("AC11", "whitelist survives restart", {r["value"] for r in rules} >= {"allowed.test", "udp.test", "other.test"})
    check("AC11", "enforcement mode survives restart", api("/api/settings")["mode"] == "enforce")
    r = probe(a, "http", "allowed.test")
    check("AC11", "approved destination works after restart", r["ok"], r)
    check("AC11", "blocked destination still blocked after restart", not probe(a, "http", "stream.test")["ok"])


def failsafe_flow():
    print("\n5b. boot fail-safe and self-repair")
    a = "e2e-agent-a"
    sh(*COMPOSE, "stop", "gateway")
    sh("nft", "-f", os.path.join(ROOT, "host", "agentgw-failsafe.nft"))
    check("REL", "boot fail-safe blocks agents before the gateway runs", not probe(a, "http", "203.0.113.10")["ok"])
    started = time.time()
    sh(*COMPOSE, "start", "gateway")
    wait_for(lambda: _status_ok() and api("/api/status")["gateway_heartbeat"] > started, timeout=30)
    check("REL", "gateway replaces the fail-safe table and restores approvals", probe(a, "http", "allowed.test")["ok"])
    sh("nft", "delete", "table", "inet", "agentgw")
    check("REL", "flushed rules are detected and re-applied by the gateway",
          wait_for(lambda: sh("nft", "list", "set", "inet", "agentgw", "schema_v1", check=False).returncode == 0,
                   timeout=20))
    check("REL", "enforcement back after self-repair",
          not probe(a, "http", "203.0.113.13")["ok"] and wait_for(lambda: probe(a, "http", "allowed.test")["ok"], 10))
    out = sh(*COMPOSE, "exec", "-T", "controller", "python3", "-m", "agentgw.admin", "status", check=False).stdout
    check("REL", "admin CLI works without the dashboard", '"mode": "enforce"' in out, out)


def agent_tools_flow():
    print("\n9. agent tools: agentgw-net and the PostToolUse hook")
    a = "e2e-agent-a"
    if sh("docker", "exec", a, "sh", "-c", "command -v curl", check=False).returncode != 0:
        print("  SKIP  [AC15] agent image has no curl (set AGENTGW_E2E_AGENT_IMAGE to one with curl)")
        return
    sh("docker", "exec", a, "sh", "-c", "curl -s -m 3 http://tools-check.test/ || true", check=False)
    hook_in = json.dumps({"session_id": "e2e-session", "hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                          "tool_input": {"command": "curl http://tools-check.test/"},
                          "error": "curl: (6) Could not resolve host: tools-check.test"})
    p = subprocess.run(["docker", "exec", "-i", a, "agentgw-hook"], input=hook_in, text=True, capture_output=True)
    try:
        ctx = json.loads(p.stdout)["hookSpecificOutput"]
    except (ValueError, KeyError):
        ctx = {}
    check("AC15", "hook reports the blocked destination as additionalContext",
          ctx.get("hookEventName") == "PostToolUseFailure" and "tools-check.test" in ctx.get("additionalContext", ""),
          p.stdout + p.stderr)
    p = subprocess.run(["docker", "exec", "-i", a, "agentgw-hook"], input=hook_in, text=True, capture_output=True)
    check("AC15", "hook reports each destination once per session", p.stdout.strip() == "", p.stdout)
    r = sh("docker", "exec", a, "agentgw-net", "request", "tools-check.test", "--required", "--port", "tcp/80",
           "--reason", "needed for e2e", check=False)
    check("AC15", "agentgw-net request records a required request", '"pending"' in r.stdout, r.stdout + r.stderr)
    check("AC15", "agentgw-net check exits 4 while pending",
          sh("docker", "exec", a, "agentgw-net", "check", "tools-check.test", check=False).returncode == 4)
    res = {}
    t = threading.Thread(target=lambda: res.update(rc=sh("docker", "exec", a, "agentgw-net", "wait", "tools-check.test",
                                                         "--timeout", "30", check=False).returncode))
    t.start()
    time.sleep(1)
    api("/api/decide", {"dest": "tools-check.test", "action": "block"})
    t.join(40)
    check("AC15", "agentgw-net wait returns 'denied' (exit 3) after Block", res.get("rc") == 3, res)


def snapshot_flow():
    print("\n6. snapshots, export and import")
    a = "e2e-agent-a"
    snap = api("/api/snapshots", {"name": "baseline", "note": "e2e"})
    exported = api("/api/policy/export", raw=True)
    check("AC12", "export is YAML with the rules", "agentgw_policy: 1" in exported and "allow: allowed.test" in exported)
    rid = next(r["id"] for r in api("/api/rules") if r["value"] == "other.test")
    api(f"/api/rules/{rid}", method="DELETE")
    check("AC12", "removed rule takes effect", not probe(a, "http", "other.test")["ok"])
    pending_before = queue_item("blocked.test")
    r = api(f"/api/snapshots/{snap['id']}/restore", method="POST")
    check("AC12", "snapshot restore applied", r["applied"] and r["rule_count"] == snap["rule_count"], r)
    check("AC12", "restored rule works again", probe(a, "http", "other.test")["ok"])
    check("AC12", "restore keeps a backup snapshot", any(s["id"] == r["backup_snapshot"] for s in api("/api/snapshots")))
    check("AC12", "pending items are not promoted by restore",
          not pending_before or queue_item("blocked.test") is not None)
    r = api("/api/policy/import?mode=replace", exported)
    check("AC12", "import of exported YAML round-trips", r["applied"] and r["rule_count"] == len(api("/api/rules")), r)
    bad = None
    try:
        api("/api/policy/import", "rules:\n  - allow: 'not a host!'\n")
    except urllib.error.HTTPError as e:
        bad = e.code
    check("AC12", "invalid policy import rejected without changing rules", bad == 400)


def intel_flow():
    print("\n7. risk and country information")
    vol = json.loads(sh("docker", "volume", "inspect", f"{PROJECT}_agentgw-data").stdout)[0]["Mountpoint"]
    intel = os.path.join(vol, "intel")
    os.makedirs(intel, exist_ok=True)
    for f in ("country", "asn"):
        shutil.copy(os.path.join(ROOT, "tests", "fixtures", f"{f}.mmdb"), os.path.join(intel, f"{f}.mmdb"))
        open(os.path.join(intel, f"{f}.mmdb.manual"), "w").close()
    with open(os.path.join(intel, "feed-feodo.json"), "w") as f:
        json.dump({"fetched_at": time.time(), "entries": ["203.0.113.20/32"]}, f)
    sh(*COMPOSE, "restart", "controller")
    wait_for(_status_ok, timeout=30)
    d = dest("cn-host.test")
    check("AC13", "country shown for destination", d and d["intel"]["countries"] == ["CN"], d and d["intel"])
    check("AC13", "ASN / network owner shown", d and any("EXAMPLE-CN-CLOUD" in x for x in d["intel"]["asns"]))
    check("AC13", "watched country flagged for review (not malicious)",
          d and d["intel"]["level"] == "review" and any("watched country" in s for s in d["intel"]["signals"]))
    api("/api/settings", {"mode": "observe"})
    probe("e2e-agent-a", "http", "evil.test")
    e = wait_for(lambda: dest("evil.test"))
    check("AC13", "verified malicious indicator shown", e and e["intel"]["level"] == "malicious", e and e["intel"])
    check("AC13", "malicious destination not blocked by default (observe)", e and e["outcome"] == "ok", e)
    # Optional auto-block: needs the blocklist file the controller writes on refresh.
    api("/api/intel/refresh", method="POST")
    time.sleep(2)
    r = api("/api/settings", {"auto_block_malicious": True})
    check("AC13", "auto-block (opt-in) blocks the malicious IP", r["applied"] and not probe("e2e-agent-a", "http", "evil.test")["ok"])
    check("AC13", "auto-block leaves other unreviewed traffic alone in observe mode",
          probe("e2e-agent-a", "http", "blocked.test")["ok"])
    api("/api/settings", {"auto_block_malicious": False})


def observe_block_and_temp():
    print("\n8. block in observation mode, temporary approval")
    a = "e2e-agent-a"
    check("OBS", "unreviewed destination reachable in observe mode", probe(a, "http", "cn-host.test")["ok"])
    api("/api/decide", {"dest": "cn-host.test", "action": "block"})
    check("OBS", "Block works in observe mode (by name)", not probe(a, "http", "cn-host.test")["ok"])
    check("OBS", "Block works in observe mode (cached IP)", not probe(a, "http", "203.0.113.16")["ok"])
    api("/api/settings", {"mode": "enforce"})
    r = api("/api/decide", {"dest": "blocked.test", "action": "approve", "expires_hours": 6 / 3600})
    check("TMP", "temporary approval works", r["applied"] and probe(a, "http", "blocked.test")["ok"], r)
    time.sleep(8)
    check("TMP", "temporary approval expires and is enforced", not probe(a, "http", "blocked.test")["ok"])
    check("TMP", "expiry recorded in history",
          any(h["event"] == "expire" and h["value"] == "blocked.test" for h in api("/api/history")))


def main():
    if {"-h", "--help"} & set(sys.argv[1:]):
        print(__doc__)
        return
    keep = "--keep" in sys.argv
    setup()
    try:
        observe_phase()
        enforce_phase()
        approve_flow()
        revoke_flow()
        restart_flow()
        failsafe_flow()
        snapshot_flow()
        intel_flow()
        observe_block_and_temp()
        agent_tools_flow()
        print("\n  SKIP  [IPv6] not testable here unless the kernel has IPv6; rules are rendered for both families")
    finally:
        if not keep:
            teardown()
    failed = [r for r in results if not r[2]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
