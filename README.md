# agentgw — network gateway for Dockerized AI agents

See where your agent containers connect, approve destinations once, enforce the
decision immediately, and let agents keep working with as little manual review
as possible.

```
 agent containers ──► br-agents (Docker bridge) ──► host FORWARD ──► internet
   dns: 172.30.0.1        │                          │
                          │ DNS (udp/tcp 53)          │ nftables table `inet agentgw`
                          ▼                          │   allow / deny / accounting sets
                 gateway (host netns, NET_ADMIN) ────┘   reject + conntrack revocation
                   resolver · policy apply · counters
                          ▲  SQLite (policy, activity)
                 controller (no capabilities)
                   dashboard 127.0.0.1:8080 · agent API 172.30.0.1:8081
```

- **Observation mode** records every outbound connection (DNS names, IPs,
  ports, protocol, per-container attribution, counts, bytes) and blocks nothing.
- **Enforcement mode** is default-deny. Approved hostnames work (their DNS
  answers are admitted), everything else is refused fast (NXDOMAIN / TCP reset)
  and lands, aggregated per destination, in the review queue.
- **Approve / Block** apply within about 100 ms. Block also cuts existing
  connections. No container restarts, ever, for policy changes.
- **Risk context** comes from offline public data: country and ASN (DB-IP Lite),
  verified malicious indicators (abuse.ch, Spamhaus DROP), weak signals. It is
  informational by default.
- **Agents** learn what was blocked (Claude Code / Codex hook), say whether they
  need it and why (`agentgw-net request`), and wait for your decision
  (`agentgw-net wait`) instead of failing the whole task.

Built from Linux and Docker primitives: one nftables table, conntrack, a small
DNS forwarder, SQLite. Python standard library plus three distribution
packages (dnslib, PyYAML, maxminddb). No HTTPS interception, no payload
inspection.

> Status: proof of concept. Developed and tested end to end on Ubuntu 24.04,
> kernel 6.18, Docker 29.9 (iptables-nft backend), with a simulated internet in
> a network namespace (`tests/e2e`). IPv6 rules are generated but were **not**
> exercised (that kernel had IPv6 disabled). Live threat feed downloads were not
> exercised (no outbound access); parsers are tested against the documented
> formats. Run `host/inspect-host.sh` and the e2e suite on your VPS before
> relying on it.

## Quick start

```bash
git clone https://github.com/weboko/network-layer && cd network-layer
./scripts/setup.sh              # creates the agents network (br-agents, 172.30.0.0/24) and .env
docker compose up -d --build    # gateway, controller, read-only Docker socket proxy
sudo host/install-failsafe.sh   # optional, recommended: fail closed at boot (see Reliability)
```

Dashboard: it listens on `127.0.0.1:8080` only.

```bash
ssh -L 8080:127.0.0.1:8080 your-vps      # then open http://127.0.0.1:8080/
```

With Tailscale, either run `tailscale serve --bg 8080` on the VPS, or set
`AGENTGW_ADMIN_LISTEN=<tailscale-ip>:8080` and `AGENTGW_ADMIN_HOSTS=<that ip>,<magicdns name>`.
Set `AGENTGW_ADMIN_TOKEN` whenever anything other than you can reach the port.

## Onboarding agent containers

A container is managed when it is attached to **only** the `agentgw-agents`
network and uses the gateway as its DNS server:

```yaml
services:
  my-agent:
    networks: [agentgw]
    dns: [172.30.0.1]
networks:
  agentgw:
    external: true
    name: agentgw-agents
```

`dns:` is applied when a container is created, so onboarding needs one
`docker compose up -d --force-recreate`. Policy changes later never restart
anything. The dashboard warns about managed containers that miss the DNS
setting or are also attached to other networks.

For [ai-box](https://github.com/weboko/ai-box) there is a ready-made override:
see [integrations/ai-box](integrations/ai-box/README.md).

Never mount `/var/run/docker.sock` into an agent container. With it the agent
can start a container on the host network and nothing here can stop that.

## Workflow

1. **Observe.** Start in observation mode (the default) and let the agents
   work normally for a while. *Activity* shows every destination grouped by
   hostname (or IP when no name was seen), with country / network, ports,
   connection counts, traffic, containers, risk and status. Nothing observed is
   trusted automatically.
2. **Build the whitelist.** Approve what you recognise: row buttons, or tick
   several and *Approve selected*. Approval takes the ports actually observed.
   Wildcards (`*.example.com`), port edits and temporary approvals are under
   *Whitelist* and the queue's *advanced…*.
3. **Enforce.** *Settings → Mode → enforce*. Existing connections to
   unapproved destinations are cut and new ones are refused.
4. **Review the queue.** Blocked destinations appear once each, with attempts,
   ports, containers and any reason an agent gave ("required" / "optional").
   **Approve** or **Block** apply immediately; **Dismiss** hides an item until
   it is attempted again.
5. **Snapshot.** Save the whitelist under a name, export / import YAML, restore
   older versions (the current one is saved automatically first).

The whitelist file format (`agentgw_policy: 1`):

```yaml
agentgw_policy: 1
name: baseline
rules:
  - allow: github.com
    ports: [tcp/443, tcp/22]
  - allow: "*.githubusercontent.com"
    ports: [tcp/443]
  - allow: 192.0.2.0/24       # IP / CIDR rules for services without DNS
    ports: ["*"]
  - deny: tracker.example     # deny always wins, any port
  - allow: staging.example.com
    ports: [tcp/443]
    expires: 2026-11-30T00:00:00Z
```

Import and restore change rules only. They never touch the mode or turn pending
review items into approvals.

## Agent integration

Summary (details, evidence and per-mode behaviour in
[docs/AGENT-INTEGRATION.md](docs/AGENT-INTEGRATION.md)):

| | Claude Code | Codex CLI |
|---|---|---|
| Learns what was blocked | `PostToolUse` + `PostToolUseFailure` hook → `additionalContext` (tested live) | `PostToolUse` hook → `additionalContext` (format checked against source; not run live) |
| Says if it is required + why | `agentgw-net request` (any shell) | same |
| Waits for your decision | `agentgw-net wait` (blocking shell call, ≤ 10 min per call) | same |
| Instructions | `agent/AGENTS.network.md` in CLAUDE.md / AGENTS.md | same |

Hooks cannot pause and later resume an agent. Waiting is done by the agent
itself calling `agentgw-net wait`. Finished headless runs can be resumed by a
script (`claude -p --resume`, `codex exec resume`). The gateway works without
any of this.

## Configuration

Environment (`.env`): network layout, upstream DNS, dashboard bind/token,
`ABUSECH_AUTH_KEY`. See [.env.example](.env.example).
Runtime settings (dashboard → Settings, applied immediately):

| setting | default | meaning |
|---|---|---|
| mode | observe | `observe` records and blocks only explicit blocks; `enforce` is default-deny |
| unapproved_dns | refuse | enforce mode: `refuse` answers NXDOMAIN locally (no DNS exfiltration, port unknown until approved); `resolve` resolves and blocks the connection (shows the port, query leaves the host) |
| dns_min_ttl / dns_max_ttl | 3600 / 86400 s | how long an IP stays admitted after an approved name resolved to it |
| auto_block_malicious | off | block IPs/domains on the *verified malicious* feeds |
| watch_countries | CN, RU, KP, IR | highlighted for review only; country never blocks |
| intel feeds, geoip, retention | on, on, 30 d | |

CLI (scripting and recovery, no dashboard needed):

```bash
docker compose exec controller python3 -m agentgw.admin status|mode enforce|allow HOST [PORTS]|block HOST|rules|export
```

## Security model and limitations

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#limitations) before relying on
this. The short version:

- **Enforcement is per IP and port, driven by DNS.** An approved hostname
  admits the IPs *our* resolver returned for it. Anything else served from those
  IPs (CDNs, shared hosting) becomes reachable too, including by raw IP with a
  different SNI or Host header. Hostnames are never inspected on the wire.
- **Direct IP connections cannot bypass hostname rules.** An IP is admitted
  only by an IP rule or by a DNS answer for an approved name. Tested.
- **DNS**: all port-53 traffic from agents is answered by the gateway, and
  unapproved names are refused without asking upstream (in `refuse` mode). DoH
  and DoT to public resolvers are blocked like any other unapproved destination
  unless you approve the resolver.
- **Revocation** deletes conntrack entries. The next packet is rejected (TCP
  reset). A client that is only *receiving* is not told: its stream stops and it
  fails on its own read timeout or next send.
- **Only the agents bridge** is affected. A container that is also on another
  network, uses `network_mode: host`, or can reach the Docker socket is outside
  the gateway.
- Agents can talk to each other on the agents network, and can reach only DNS
  and the agent API on the host. Agent-provided reasons are claims, labelled as
  such in the UI.

## Reliability and recovery

- The nftables table stays in force when the gateway or controller stops (fail
  closed). Policy changes are single atomic nft transactions.
- A gateway restart keeps DNS-derived allowances and counters. If the table is
  flushed (`nft flush ruleset`, firewall reload), the gateway restores it within
  about 10 s.
- `host/install-failsafe.sh` (optional) installs a systemd unit that loads a
  block-all placeholder for the agents bridge at boot, before Docker. Without it,
  agent containers that start before the gateway after a reboot are briefly
  unfiltered.
- Docker's own chains are never modified. SSH, VPN and other containers do not
  match any agentgw rule.

`host/recover.sh status|observe|open|restore`:

- `observe` stops blocking but keeps explicit blocks.
- `open` removes all agentgw rules and stops the gateway, so agents get plain
  Docker networking.
- `restore` starts the gateway again, which re-applies the stored policy.

To uninstall: `docker compose down`, `nft delete table inet agentgw`, disable the
fail-safe unit, `docker network rm agentgw-agents`.

## Tests

```bash
docker run --rm -v "$PWD":/src:ro -w /src agentgw:local python3 -m unittest discover -s tests/unit -t .
sudo python3 tests/e2e/run.py     # real stack + simulated internet; ~3 min; cleans up after itself
```

The end-to-end suite walks through every acceptance criterion against the real
kernel firewall: observation, approval, default deny, aggregated queue, runtime
approve, live revocation, restarts, fail-safe, self-repair, snapshots, intel,
direct-IP bypass attempts and the agent tools. The last run passed 74/74 checks.

## Layout

```
agentgw/           gateway.py (privileged) · web.py (controller) · nft.py · dnsproxy.py
                   policy.py · db.py · intel.py · conntrack.py · docker_meta.py · admin.py · static/
agent/             agentgw-net, agentgw-hook, AGENTS.network.md, Claude/Codex settings
host/              inspect-host.sh, fail-safe unit, recover.sh
integrations/      ai-box override
tests/             unit/, e2e/ (sim internet, probe, runner), fixtures/
docs/              ARCHITECTURE.md, AGENT-INTEGRATION.md, THREAT-INTEL.md
```
