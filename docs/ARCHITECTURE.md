# Architecture

## Components

| | runs as | does |
|---|---|---|
| **gateway** (`agentgw/gateway.py`) | container, host network namespace, `CAP_NET_ADMIN` + `CAP_NET_BIND_SERVICE` only | owns the nftables table `inet agentgw`; DNS resolver on the bridge IP; applies policy; deletes conntrack entries; turns kernel counters into flow records |
| **controller** (`agentgw/web.py`) | container, host network namespace, no capabilities | dashboard + admin API on 127.0.0.1:8080; agent API on 172.30.0.1:8081; snapshots; threat-intel downloads |
| **socket-proxy** | `wollomatic/socket-proxy`, no network, unprivileged | read-only Docker metadata (GET network + container inspect) on a unix socket only the gateway mounts |
| **SQLite** (volume) | | single source of truth and the only interface between controller and gateway |

The controller never touches the firewall. It writes rules or settings, bumps
`policy_version`, and waits (up to 5 s) for the gateway to report
`applied_version`. So the dashboard tells you whether a change is actually in
force.

## Packet path

Managed containers sit on one Docker bridge network (`agentgw-agents`, bridge
device `br-agents`). Everything is matched on that interface name, so nothing
else on the host is affected.

```
container ── br-agents ──► prerouting/nat  dns_redirect: any :53 not to the host → gateway resolver
                          ├► input          only DNS + agent API on 172.30.0.1; everything else rejected
                          └► forward        egress (br-agents → elsewhere):
                                              invalid → drop
                                              established/related → pass (tx accounting)
                                              new → account → deny/threat? reject
                                                            → static allow (IP/CIDR [+port])? pass
                                                            → DNS-derived allow (IP [+port])? pass
                                                            → mode chain: observe = record + pass
                                                                          enforce = record + reject
                                            ingress (→ br-agents): rx accounting only
```

"Pass" means *return*, which hands the packet on to Docker's own chains. A
reject in our table is final. This is the coexistence model Docker documents
for its nftables backend, and it works the same with iptables-nft or legacy
iptables underneath, because each table is its own netfilter hook. Docker's
chains (`DOCKER-USER` included) are never touched.

Rejections are TCP resets or ICMP admin-prohibited, so agents fail in
milliseconds instead of hanging on a timeout.

## Hostname enforcement via DNS

Encrypted traffic carries no reliable hostname, and decrypting it is out of
scope, so enforcement is IP-based and driven by DNS:

1. Managed containers resolve through the gateway (`dns: 172.30.0.1`). Any
   other port-53 traffic is DNATed to it, so `dig @8.8.8.8` gets the gateway too.
2. For a name matching an allow rule, the gateway resolves upstream, adds the
   answer's IPs (with the rule's ports) to a timeout set, **then** returns the
   answer. The allowance lives for `max(dns_min_ttl, min(TTL, dns_max_ttl))` and
   is refreshed on every lookup.
3. A connection to an IP that did not come from such an answer, or from an IP
   rule, does not match an allow set. Hardcoded IPs, IPs from other resolvers and
   DoH answers are blocked in enforce mode.
4. Unapproved names in enforce mode get NXDOMAIN without an upstream query
   (`unapproved_dns: refuse`). That closes DNS tunnelling, but the review item
   only learns the port after approval.

**Finding while building this:** on Docker 29, a container on a user-defined
network that uses Docker's embedded resolver (127.0.0.11) with the default
upstream has its external queries sent **from the host's network namespace**.
Host-side DNAT never sees them, and they cannot be attributed. With `dns:` set to
the gateway, the embedded resolver forwards from the container's own IP. That
was verified with packet captures, and it is why onboarding requires `dns:`.
Containers without it still get IP enforcement (their answers never admit
anything), but hostnames are unknown and their DNS is uncontrolled. The
dashboard flags them.

## Revocation

Every policy apply ends with a pass over conntrack entries from the agents
subnet. An entry whose destination is no longer admitted is deleted:

- denied by rule or threat feed;
- IP resolved for a now-denied name;
- in enforce mode, not covered by any allowance.

The next packet of that flow is treated as new, hits the policy and gets a TCP
reset. A Block in observation mode also adds the IPs the blocked name resolved
to (unless shared with an approved name) to the deny set, so a cached address
cannot be used.

Measured on the test host: a whole Approve/Block round trip (save, apply,
revoke, confirm) took 104 ms median and 128 ms max over 20 decisions. The nft
apply itself takes 30–80 ms. Idle cost: about 1% of one CPU and 14 MB for the
gateway, 20 MB for the controller.

## Data and aggregation

The kernel aggregates. Dynamic nft sets with per-element counters, keyed by
(container IP, destination IP, protocol, port), count new connections, packets
and bytes in each direction, rejections and would-be rejections. The gateway
reads them every 2 s and adds the deltas to the `flows` table. 10,000
connections to github.com become one row per container and port, rolled up into
one destination in the UI. DNS answers map destination IPs back to names
(preferring the name the same container looked up).

Container names come from Docker metadata every 10 s.

## Failure behaviour

| event | result |
|---|---|
| gateway process stops/crashes | table stays: unapproved stays blocked, existing allowances keep working until their DNS timeout, then fail closed; DNS fails (SERVFAIL/unreachable) |
| controller stops | dashboard gone; enforcement unchanged |
| gateway restart | table kept; dynamic allowances re-learned from kernel + stored DNS history; ~1 s without DNS |
| `nft flush ruleset` / firewall reload | gateway re-applies within ~10 s (agents unfiltered in between) |
| host reboot | with the fail-safe unit: agents blocked until the gateway starts; without it: unfiltered until then |
| bad policy (validation) | rejected by the API; nothing applied |
| nft transaction error | nothing applied (atomic), error shown in the dashboard |
| accounting set full | accounting stops counting new flows; enforcement unaffected (updates never share a rule with a verdict; unit-tested) |

## Alternatives considered

- **Explicit or transparent HTTP(S) proxy** (Squid, tinyproxy, SNI-peeking
  proxies). It sees hostnames for HTTP and TLS, but only for proxied protocols:
  SSH, QUIC/UDP and arbitrary TCP need a separate path. An agent that ignores
  proxy variables has to be caught by a firewall anyway. It would add a
  component without removing the firewall.
- **dnsmasq / unbound with `nftset`**: the same DNS-to-set mechanism, but policy
  changes need restarts and per-container attribution means parsing logs. The
  forwarder here is a small module on top of dnslib.
- **Per-container rules in `DOCKER-USER`**: this is Docker's chain. A separate
  nft table is cleaner and Docker documents it for the nftables backend.
- **eBPF / cgroup socket hooks**: explicitly out of scope, and unnecessary for a
  handful of containers on one bridge.

## Limitations

- **Shared IPs.** Approving a hostname admits its current IPs for every
  destination served from them (CDNs, shared hosting, cloud load balancers). A
  determined agent could reach another site on the same IP by sending its own
  SNI/Host. Closing this needs SNI-aware filtering (an NFQUEUE or proxy
  component), not included.
- **DNS caching beyond our window.** A long-running process that caches an IP
  longer than `dns_max_ttl` without re-resolving will be refused. The blocked IP
  shows up with its known hostname. Raise the TTLs if that matters.
- **HTTPS/SVCB records.** IP hints inside HTTPS records are not admitted. Only
  A/AAAA answers are. Clients that connect to hints without A lookups will be
  blocked.
- **Receive-only connections** are cut but not reset on the client side (see
  Revocation).
- **IPv6** rules are generated, and IPv6 DNS redirection is configured when the
  agents network has an IPv6 subnet. Neither was tested (the build machine had
  no IPv6). If the agents network has no IPv6, containers have no global IPv6
  and nothing escapes that way.
- **Attribution** is by source IP. A container with `CAP_NET_RAW` (Docker's
  default) can spoof another agent's IP on the bridge. Policy is global, so this
  only affects attribution, not enforcement.
- **Outside the boundary:** containers with extra networks, host networking, or
  Docker socket access. The host itself. Agents talking to each other on the
  agents network.
- **ICMP and other non-TCP/UDP protocols** are allowed only to destinations
  with an any-port rule. ICMP errors for existing flows always pass.
