# Threat intelligence and destination context

All lookups are local, against files refreshed in the background by the
(unprivileged) controller. Destinations are never sent to a third-party API.
Sources are independent modules in `agentgw/intel.py` (`FEEDS`). Adding one
means adding a URL, a kind (`ip` / `cidr` / `domain`) and a strength.

| source | gives | strength | access | refresh | notes |
|---|---|---|---|---|---|
| DB-IP Lite country + ASN (`dbip-country-lite-YYYY-MM.mmdb.gz`, `dbip-asn-lite-…`) | country, ASN, network owner | context | no account; CC BY 4.0 (attribution shown in the dashboard) | monthly release; checked every 14 days | MaxMind-format files. GeoLite2 files dropped in `intel/country.mmdb`, `intel/asn.mmdb` with a `*.mmdb.manual` marker are used instead and never overwritten |
| abuse.ch Feodo Tracker IP blocklist | botnet C2 IPs | **malicious** | free abuse.ch Auth-Key (`ABUSECH_AUTH_KEY`), sent as `Auth-Key` header | every 12 h | small, curated, low false-positive list |
| abuse.ch URLhaus hostfile | malware distribution hosts | **malicious** | Auth-Key | every 12 h | hostnames on legitimate shared platforms can appear; parent-domain matches are only *suspicious* |
| abuse.ch ThreatFox hostfile | IOC domains | **malicious** | Auth-Key | every 12 h | |
| Spamhaus DROP (v4/v6 JSON) | hijacked / criminal netblocks | **malicious** | no account; check Spamhaus' terms for your use | every 12 h | a few thousand CIDRs |
| Tor Project bulk exit list | Tor exit relays | info | public | every 12 h | not malicious by itself |

Weak signals, computed locally, are never "malicious":

- **Watched countries.** Default CN, RU, KP, IR, configurable. Shown as
  *review*. Country alone never blocks anything, and GeoIP country is where the
  IP is registered or located, not who operates the service.
- **Direct-IP connection with no DNS name seen.**
- **Uncommon port** (anything but 80/443, 22, 53, 123, udp/443).
- **Punycode (IDN) hostname.**

Levels in the UI:

- *malicious*: on a malicious feed.
- *suspicious*: a parent domain is listed.
- *review*: watched country.
- *none*.

**Auto-block** (Settings → "Auto-block verified malicious indicators", off by
default) loads only the *malicious* feeds' IPs into a deny set checked before
any allow rule, and makes the resolver refuse listed domains. It applies in both
modes.

**Verification status.** The parsers are unit-tested against each feed's
published format (comment lines, hosts-file lines, Spamhaus NDJSON). GeoIP
lookups were tested with generated MaxMind-format fixtures
(`tests/fixtures/make_geo.py`). Live downloads were **not** exercised (the build
environment had no outbound access). On first start, check Settings → Threat
intelligence sources, which shows each feed's last fetch result or error. abuse.ch
announced Auth-Keys for its services in 2025 and vendor integrations now list the
key as required, so assume it is needed. Without one, those three feeds report an
HTTP error and the rest still work.

Possible later additions, deliberately not included: online reputation APIs
(VirusTotal, AbuseIPDB: rate limits, API keys, and they leak your destinations),
newly-registered-domain lists, nDPI/NFStream flow classification.
