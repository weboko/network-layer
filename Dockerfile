FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# Distribution packages only: nftables + conntrack for enforcement, dnslib for
# the resolver, PyYAML for policy files, maxminddb for offline GeoIP/ASN.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-dnslib python3-yaml python3-maxminddb \
      nftables conntrack ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/agentgw
COPY agentgw ./agentgw

# Overridden per service in docker-compose.yml (gateway / controller).
CMD ["python3", "-m", "agentgw.web"]
