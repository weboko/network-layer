# ai-box behind agentgw

[ai-box](https://github.com/weboko/ai-box) runs Claude Code and Codex as
remote-control daemons in containers on the compose default network. This
override moves them onto the agents network and installs the agent tools,
without changing ai-box's own files except `.env` and `context/AGENTS.md`.

1. Install agentgw on the same host (top-level README: `scripts/setup.sh`,
   `docker compose up -d --build`). It starts in observation mode.
2. In ai-box's `.env`:

   ```bash
   AGENTGW_DIR=/opt/network-layer   # this repository's checkout
   COMPOSE_FILE=docker-compose.yml:/opt/network-layer/integrations/ai-box/docker-compose.agentgw.yml
   ```

3. Append `agent/AGENTS.network.md` to ai-box's `context/AGENTS.md` (both
   agents read that file).
4. Recreate once: `./box up -d --force-recreate` (add `--profile box` / the
   service name for the combined box).
5. Use the boxes as usual for a while, then review *Activity* in the dashboard.
   Expect at least:
   - the Anthropic and OpenAI API and remote-control endpoints;
   - GitHub (`github.com`, `api.github.com`, `*.githubusercontent.com`; tcp/22
     if you use SSH remotes);
   - package registries the agents use (npm, PyPI, crates, the Nix cache from
     `prime.sh`);
   - with `TUNNEL_TOKEN`, Cloudflare's tunnel edge (cloudflared connects
     outbound, by default on port 7844 over QUIC/udp with TCP fallback).

   Approve what you recognise, then switch to enforcement.

What the override does per service (`claude`, `codex`, `box`):

- `networks: [agentgw]` replaces the compose default network, so the boxes are
  attached to the agents network only;
- `dns: [172.30.0.1]`;
- mounts `agentgw-net` and `agentgw-hook` into `/usr/local/bin`;
- replaces `/etc/claude-code/managed-settings.json` and
  `/etc/codex/managed_config.toml` with the same settings ai-box bakes in, plus
  the gateway hook.

If ai-box changes those managed settings later, update
`agent/claude/managed-settings.json` / `agent/codex/managed_config.toml` to
match.

Notes specific to ai-box:

- The boxes include `docker-ce-cli`. Never mount the Docker socket into them:
  it would let an agent start containers outside the gateway.
- `./box run --rm <service> ...` one-off containers (logins) use the same
  override, so they are also behind the gateway. Approve the login endpoints
  during observation, or log in before enforcing.
- Inbound traffic to the boxes' Caddy server through the tunnel is the reply
  direction of cloudflared's outbound connection and needs no extra rule.
