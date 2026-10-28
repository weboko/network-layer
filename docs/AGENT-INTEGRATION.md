# Agent integration: Claude Code and Codex

The gateway enforces policy on its own. Everything here is optional and only
helps agents react sensibly to blocks instead of failing whole tasks.

## What actually exists

**Claude Code**: checked against the official docs (code.claude.com/docs:
hooks, headless, remote-control, settings) and tested live with Claude Code
2.1.312 in this repository's test environment.

| capability | status |
|---|---|
| `PostToolUse` / `PostToolUseFailure` hooks returning `hookSpecificOutput.additionalContext` (shown to the model) | **tested live**: hook fired on a failed `curl`, the context reached the model, and the model followed it |
| Managed hooks in `/etc/claude-code/managed-settings.json` (cannot be overridden by user/project settings) | documented; used by the ai-box integration |
| `Stop` hook with `decision: "block"` forces the agent to continue (guarded by `stop_hook_active`, capped at 8 consecutive blocks) | documented; not used here |
| Hook timeout: 600 s default for command hooks, no documented maximum; `async` / `asyncRewake` hooks | documented |
| `claude -p ... --output-format json` returns `session_id`; `claude -p --resume <id> "..."` continues it later | documented |
| Remote Control (`claude remote-control`): the session runs on your machine with its normal configuration | documented as a local session; hooks there were not separately tested |

**Codex CLI**: checked against the source (`openai/codex` at the commit of
v0.165.0, Oct 2026). Not run live: no Codex credentials in the test
environment.

| capability | evidence |
|---|---|
| Hooks are stable and on by default since v0.124; events include `PostToolUse`, `Stop`, `SessionStart`, `PermissionRequest` | `features/src/lib.rs`, release notes |
| Hooks in `/etc/codex/managed_config.toml` are *managed*: no per-user trust step | `hooks/src/engine/discovery.rs` (`LegacyManagedConfigTomlFromFile` → managed) |
| Inline TOML format `[[hooks.PostToolUse]]` / `[[hooks.PostToolUse.hooks]]` | `config/src/hooks_tests.rs`, `config_toml.rs` |
| Shell tool is reported to hooks as `Bash` | `core/src/tools/hook_names.rs` |
| `PostToolUse` fires for non-zero exits with the default unified-exec tool | `core/src/tools/registry.rs` + `ExecCommandToolOutput::success_for_logging() == true` |
| Output schema: `hookSpecificOutput.{hookEventName, additionalContext}`, no extra keys | `hooks/schema/generated/post-tool-use.command.output.schema.json`; `agentgw-hook` output checked against it in the e2e suite |
| `codex exec resume <id> "prompt"`, `--json` events with `thread_id` | `exec/src/cli.rs` |
| `codex remote-control` / app-server runs the agent core (config, hooks, AGENTS.md) in the container | inferred from source structure; not tested |

**What neither offers:** a hook that suspends an agent and resumes it when an
external event (your approval) arrives. Hooks are synchronous with a timeout.
Claude's `asyncRewake` can wake an idle session when a background hook exits
2, but it can't hold a tool call open. So continuation is built from parts
that do exist.

## How continuation works

1. **Fast, clear failure.** The gateway answers unapproved names with NXDOMAIN
   and rejects connections with TCP resets, so tools fail in milliseconds with
   recognisable errors instead of hanging.
2. **The hook tells the agent what happened.** After each shell/fetch tool call,
   `agent/agentgw-hook` asks the agent API which destinations were blocked for
   this container since the previous call. New ones are injected as context:
   the destination, status, and what to do. The agent sees "pkg-mirror.test
   (pending), blocked by network policy" rather than guessing at a DNS problem.
3. **The agent decides necessity.** Per `agent/AGENTS.network.md` it drops
   optional resources (and reports them), and for required ones runs
   `agentgw-net request <host> --required --reason "..."`. That attaches the
   reason to the single aggregated review item. The dashboard labels it as the
   agent's claim.
4. **The agent keeps working, then waits.** It does everything that doesn't
   depend on the resource first, then calls `agentgw-net wait <host> --timeout 110`.
   That long-poll returns as soon as you Approve (exit 0) or Block (exit 3) in
   the dashboard, or exit 4 if still pending, so it calls again. 110 s keeps each
   call under the shell tools' default time limits.
5. **Approved → retry works immediately**: no restart, no reconnect of anything
   else. Denied → the agent finishes without it and says so.

Live test result (Claude Code, headless, small model): after
`curl https://pkg-mirror.test/...` failed, the hook injected the block, and the
model answered that it would run
`agentgw-net request pkg-mirror.test --required --reason "..."`, then
`agentgw-net wait`, then retry, and report if denied. Told the same resource was
optional, it skipped the request and said it would report the resource as
blocked. It did not try to work around the block in either case.

No task attribution is inferred. The only task information shown is what an
agent passes with `--task`. Container attribution comes from the source IP.

## Per execution mode

**Interactive terminal sessions** (`claude`, `codex` TUI). Hook and
instructions apply. While the agent waits in `agentgw-net wait` you can approve
in the dashboard, or just tell the agent in the terminal.

**Automated scripts** (`claude -p`, `codex exec`). The same in-session waiting
works, within whatever time budget the script allows. If a run ends with
required destinations still pending (the agent lists them in its final answer),
resume it after approval:

```bash
sid=$(claude -p "$TASK" --output-format json | jq -r .session_id)
# ... approve in the dashboard ...
until agentgw-net wait pkg-mirror.test --timeout 110; do [ $? -eq 4 ] || break; done
claude -p --resume "$sid" "Network access to pkg-mirror.test is now approved. Continue the task."
# Codex: codex exec resume "$thread_id" "..." (thread_id from the thread.started event of --json)
```

Note: `claude -p --bare` skips hooks, and the agent instructions then do all
the work.

**Remote sessions** (Claude Remote Control, Codex remote-control: what ai-box
runs). These execute inside the container, so the container's managed settings,
hooks and AGENTS.md apply as in a terminal session. Two practical points:

- the operator is often on a phone, so keep the dashboard reachable over
  Tailscale/WireGuard;
- a session that ends while waiting can be continued from the app with
  "approved, continue".

Without any integration (a plain script, another agent framework), the gateway
still blocks and queues. `agentgw-net blocked` is then the manual way to see why
something failed.

## Installing

- Put `agent/agentgw-net` and `agent/agentgw-hook` on the agent's PATH
  (`/usr/local/bin`). They need `sh`, `curl`, `sed`, `awk`.
- Claude Code: merge `agent/claude/managed-settings.json` into
  `/etc/claude-code/managed-settings.json` (or the user's `settings.json`).
- Codex: merge `agent/codex/managed_config.toml` into
  `/etc/codex/managed_config.toml`. In user-level config, Codex requires trusting
  the hook once via `/hooks`.
- Add `agent/AGENTS.network.md` to the instructions both agents read
  (`CLAUDE.md` / `AGENTS.md`).
- For ai-box, `integrations/ai-box` does all of the above.

## Not built, on purpose

- **No Stop hook that blocks completion while requests are pending.** Requests
  are tracked per container, not per session. In a container running several
  sessions (Remote Control), one session would be held up by another's
  requests.
- **No MCP server.** The CLI covers the same three calls in any shell, with no
  per-agent MCP configuration or tool-call timeouts to manage.
- **No custom agent runtime or orchestrator.**
