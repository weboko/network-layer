## Network access

All outbound traffic from this container goes through a gateway that only lets
approved destinations through. A blocked attempt fails immediately: DNS says the
host does not exist (NXDOMAIN, "could not resolve host"), or the connection is
refused/reset. That is policy, not a transient fault: do not retry in a loop.

When a network step fails like that:

1. `agentgw-net blocked` lists what was blocked for this container and whether
   each destination is pending, approved or denied.
2. Decide whether the task actually needs it. Prefer what is already reachable
   (approved mirrors, cached packages, local docs, data you already have).
   - Optional: carry on without it and list it under "Blocked (optional)" in
     your final answer.
   - Required: `agentgw-net request <host> --required --reason "<one sentence:
     what for>" [--port tcp/443]`. Then do all the work that does not depend on
     it first.
3. Before the step that needs it: `agentgw-net wait <host> --timeout 110`
   (exit 0 approved, 3 denied, 4 still pending; 110 s stays under shell-tool
   time limits). While it is pending and the task can wait, run it again;
   otherwise stop and report exactly what is blocked and what remains to be
   done once it is approved.
4. Approved: retry. Denied: finish with what you have and report it.

Never try to get around the gateway (other mirrors for the same thing, raw IP
addresses, proxies, tunnels, DNS-over-HTTPS). Requests are reviewed by a human;
say honestly why the task needs the destination.
