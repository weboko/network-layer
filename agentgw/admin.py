"""Command-line administration, for scripting and for recovery when the
dashboard is unavailable. Writes the same database the dashboard does; the
gateway applies the change and this command reports whether it did.

    docker compose exec controller python3 -m agentgw.admin status
    docker compose exec controller python3 -m agentgw.admin mode observe
    docker compose exec controller python3 -m agentgw.admin allow github.com tcp/443 tcp/22
    docker compose exec controller python3 -m agentgw.admin block example.com
    docker compose exec controller python3 -m agentgw.admin rules
    docker compose exec controller python3 -m agentgw.admin export > policy.yaml
    docker compose exec -T controller python3 -m agentgw.admin import < policy.yaml
"""

import json
import sys

from . import config, db
from .policy import PolicyError
from .web import Controller


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    ctl = Controller(config.load())
    cmd, args = argv[0], argv[1:]
    try:
        if cmd == "status":
            s = ctl.status()
            out = {k: s[k] for k in ("policy_version", "applied_version", "apply_error", "gateway_alive",
                                     "rules", "pending")}
            out["mode"] = s["settings"]["mode"]
            print(json.dumps(out, indent=2))
            return 0
        if cmd == "mode" and args and args[0] in ("observe", "enforce"):
            res = ctl.update_settings({"mode": args[0]}, actor="cli")
        elif cmd == "allow" and args:
            res = ctl.decide({"dest": args[0], "action": "approve", "ports": args[1:] or None}, actor="cli")
        elif cmd == "block" and args:
            res = ctl.decide({"dest": args[0], "action": "block"}, actor="cli")
        elif cmd == "rules":
            for r in db.load_rules(ctl.db()):
                print(f"{r['id']:>4}  {r['action']:<5}  {r['value']:<40}  {','.join(r['ports'])}")
            return 0
        elif cmd == "remove" and args:
            res = ctl.delete_rule(int(args[0]), actor="cli")
        elif cmd == "export":
            sys.stdout.write(ctl.export_yaml())
            return 0
        elif cmd == "import":
            res = ctl.import_yaml(sys.stdin.read(), args[0] if args else "replace", actor="cli")
        else:
            print(__doc__)
            return 2
    except PolicyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps(res, indent=2, default=str))
    return 0 if res.get("applied") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
