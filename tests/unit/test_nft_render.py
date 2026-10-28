import ipaddress
import re
import unittest

from agentgw import config, nft

VERDICTS = re.compile(r"\b(accept|drop|reject|return|goto|jump)\b")


class Render(unittest.TestCase):
    def setUp(self):
        self.cfg = config.load()

    def all_rules(self, mode):
        return {**nft._rules(self.cfg), **nft._mode_rules(mode)}

    def test_accounting_never_shares_a_rule_with_a_verdict(self):
        # A full accounting set makes `update` fail and skips the rest of the
        # rule; a verdict in the same rule would then be skipped too.
        for mode in ("observe", "enforce"):
            for chain, rules in self.all_rules(mode).items():
                for r in rules:
                    if "update @" in r:
                        self.assertIsNone(VERDICTS.search(r), f"{chain}: {r}")

    def test_sets_referenced_are_declared(self):
        skel = nft._skeleton()
        declared = set(re.findall(r"set (\w+) \{", skel))
        for mode in ("observe", "enforce"):
            for rules in self.all_rules(mode).values():
                for r in rules:
                    for s in re.findall(r"@(\w+)", r):
                        self.assertIn(s, declared, r)

    def test_mode_chains(self):
        enf = nft._mode_rules("enforce")
        obs = nft._mode_rules("observe")
        self.assertIn("goto reject_now", enf["nomatch4_l4"])
        self.assertNotIn("goto reject_now", obs["nomatch4_l4"])
        self.assertEqual(obs["nomatch6_other"], [])

    def test_only_bridge_traffic_is_matched(self):
        rules = nft._rules(self.cfg)
        b = f'"{self.cfg.bridge}"'
        self.assertTrue(all(b in r for r in rules["forward"]))
        self.assertTrue(rules["input"][0].startswith(f"iifname != {b}"))
        self.assertTrue(all(b in r for r in rules["dns_redirect"]))

    def test_policy_checks_deny_before_allow(self):
        r = nft._rules(self.cfg)["new4_l4"]
        first_allow = next(i for i, x in enumerate(r) if "@allow4" in x or "@dyn4" in x)
        last_deny = max(i for i, x in enumerate(r) if "goto reject_now" in x)
        self.assertLess(last_deny, first_allow)
        self.assertEqual(r[-1], "goto nomatch4_l4")

    def test_static_sets_collapse_overlaps(self):
        n = ipaddress.ip_network
        script = nft.render_static({
            "allow_any": [n("10.0.0.0/8"), n("10.1.0.0/16"), n("2001:db8::/32")],
            "allow_port": [(n("192.168.0.0/16"), "tcp", 22), (n("192.168.1.0/24"), "tcp", 22)],
            "deny": [n("1.2.3.4/32")], "threat": []})
        self.assertIn("add element inet agentgw allow4_any { 10.0.0.0/8 }", script)
        self.assertIn("allow6_any { 2001:db8::/32 }", script)
        self.assertIn("allow4_port { 192.168.0.0/16 . tcp . 22 }", script)
        self.assertIn("deny4 { 1.2.3.4 }", script)
        # Every static set is flushed in the same transaction.
        self.assertEqual(script.count("flush set"), 8)


if __name__ == "__main__":
    unittest.main()
