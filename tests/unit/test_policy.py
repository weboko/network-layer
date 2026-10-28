import time
import unittest

from agentgw.policy import (Policy, PolicyError, from_yaml, host_matches, normalize_host, normalize_ports, to_yaml,
                            validate_rule)


def rule(action, value, ports=None, **kw):
    return validate_rule(dict(action=action, value=value, ports=ports, **kw))


class Normalize(unittest.TestCase):
    def test_hosts(self):
        self.assertEqual(normalize_host("GitHub.com."), "github.com")
        self.assertEqual(normalize_host("*.Example.org"), "*.example.org")
        for bad in ("", "localhost", "exa mple.com", "-bad.com", "a..b", "x" * 300 + ".com"):
            with self.assertRaises(PolicyError, msg=bad):
                normalize_host(bad)

    def test_ports(self):
        self.assertEqual(normalize_ports(None), ["*"])
        self.assertEqual(normalize_ports("443, udp/443 tcp/80"), ["tcp/80", "tcp/443", "udp/443"])
        self.assertEqual(normalize_ports(["tcp/22", "*"]), ["*"])
        for bad in (["icmp/1"], ["tcp/0"], ["tcp/70000"], ["tcp/x"]):
            with self.assertRaises(PolicyError):
                normalize_ports(bad)

    def test_rule_kinds(self):
        self.assertEqual(rule("allow", "10.1.2.3/8")["value"], "10.0.0.0/8")
        self.assertEqual(rule("allow", "2001:db8::1")["kind"], "ip")
        self.assertEqual(rule("deny", "example.com", ["tcp/443"])["ports"], ["*"])


class Matching(unittest.TestCase):
    def test_wildcard_does_not_match_apex(self):
        self.assertTrue(host_matches("*.example.com", "a.b.example.com"))
        self.assertFalse(host_matches("*.example.com", "example.com"))
        self.assertFalse(host_matches("*.example.com", "badexample.com"))

    def test_deny_beats_allow(self):
        p = Policy([rule("allow", "*.example.com"), rule("deny", "evil.example.com")])
        self.assertEqual(p.host_decision("evil.example.com")[0], "deny")
        self.assertEqual(p.host_decision("ok.example.com")[0], "allow")
        self.assertEqual(p.host_allow_rules("evil.example.com"), [])
        p = Policy([rule("allow", "10.0.0.0/8"), rule("deny", "10.1.2.3")])
        self.assertEqual(p.ip_decision("10.1.2.3")[0], "deny")
        self.assertEqual(p.ip_decision("10.1.2.4", "tcp", 1)[0], "allow")

    def test_ports_and_status(self):
        p = Policy([rule("allow", "api.test", ["tcp/443"]), rule("allow", "203.0.113.0/24", ["udp/53"])])
        self.assertEqual(p.dest_status("api.test", ["tcp/443"]), "approved")
        self.assertEqual(p.dest_status("api.test", ["tcp/443", "tcp/22"]), "partial")
        self.assertEqual(p.dest_status("other.test"), "unreviewed")
        self.assertIsNone(p.ip_decision("203.0.113.9", "tcp", 53)[0])
        self.assertEqual(p.ip_decision("203.0.113.9", "udp", 53)[0], "allow")

    def test_expired_rules_ignored(self):
        p = Policy([rule("allow", "a.test", expires_at=time.time() - 1)])
        self.assertIsNone(p.host_decision("a.test")[0])


class Yaml(unittest.TestCase):
    def test_round_trip(self):
        rules = [rule("allow", "github.com", ["tcp/443", "tcp/22"], note="git"),
                 rule("allow", "*.npmjs.org"), rule("deny", "1.2.3.4"),
                 rule("allow", "a.test", expires_at=4102444800.0)]
        text = to_yaml(rules, name="t")
        back, meta = from_yaml(text)
        key = lambda r: (r["kind"], r["value"])  # noqa: E731
        self.assertEqual(sorted(back, key=key), sorted(rules, key=key))
        self.assertEqual(meta["name"], "t")

    def test_errors_name_the_rule(self):
        with self.assertRaisesRegex(PolicyError, "rule 2"):
            from_yaml("rules:\n  - allow: a.test\n  - allow: 'bad host'\n")
        with self.assertRaisesRegex(PolicyError, "duplicate"):
            from_yaml("rules:\n  - allow: a.test\n  - deny: a.test\n")
        with self.assertRaises(PolicyError):
            from_yaml("just a string")
        with self.assertRaises(PolicyError):
            from_yaml("rules:\n  - allow: a.test\n    deny: b.test\n")


if __name__ == "__main__":
    unittest.main()
