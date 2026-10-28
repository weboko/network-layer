"""Gateway DNS decisions with a fake upstream and nft calls recorded."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from dnslib import A, DNSRecord, RR, QTYPE

from agentgw import config, db, gateway, nft
from agentgw.policy import validate_rule


def answer(data, ip="203.0.113.10", ttl=60):
    req = DNSRecord.parse(data)
    r = req.reply()
    r.add_answer(RR(req.q.qname, QTYPE.A, rdata=A(ip), ttl=ttl))
    return r.pack()


class DNS(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {"AGENTGW_DATA": self.dir, "AGENTGW_UPSTREAM_DNS": "192.0.2.53"}):
            self.gw = gateway.Gateway(config.load())
        self.upstream = mock.patch.object(self.gw.upstream, "query", side_effect=answer).start()
        self.added = []
        mock.patch.object(nft, "dyn_add", side_effect=lambda e, r=(): self.added.extend(e)).start()

    def tearDown(self):
        mock.patch.stopall()
        shutil.rmtree(self.dir)

    def set_policy(self, rules, **settings):
        with db.tx(self.gw.conn) as c:
            for r in rules:
                db.upsert_rule(c, validate_rule(r), "test")
            for k, v in settings.items():
                db.set_setting(c, k, v)
        self.gw.policy = gateway.Policy(db.load_rules(self.gw.conn))
        self.gw.settings = db.get_settings(self.gw.conn)

    def ask(self, name):
        resp = self.gw.handle_dns("172.30.0.5", DNSRecord.question(name).pack())
        return DNSRecord.parse(resp)

    def test_observe_resolves_without_admitting(self):
        r = self.ask("unknown.test")
        self.assertEqual(r.header.rcode, 0)
        self.assertEqual(self.added, [])
        self.assertEqual(self.gw.names["203.0.113.10"].keys(), {"unknown.test"})

    def test_allowed_name_admitted_before_answer(self):
        self.set_policy([{"action": "allow", "value": "*.ok.test", "ports": ["tcp/443"]}],
                        mode="enforce")
        r = self.ask("api.ok.test")
        self.assertEqual(str(r.rr[0].rdata), "203.0.113.10")
        self.assertEqual(self.added, [("dyn4_port", "203.0.113.10 . tcp . 443", 3600)])

    def test_enforce_refuses_unapproved_without_asking_upstream(self):
        self.set_policy([], mode="enforce")
        r = self.ask("exfil-data.attacker.test")
        self.assertEqual(r.header.rcode, 3)
        self.upstream.assert_not_called()
        self.gw.drain_events()
        row = self.gw.conn.execute("SELECT * FROM requests").fetchone()
        self.assertEqual(row["dest"], "exfil-data.attacker.test")

    def test_resolve_mode_resolves_but_does_not_admit(self):
        self.set_policy([], mode="enforce", unapproved_dns="resolve")
        self.assertEqual(self.ask("x.test").header.rcode, 0)
        self.assertEqual(self.added, [])

    def test_deny_wins_in_any_mode(self):
        self.set_policy([{"action": "allow", "value": "*.ok.test"}, {"action": "deny", "value": "bad.ok.test"}], mode="observe")
        self.assertEqual(self.ask("bad.ok.test").header.rcode, 3)
        self.upstream.assert_not_called()

    def test_ttl_clamped(self):
        self.set_policy([{"action": "allow", "value": "ok.test"}], dns_min_ttl=100, dns_max_ttl=200)
        self.upstream.side_effect = lambda d: answer(d, ttl=100000)
        self.ask("ok.test")
        self.assertEqual(self.added, [("dyn4_any", "203.0.113.10", 200)])


if __name__ == "__main__":
    unittest.main()
