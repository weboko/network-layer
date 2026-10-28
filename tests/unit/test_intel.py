import json
import os
import shutil
import tempfile
import time
import unittest

from agentgw import intel

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")


class Feeds(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(intel.parse_feed("ip", "# Feodo\n# comment\n1.2.3.4\n\n5.6.7.8\nnot-an-ip\n"),
                         ["1.2.3.4/32", "5.6.7.8/32"])
        hostfile = "# URLhaus\n127.0.0.1\tevil.example\n127.0.0.1 Bad.Example.\n127.0.0.1 localhost\n127.0.0.1 9.9.9.9\n"
        self.assertEqual(intel.parse_feed("domain", hostfile), ["evil.example", "bad.example"])
        drop = ('{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}\n'
                '{"type":"metadata","timestamp":1700000000,"size":1}\n')
        self.assertEqual(intel.parse_feed("cidr", drop), ["1.10.16.0/20"])
        self.assertEqual(intel.parse_feed("cidr", "1.10.16.0/20 ; SBL256894\n"), ["1.10.16.0/20"])

    def test_net_index(self):
        idx = intel.NetIndex(["10.0.0.0/8", "192.0.2.5/32", "2001:db8::/32"])
        self.assertIn("10.9.9.9", idx)
        self.assertIn("192.0.2.5", idx)
        self.assertNotIn("192.0.2.6", idx)
        self.assertIn("2001:db8::1", idx)
        self.assertNotIn("11.0.0.1", idx)


class Assess(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        d = os.path.join(self.dir, "intel")
        os.makedirs(d)
        for f in ("country", "asn"):
            shutil.copy(os.path.join(FIXTURES, f"{f}.mmdb"), os.path.join(d, f"{f}.mmdb"))
        for name, entries in (("feodo", ["203.0.113.20/32"]), ("urlhaus", ["evil.test"]),
                              ("tor_exits", ["203.0.113.30/32"])):
            with open(os.path.join(d, f"feed-{name}.json"), "w") as f:
                json.dump({"fetched_at": time.time(), "entries": entries}, f)
        self.intel = intel.Intel(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_country_is_review_not_malicious(self):
        a = self.intel.assess("cn-host.test", ["203.0.113.16"], ["tcp/443"], ["CN"])
        self.assertEqual(a["countries"], ["CN"])
        self.assertEqual(a["level"], "review")
        self.assertTrue(any("AS64501" in x for x in a["asns"]))

    def test_malicious_ip_and_domain(self):
        self.assertEqual(self.intel.assess("x.test", ["203.0.113.20"], [], [])["level"], "malicious")
        self.assertEqual(self.intel.assess("evil.test", ["203.0.113.10"], [], [])["level"], "malicious")
        # A listed parent domain is only suspicious for a subdomain.
        self.assertEqual(self.intel.assess("cdn.evil.test", [], [], [])["level"], "suspicious")

    def test_info_feeds_do_not_raise_level(self):
        a = self.intel.assess("203.0.113.30", ["203.0.113.30"], ["tcp/9001"], [])
        self.assertEqual(a["level"], "none")
        self.assertTrue(any("direct IP" in s for s in a["signals"]))
        self.assertTrue(any("uncommon port" in s for s in a["signals"]))

    def test_blocklist_only_contains_malicious(self):
        bl = self.intel.blocklist()
        self.assertEqual(bl, {"ips": ["203.0.113.20/32"], "domains": ["evil.test"]})


if __name__ == "__main__":
    unittest.main()
