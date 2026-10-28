"""Regenerate the GeoIP fixture databases (MaxMind DB format, like DB-IP Lite).

    pip install mmdb-writer netaddr && python3 tests/fixtures/make_geo.py

203.0.113.0/24 -> US / AS64500, except 203.0.113.16 -> CN / AS64501.
"""

import os

from mmdb_writer import MMDBWriter
from netaddr import IPSet

HERE = os.path.dirname(os.path.abspath(__file__))

country = MMDBWriter(ip_version=6, database_type="DBIP-Country-Lite", ipv4_compatible=True)
country.insert_network(IPSet(["203.0.113.0/24"]) - IPSet(["203.0.113.16/32"]),
                       {"country": {"iso_code": "US", "names": {"en": "United States"}}})
country.insert_network(IPSet(["203.0.113.16/32"]), {"country": {"iso_code": "CN", "names": {"en": "China"}}})
country.to_db_file(os.path.join(HERE, "country.mmdb"))

asn = MMDBWriter(ip_version=6, database_type="DBIP-ASN-Lite", ipv4_compatible=True)
asn.insert_network(IPSet(["203.0.113.0/24"]) - IPSet(["203.0.113.16/32"]),
                   {"autonomous_system_number": 64500, "autonomous_system_organization": "EXAMPLE-NET"})
asn.insert_network(IPSet(["203.0.113.16/32"]),
                   {"autonomous_system_number": 64501, "autonomous_system_organization": "EXAMPLE-CN-CLOUD"})
asn.to_db_file(os.path.join(HERE, "asn.mmdb"))
print("wrote country.mmdb and asn.mmdb")
