"""Small source files in the real formats, for the asinfo tests.

`write_sources` writes one file per dataset id, named as the last path segment
of the dataset's URL (CAIDA's carry a date), gzipped or bzipped where the
source is. They describe a handful of ASes the tests share: AS4766 (KT), its
providers 174 and 701, its peer 9318, three customers, and AS13335.
"""

import bz2
import gzip
import json
import os

CAIDA_REL_NAME = "20261001.as-rel2.txt.bz2"
CAIDA_ORG_NAME = "20261001.as-org2info.jsonl.gz"

ASNAMES = """\
174 COGENT-174 - Cogent Communications, US
701 UUNET - Verizon Business, US
4766 KIXS-AS-KR-KR - Korea Telecom, KR
9318 SKB-AS-KR - SK Broadband Co Ltd, KR
13335 CLOUDFLARENET - Cloudflare, Inc., US
17858 POWERVIS-AS-KR - LG POWERCOMM, KR
38661 KRNIC-AS-KR - Example Customer One, KR
45400 KT-CUSTOMER-AS - Example Customer Two, KR
"""

NRO = """\
2|nro|20261019|773470|19821213|20261019|+0000
nro|*|asn|*|117501|summary
apnic|KR|asn|4766|1|19960422|assigned|A9149F3E|e-stats
apnic|KR|asn|9318|1|20000101|assigned|B0000001|e-stats
arin|US|asn|701|1|19900801|assigned|C0000001|e-stats
ripencc|NL|asn|1101|10|19930901|assigned|x|e-stats
arin||asn|7|1||available||e-stats
"""

RIS_V4 = """\
% RIS whois dump, generated at 2026-10-19 08:00 UTC
% origin\tprefix\tseen by peers

4766\t211.252.112.0/24\t326
4766\t211.252.0.0/15\t330
13335\t1.1.1.0/24\t340
174\t0.0.0.0/0\t40
4766\t14.34.86.32/27\t8
"""

RIS_V6 = """\
% RIS whois dump, generated at 2026-10-19 08:00 UTC
4766\t2001:2d8::/32\t120
13335\t2606:4700::/32\t150
"""

RPKI = """\
ASN,IP Prefix,Max Length,Trust Anchor,Expires
AS13335,1.1.1.0/24,24,apnic,1792937860
AS4766,211.252.0.0/15,24,apnic,1792937860
"""

CAIDA_REL = """\
# inferred AS relationships, serial-2
174|4766|-1|bgp
701|4766|-1|bgp
4766|17858|-1|bgp
4766|38661|-1|bgp
4766|45400|-1|bgp
4766|9318|0|bgp
"""

CAIDA_ORG = [
    {
        "type": "ASN",
        "asn": "4766",
        "name": "KIXS-AS-KR",
        "organizationId": "@aut-45400-APNIC",
        "source": "APNIC",
    },
    {
        "type": "ASN",
        "asn": "9318",
        "name": "SKB-AS-KR",
        "organizationId": "@aut-9318-APNIC",
        "source": "APNIC",
    },
    {
        "type": "ASN",
        "asn": "9760",
        "name": "KT-SIBLING",
        "organizationId": "@aut-45400-APNIC",
        "source": "APNIC",
    },
    {
        "type": "Organization",
        "organizationId": "@aut-45400-APNIC",
        "name": "Korea Telecom",
        "country": "KR",
        "source": "APNIC",
    },
    {
        "type": "Organization",
        "organizationId": "@aut-9318-APNIC",
        "name": "SK Broadband Co Ltd",
        "country": "KR",
        "source": "APNIC",
    },
]


def _gzip(path: str, text: str) -> None:
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write(text)


def write_sources(directory) -> dict[str, str]:
    """Write one file per dataset id into `directory`; return id -> path."""
    directory = str(directory)
    paths = {
        "asnames": os.path.join(directory, "asn.txt"),
        "nro": os.path.join(directory, "nro-delegated-stats"),
        "ris_v4": os.path.join(directory, "riswhoisdump.IPv4.gz"),
        "ris_v6": os.path.join(directory, "riswhoisdump.IPv6.gz"),
        "rpki": os.path.join(directory, "rpki.csv"),
        "caida_rel": os.path.join(directory, CAIDA_REL_NAME),
        "caida_org": os.path.join(directory, CAIDA_ORG_NAME),
    }
    for key in ("asnames", "nro", "rpki"):
        with open(paths[key], "w", encoding="utf-8") as handle:
            handle.write({"asnames": ASNAMES, "nro": NRO, "rpki": RPKI}[key])
    _gzip(paths["ris_v4"], RIS_V4)
    _gzip(paths["ris_v6"], RIS_V6)
    with bz2.open(paths["caida_rel"], "wt", encoding="utf-8") as handle:
        handle.write(CAIDA_REL)
    _gzip(paths["caida_org"], "".join(json.dumps(r) + "\n" for r in CAIDA_ORG))
    return paths
