"""An IPv6 address is looked up like an IPv4 one, and AAAA is queried.

gather() had a domain branch and an IPv4 branch, so an IPv6 literal got RDAP
alone and came back looking like a normal answer with GeoIP, ASN, PTR and the
map all empty; #10 then turned it away with ipv6_not_supported. AAAA was never
queried anywhere, and the search box called an IPv6 address "not a domain or
an IP address".

Production has no IPv6 route out, so nothing here may need one: GeoIP is a
local database, RDAP is HTTPS to the registries, and the PTR (ip6.arpa) and
AAAA questions go to the public resolvers over IPv4. The one leg that would
have to connect over IPv6 is TLS, so it is never attempted to an IPv6 address
and the response says it was skipped.

Every lookup is faked; nothing here touches the network.
"""

import ipaddress
import json
import re
import shutil
import subprocess
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.rrset
import pytest
from fastapi.testclient import TestClient

import lookup
import main
import managers
import mcp_server
from main import app
from viewmodel import build_view

V6 = "2001:4860:4860::8888"
V6_PTR_NAME = dns.reversename.from_address(V6).to_text(omit_final_dot=True)
V4 = "93.184.216.34"

CURL = {"user-agent": "curl/8.7.1", "accept": "*/*"}
CHROME = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    ),
    "accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}

client = TestClient(app, client=("8.8.8.8", 41234))

RECORDS = {
    (V6_PTR_NAME, "PTR"): ["dns.google."],
    ("dns.google", "A"): ["8.8.8.8", "8.8.4.4"],
    ("dns.google", "AAAA"): [V6, "2001:4860:4860::8844"],
    ("v6only.example.com", "AAAA"): [V6],
    ("dual.example.com", "A"): [V4],
    ("v4only.example.com", "A"): [V4],
    ("dual.example.com", "AAAA"): ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
    ("loopback.example.com", "AAAA"): ["::1"],
    ("mapped.example.com", "AAAA"): ["::ffff:10.0.0.1"],
}

RAISE = {
    "timeout": lambda: dns.resolver.LifetimeTimeout(timeout=3.0, errors=[]),
    "servfail": dns.resolver.NoNameservers,
    "nxdomain": dns.resolver.NXDOMAIN,
}


class FakeAnswer:
    """The slice of dns.resolver.Answer that get_records() and gather() read."""

    def __init__(self, rrset):
        self.rrset = rrset

    def __iter__(self):
        return iter(self.rrset)

    def __getitem__(self, index):
        return list(self.rrset)[index]


class FakeResolver:
    """Answers from RECORDS; anything else has no record of that type.
    `outcomes` makes one (name, type) query fail the way dnspython reports it.
    SOA always fails, so zone_apex() settles on the registrable domain."""

    def __init__(self):
        self.outcomes = {}
        self.queries = []

    def resolve(self, qname, rdtype="A", *args, **kwargs):
        name = str(qname).rstrip(".").lower()
        rdtype = dns.rdatatype.to_text(dns.rdatatype.RdataType.make(rdtype))
        self.queries.append((name, rdtype))
        if rdtype == "SOA":
            raise dns.resolver.NoNameservers()
        if (name, rdtype) in self.outcomes:
            raise RAISE[self.outcomes[name, rdtype]]()
        if (name, rdtype) in RECORDS:
            return FakeAnswer(
                dns.rrset.from_text(
                    name + ".", 300, "IN", rdtype, *RECORDS[name, rdtype]
                )
            )
        raise dns.resolver.NoAnswer()


def _location(ip):
    """What GeoLite2-City and -ASN put together for an address."""
    return {
        "ip": ip,
        "country_code": "US",
        "country_name": "United States",
        "city_name": "",
        "subdivision_name": "",
        "subdivision_code": "",
        "lat": 37.751,
        "lon": -97.822,
        "accuracy_km": 1000,
        "time_zone": "America/Chicago",
        "cidr": "2001:4860::/32" if ":" in ip else "8.8.8.0/24",
        "asn_name": "GOOGLE",
        "asn_number": 15169,
        "asn_cidr": "2001:4860::/32" if ":" in ip else "8.8.8.0/24",
        "is_private": False,
        "hostname": "",
    }


@pytest.fixture
def offline():
    """The real pipeline over a fake resolver, with WHOIS and GeoIP answered
    locally. SSLManager's connect fails the test if it is reached: TLS must
    never get as far as opening a connection to an IPv6 address."""
    fake = FakeResolver()
    mocks = {
        "resolver": fake,
        "whois": AsyncMock(
            side_effect=lambda t: {
                "source": "rdap",
                "name": "GOOGLE-IPV6",
                "rir": "arin",
            }
        ),
        "geo": MagicMock(side_effect=_location),
        "connect": MagicMock(side_effect=AssertionError("TLS connection opened")),
    }
    allowed = {"allowed": True, "country": "US", "region": None, "reason": "test"}
    with ExitStack() as stack:
        stack.enter_context(patch("lookup._recursive_resolver", lambda: fake))
        stack.enter_context(patch("managers._recursive_resolver", lambda: fake))
        stack.enter_context(patch("lookup.lookup_whois", mocks["whois"]))
        stack.enter_context(
            patch.object(lookup.geo_ip_manager, "fetch_location", mocks["geo"])
        )
        stack.enter_context(
            patch.object(managers.SSLManager, "_connect", mocks["connect"])
        )
        stack.enter_context(
            patch("main.geo_block_manager.check_access", return_value=allowed)
        )
        yield mocks


# --- is_safe_ip: addresses that carry an IPv4 address -----------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",  # cloud metadata
        "::ffff:100.100.100.100",  # Tailscale MagicDNS
        "::ffff:192.168.1.1",
        "2002:a00:1::1",  # 6to4 around 10.0.0.1
        "2002:7f00:1::1",  # 6to4 around 127.0.0.1
        "2002:a9fe:a9fe::1",  # 6to4 around 169.254.169.254
        "64:ff9b::a00:1",  # NAT64 around 10.0.0.1
        "64:ff9b::7f00:1",  # NAT64 around 127.0.0.1
        "64:ff9b::a9fe:a9fe",  # NAT64 around 169.254.169.254
    ],
)
def test_an_embedded_private_ipv4_is_refused(ip):
    assert lookup.is_safe_ip(ip) is False


@pytest.mark.parametrize(
    "ip",
    [
        "::ffff:10.0.0.1",
        "::ffff:127.0.0.1",
        "2002:a00:1::1",
        "2002:7f00:1::1",
        "64:ff9b::a00:1",
        "64:ff9b::7f00:1",
    ],
)
def test_the_refusal_does_not_lean_on_the_registry(ip, monkeypatch):
    """IANA lists 64:ff9b::/96 as globally reachable; is_global refuses it
    only by way of is_reserved, and 6to4 only because the stdlib's list
    happens to call 2002::/16 private. Were either to change, the IPv4 address
    inside is still what a connection would reach."""
    monkeypatch.setattr(ipaddress.IPv6Address, "is_global", property(lambda s: True))
    monkeypatch.setattr(ipaddress.IPv6Address, "is_reserved", property(lambda s: False))
    monkeypatch.setattr(ipaddress.IPv6Address, "is_private", property(lambda s: False))
    assert lookup.is_safe_ip(ip) is False


def test_an_ipv4_mapped_address_is_the_ipv4_address():
    # ::ffff:a.b.c.d is a.b.c.d in IPv6 notation, and a dual-stack socket
    # connecting to it reaches the IPv4 host, so the IPv4 rules decide.
    assert lookup.is_safe_ip("::ffff:8.8.8.8") is True


@pytest.mark.parametrize("ip", ["2002:808:808::1", "64:ff9b::808:808"])
def test_6to4_and_nat64_stay_refused_around_a_public_ipv4(ip):
    """A decision, not an accident: these are a transition mechanism's
    addresses, not a host's. No RIR has a record for them and no PTR zone
    answers for them, so a lookup would come back empty -- and the IPv4
    address inside can be looked up as itself."""
    assert lookup.is_safe_ip(ip) is False


@pytest.mark.parametrize(
    "ip",
    ["::1", "::", "fe80::1", "fd00::1", "fec0::1", "2001:db8::1", "ff02::1"],
)
def test_non_public_ipv6_is_still_refused(ip):
    assert lookup.is_safe_ip(ip) is False


def test_public_ipv6_passes():
    assert lookup.is_safe_ip(V6) is True


# --- classify_target --------------------------------------------------------------


@pytest.mark.parametrize("target", ["fe80::1%eth0", f"{V6}%1"])
def test_a_zone_index_is_not_a_lookup_target(target):
    """ipaddress accepts "fe80::1%eth0", but the zone names an interface on
    the machine that typed it, which means nothing here."""
    assert lookup.classify_target(target) == "invalid"


def test_the_public_resolvers_are_reached_over_ipv4():
    """PTR (ip6.arpa) and AAAA questions travel over IPv4 like every other
    query: this server has no IPv6 route to send them over."""
    nameservers = managers._recursive_resolver().nameservers
    assert nameservers
    assert all(ipaddress.ip_address(ns).version == 4 for ns in nameservers)


# --- gather(): an IPv6 literal ----------------------------------------------------


async def test_gather_fills_geoip_asn_ptr_and_registration(offline):
    data = await lookup.gather(V6)

    assert data["address"] == V6
    assert data["resolved_ip"] == V6
    assert data["resolution"] == "literal"
    # The PTR came from ip6.arpa, asked of the public resolvers.
    assert (V6_PTR_NAME, "PTR") in offline["resolver"].queries
    assert data["reverse_dns"] == "dns.google."
    location = data["location"]
    assert location["country_code"] == "US"
    assert location["asn_number"] == 15169
    assert location["asn_name"] == "GOOGLE"
    assert location["reverse_dns"] == "dns.google."
    assert data["whois"]["name"] == "GOOGLE-IPV6"
    offline["whois"].assert_called_once_with(V6)
    # The sweep of the PTR name, AAAA included.
    assert [r["ip"] for r in data["domain"]["aaaa"]] == [V6, "2001:4860:4860::8844"]
    assert data["domain"]["status"]["aaaa"] == "ok"


async def test_gather_makes_no_tls_handshake_to_an_ipv6_literal(offline):
    # Same as an IPv4 literal: a bare address gets no TLS leg at all.
    data = await lookup.gather(V6)
    assert data["ssl"] is None
    offline["connect"].assert_not_called()


@pytest.mark.parametrize(
    "spelling",
    [
        "2001:4860:4860:0:0:0:0:8888",
        "2001:4860:4860:0000::8888",
        "2001:4860:4860::8888".upper(),
    ],
)
async def test_gather_writes_an_address_one_way(offline, spelling):
    """ipaddress's spelling (RFC 5952), so the WHOIS cache, the log and the
    page see one address however it was typed."""
    data = await lookup.gather(spelling)
    assert data["address"] == V6
    offline["whois"].assert_called_once_with(V6)


async def test_gather_looks_an_ipv4_mapped_address_up_as_ipv4(offline):
    data = await lookup.gather("::ffff:8.8.8.8")
    assert data["address"] == "8.8.8.8"
    assert data["resolved_ip"] == "8.8.8.8"
    offline["whois"].assert_called_once_with("8.8.8.8")


@pytest.mark.parametrize(
    "target",
    ["::1", "fe80::1", "fd00::1", "2001:db8::1", "::ffff:10.0.0.1", "2002:a00:1::1"]
    + ["64:ff9b::a00:1", "64:ff9b::808:808"],
)
async def test_gather_refuses_a_non_public_ipv6_before_any_lookup(offline, target):
    with pytest.raises(lookup.PrivateAddressError):
        await lookup.gather(target)
    offline["whois"].assert_not_called()
    offline["geo"].assert_not_called()
    assert offline["resolver"].queries == []


# --- gather(): a name with only an IPv6 address -----------------------------------


async def test_an_ipv6_only_name_resolves_through_aaaa(offline):
    data = await lookup.gather("v6only.example.com")

    assert data["resolved_ip"] == V6
    assert data["resolution"] == "ok"
    assert data["location"]["asn_number"] == 15169
    assert data["domain"]["aaaa"] == [{"ip": V6, "ttl": 300}]
    assert data["domain"]["status"]["a"] == "noanswer"
    # The PTR of the address it resolved to.
    assert [r["hostname"] for r in data["domain"]["ptr"]] == ["dns.google."]


async def test_an_ipv6_only_name_reports_tls_as_skipped(offline):
    data = await lookup.gather("v6only.example.com")

    assert data["ssl"] == {
        "error": "TLS not checked",
        "reason": "IPv6-only host; this server has no IPv6 connectivity",
    }
    offline["connect"].assert_not_called()


async def test_a_name_with_an_ipv4_address_keeps_its_tls_leg(offline):
    tls = MagicMock(return_value=None)
    with patch("managers.SSLManager.get_ssl_info", tls):
        data = await lookup.gather("dual.example.com")
    assert data["resolved_ip"] == V4
    tls.assert_called_once_with("dual.example.com", V4)
    assert data["domain"]["aaaa"][0]["ip"].startswith("2606:2800:")


@pytest.mark.parametrize("name", ["loopback.example.com", "mapped.example.com"])
async def test_a_name_whose_only_address_is_private_ipv6_is_refused(offline, name):
    records = MagicMock()
    with patch.object(lookup.domain_manager, "get_records", records):
        with pytest.raises(lookup.PrivateAddressError):
            await lookup.gather(name)
    records.assert_not_called()
    offline["connect"].assert_not_called()


async def test_aaaa_is_not_asked_when_the_name_does_not_exist(offline):
    offline["resolver"].outcomes["nosuch.example.com", "A"] = "nxdomain"
    data = await lookup.gather("nosuch.example.com", legs={"resolve"})
    assert data["resolution"] == "nxdomain"
    assert ("nosuch.example.com", "AAAA") not in offline["resolver"].queries


# --- get_records(): AAAA with its status ------------------------------------------


@pytest.mark.parametrize("outcome", ["timeout", "servfail", "nxdomain"])
def test_aaaa_reports_how_its_query_ended(offline, outcome):
    offline["resolver"].outcomes["dns.google", "AAAA"] = outcome
    records = managers.DomainManager().get_records("dns.google")
    assert records["aaaa"] == []
    assert records["status"]["aaaa"] == outcome


def test_no_aaaa_record_is_an_answer(offline):
    records = managers.DomainManager().get_records("v4only.example.com", ip=V4)
    assert records["aaaa"] == []
    assert records["status"]["aaaa"] == "noanswer"
    assert records["status"]["a"] == "ok"


def test_the_ptr_fallback_uses_aaaa_when_there_is_no_a(offline):
    # gather() passes no ip when its own gating queries failed; the sweep's
    # own answers then supply the address to ask a PTR of.
    records = managers.DomainManager().get_records("v6only.example.com")
    assert [r["hostname"] for r in records["ptr"]] == ["dns.google."]
    assert records["status"]["ptr"] == "ok"


# --- HTTP: JSON, page, text -------------------------------------------------------


def test_the_json_api_answers_an_ipv6_address(offline):
    response = client.get(f"/{V6}", headers=CURL)

    assert response.status_code == 200
    body = response.json()
    assert body["address"] == V6
    assert body["resolved_ip"] == V6
    assert body["location"]["asn_number"] == 15169
    assert body["location"]["reverse_dns"] == "dns.google."
    assert body["whois"]["name"] == "GOOGLE-IPV6"
    assert body["ssl"] is None
    # GeoIP coordinates feed the map exactly as an IPv4 address's do.
    assert body["map"] is not None
    assert body["location"]["lat"] == 37.751


def test_a_bracketed_ipv6_url_is_looked_up_as_its_address(offline):
    response = client.get("/[2001:4860:4860::8888]:8443", headers=CURL)
    assert response.status_code == 200
    assert response.json()["address"] == V6


def test_the_page_tags_an_ipv6_address_as_ipv6(offline):
    response = client.get(f"/{V6}", headers=CHROME)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    tags = re.findall(r'<span class="tag tone-\w+">([^<]*)</span>', response.text)
    assert "IPv6" in tags
    assert "IPv4" not in tags
    assert "dns.google." in response.text


def test_the_page_lists_aaaa_records(offline):
    response = client.get("/v6only.example.com", headers=CHROME)
    assert response.status_code == 200
    rows = re.findall(
        r"<tr>\s*<td>(\w+)</td>\s*<td>[^<]*</td>\s*<td[^>]*>([^<]*)</td>", response.text
    )
    assert ("AAAA", V6) in rows


def test_the_page_says_tls_was_skipped_for_an_ipv6_only_name(offline):
    response = client.get("/v6only.example.com", headers=CHROME)
    text = " ".join(re.sub(r"<[^>]+>", " ", response.text).split())
    assert "TLS not checked" in text
    assert "this server has no IPv6 connectivity" in text
    assert "No certificate" not in text


def test_text_format_answers_an_ipv6_address(offline):
    response = client.get(f"/{V6}?format=text", headers=CURL)

    assert response.status_code == 200
    block = dict(
        line.split(": ", 1) for line in response.text.splitlines() if ": " in line
    )
    assert block["target"] == V6
    assert block["ip"] == V6
    assert block["reverse_dns"] == "dns.google."
    assert block["asn_number"] == "15169"
    assert block["country_code"] == "US"
    assert block["registrant"] == "-"


def test_fields_answer_an_ipv6_address(offline):
    response = client.get(f"/{V6}?fields=asn_number,cidr", headers=CURL)
    assert response.status_code == 200
    assert response.json() == {"asn_number": 15169, "cidr": "2001:4860::/32"}


@pytest.mark.parametrize("path", ["/::1", "/fe80::1", "/fd12:3456::1"])
def test_a_local_ipv6_address_gets_the_local_network_page(offline, path):
    response = client.get(path, headers=CHROME)
    assert response.status_code == 400
    text = " ".join(re.sub(r"<[^>]+>", " ", response.text).split())
    assert f"{path[1:]} is a local network address" in text


def test_a_private_ipv6_address_is_the_same_400_as_ipv4_for_an_api_client(offline):
    response = client.get("/::1", headers=CURL)
    assert response.status_code == 400
    assert response.json() == {
        "detail": "Private or reserved IP addresses are not allowed"
    }


# --- MCP --------------------------------------------------------------------------


async def test_mcp_lookup_answers_an_ipv6_address(offline):
    payload = await mcp_server.lookup(V6)

    assert payload["target"] == V6
    assert payload["ip"] == V6
    assert payload["reverse_dns"] == "dns.google."
    assert payload["network"]["asn_number"] == 15169
    assert payload["geo"]["country_code"] == "US"
    assert payload["tls"] is None


def test_mcp_lookup_no_longer_says_ipv6_is_unsupported():
    assert "not supported" not in mcp_server.lookup.__doc__


async def test_mcp_ssl_certificate_says_why_an_ipv6_literal_has_none(offline):
    result = await mcp_server.ssl_certificate(V6)
    assert result.is_error
    assert result.structured_content == {
        "error": "TLS is checked for domain names only, not IP addresses"
    }


async def test_mcp_ssl_certificate_says_tls_was_skipped_for_an_ipv6_only_name(offline):
    result = await mcp_server.ssl_certificate("v6only.example.com")
    assert result.is_error
    payload = result.structured_content
    assert "TLS not checked" in payload["error"]
    assert "IPv6" in payload["error"]
    assert "No TLS certificate served" not in payload["error"]


async def test_mcp_dns_records_answers_aaaa(offline):
    payload = await mcp_server.dns_records("dns.google", types=["aaaa"])
    assert payload["records"] == {
        "aaaa": [
            {"ip": V6, "ttl": 300},
            {"ip": "2001:4860:4860::8844", "ttl": 300},
        ]
    }


async def test_mcp_dns_records_marks_a_failed_aaaa_query(offline):
    offline["resolver"].outcomes["dns.google", "AAAA"] = "timeout"
    payload = await mcp_server.dns_records("dns.google", types=["aaaa"])
    assert payload["records"] == {"aaaa": {"error": "timeout"}}


def test_mcp_dns_records_documents_aaaa():
    assert "aaaa" in mcp_server._RECORD_TYPES
    assert "AAAA" in mcp_server.dns_records.__doc__


# --- the view model ---------------------------------------------------------------


def _ip_response(address):
    return {
        "address": address,
        "location": _location(address),
        "domain": {},
        "whois": {},
        "ssl": None,
    }


@pytest.mark.parametrize(
    "address, version",
    [(V6, "IPv6"), ("8.8.8.8", "IPv4"), ("::ffff:8.8.8.8", "IPv4")],
)
def test_the_ip_tag_comes_from_the_address(address, version):
    tags = [
        tag["text"] for tag in build_view(_ip_response(address), is_self=True)["tags"]
    ]
    assert tags[0] == version


def test_the_dns_column_counts_aaaa():
    response = {
        "address": "dns.google",
        "location": {},
        "domain": {"a": [{"ip": "8.8.8.8"}], "aaaa": [{"ip": V6}, {"ip": "::2"}]},
        "ssl": None,
    }
    view = build_view(response, is_self=False)
    rows = {row["label"]: row["value"] for row in view["facts"][1]["rows"]}
    assert rows["AAAA"] == "2 records"
    hints = {item["id"]: item["hint"] for item in view["accordions"]}
    assert "AAAA 2" in hints["dns"]


def test_an_ipv6_only_name_is_tagged_with_its_aaaa_address():
    response = {
        "address": "v6only.example.com",
        "location": {},
        "domain": {"a": [], "aaaa": [{"ip": V6}]},
        "ssl": None,
    }
    tags = [t["text"] for t in build_view(response, is_self=False)["tags"]]
    assert f"AAAA → {V6}" in tags


def test_the_reverse_column_of_an_ipv6_address_counts_aaaa():
    response = dict(
        _ip_response(V6),
        domain={"a": [{"ip": "8.8.8.8", "ttl": 60}], "aaaa": [{"ip": V6, "ttl": 300}]},
    )
    column = build_view(response, is_self=False)["facts"][1]
    rows = {row["label"]: row["value"] for row in column["rows"]}
    assert rows["AAAA"] == "1 record"
    assert "A" not in rows
    assert rows["TTL"] == "300s"


# --- the search box (static/js/app.js) --------------------------------------------

APP_JS = Path("static/js/app.js")
NODE = shutil.which("node")


def _js(names, expression):
    """Evaluate `expression` in node against app.js's own top-level `names`."""
    source = APP_JS.read_text(encoding="utf-8")
    parts = []
    for name in names:
        match = re.search(
            rf"^(?:const {name} = .*?;|function {name}\(.*?^\}})$", source, re.M | re.S
        )
        parts.append(match.group(0))
    script = "\n".join(parts) + f"\nconsole.log(JSON.stringify({expression}));"
    # The script is app.js's own source plus a fixed expression.
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    return json.loads(out.stdout)


SEARCH = ["IPV4", "DOMAIN", "PROBE_SUFFIX", "ipv6Host", "isLookupTarget"]

CANDIDATES = [
    V6,
    "2001:4860:4860:0:0:0:0:8888",
    "2001:DB8::1",
    "::",
    "::1",
    "fe80::1",
    "::ffff:8.8.8.8",
    "2001:db8::1.2.3.4",
    "1:2:3:4:5:6:7::",
    "1:2:3:4:5:6:7:8",
    "1::2::3",
    "1:2:3:4:5:6:7:8:9",
    "2001:db8::g",
    "12345::1",
    ":1",
    "1:",
    "fe80::1%eth0",
    "x]@[::1",
    "::ffff:1.2.3",
    "example.com",
    "8.8.8.8",
]


def _python_is_ipv6(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 6 and not address.scope_id


@pytest.mark.skipif(NODE is None, reason="needs node")
def test_the_search_box_and_the_server_agree_on_what_is_ipv6():
    expression = f"{json.dumps(CANDIDATES)}.map((v) => ipv6Host(v) !== null)"
    assert _js(["ipv6Host"], expression) == [_python_is_ipv6(v) for v in CANDIDATES]


@pytest.mark.skipif(NODE is None, reason="needs node")
def test_the_search_box_accepts_an_ipv6_address():
    values = [V6, "2001:DB8::1", "::ffff:8.8.8.8", "fe80::1%eth0", "x]@[::1"]
    expression = f"{json.dumps(values)}.map(isLookupTarget)"
    assert _js(SEARCH, expression) == [True, True, True, False, False]


@pytest.mark.skipif(NODE is None, reason="needs node")
def test_the_search_box_strips_a_url_around_an_ipv6_address_like_the_server():
    values = [
        "[2001:db8::1]",
        "http://[2001:db8::1]:8443/path?q=1",
        "https://[2001:db8::1]/",
        "2001:db8::1",
        "example.com:443",
    ]
    expression = f"{json.dumps(values)}.map(normalizeLookupTarget)"
    js = _js(["normalizeLookupTarget"], expression)
    assert js == [lookup.normalize_lookup_target(v) for v in values]
    assert js[:4] == ["2001:db8::1"] * 4


@pytest.mark.skipif(NODE is None, reason="needs node")
def test_the_search_box_and_the_server_agree_on_what_ipv6_is_local():
    values = [
        "::1", "::", "::2", "fe80::1", "febf:ffff::1", "fec0::1", "fe7f::1",
        "fc00::1", "fd12:3456::1", "fdff::1", "fbff::1", "fe00::1",
        V6, "2001:db8::1", "::ffff:192.168.0.1",
    ]  # fmt: skip

    def server_is_local(value):
        address = ipaddress.ip_address(value)
        return any(address in network for network in main._LOCAL_NETWORKS)

    expression = f"{json.dumps(values)}.map(isLocalAddress)"
    js = _js(["IPV4", "ipv6Host", "isLocalAddress"], expression)
    assert js == [server_is_local(v) for v in values]
