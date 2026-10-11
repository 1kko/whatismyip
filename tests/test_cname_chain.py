"""The CNAME chain behind an A answer, and the name it ends at.

fetch_cname reports the first hop alone, and fetch_a kept only the addresses
and their TTL, so for a name behind a CDN (www.microsoft.com -> edgekey ->
akamaiedge) the page showed one hop and then presented the Akamai edge's
address, location and ASN as the site's own. dnspython already returns every
hop inside the A answer (Answer.chaining_result.cnames, Answer.canonical_name),
so these pin that get_records() reads them off that answer, hop order and
per-hop TTL intact, spending no query on them; that the page draws a row per
hop and says whose location it shows; and that dns_records relays both.

The resolver is a fake that serves real dns.resolver.Answer objects, built the
way test_resolver_unification builds one, so dnspython derives the chain from
the answer section exactly as it does for a live response. gather()'s other
legs are answered locally. No network.
"""

import re

import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest
from fastapi.testclient import TestClient

import lookup
import managers
import mcp_server
from main import app

QNAME = "www.microsoft.com"
# The chain production served on 2026-10-10: two hops, each with the TTL the
# resolver had left for it, then the A record at the Akamai edge (TTL 20).
HOPS = [
    ("www.microsoft.com-c-3.edgekey.net.", 300),
    ("e13678.dscb.akamaiedge.net.", 60),
]
CANONICAL = "e13678.dscb.akamaiedge.net"
EDGE_IP = "104.94.218.45"

RAISE = {
    "timeout": lambda: dns.resolver.LifetimeTimeout(timeout=3.0, errors=[]),
    "servfail": dns.resolver.NoNameservers,
    "nxdomain": dns.resolver.NXDOMAIN,
    "noanswer": dns.resolver.NoAnswer,
}


def _answer(qname, rdtype, values, ttl, hops=()):
    """A real dns.resolver.Answer whose answer section holds the CNAME `hops`
    ((target, ttl) in order, the first owned by `qname`) the way a recursive
    resolver returns them, and then the `rdtype` rrset at the last target.
    dnspython reads chaining_result and canonical_name off that section
    itself, so the code under test sees what a live answer gives it."""
    name = dns.name.from_text(qname)
    response = dns.message.make_response(dns.message.make_query(name, rdtype))
    owner = name
    for target, hop_ttl in hops:
        rrset = response.find_rrset(
            response.answer,
            owner,
            dns.rdataclass.IN,
            dns.rdatatype.CNAME,
            create=True,
        )
        rrset.update_ttl(hop_ttl)
        rrset.add(dns.rdata.from_text("IN", "CNAME", target))
        owner = dns.name.from_text(target)
    rrset = response.find_rrset(
        response.answer,
        owner,
        dns.rdataclass.IN,
        dns.rdatatype.from_text(rdtype),
        create=True,
    )
    rrset.update_ttl(ttl)
    for value in values:
        rrset.add(dns.rdata.from_text("IN", rdtype, value))
    return dns.resolver.Answer(
        name, dns.rdatatype.from_text(rdtype), dns.rdataclass.IN, response
    )


class FakeResolver:
    """Serves the prebuilt answers in `answers` by (name, type) and logs every
    query; `outcomes` makes one fail the way dnspython reports it, and any
    other (name, type) has no record. SOA always fails, so zone_apex() settles
    on the registrable domain without a zone walk to fake."""

    def __init__(self):
        self.answers = {}
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
        if (name, rdtype) in self.answers:
            return self.answers[name, rdtype]
        raise dns.resolver.NoAnswer()


@pytest.fixture
def fake_dns(monkeypatch):
    fake = FakeResolver()
    fake.answers[QNAME, "A"] = _answer(QNAME, "A", [EDGE_IP], 20, HOPS)
    # The CNAME-type query answers the first hop alone, as a resolver does.
    fake.answers[QNAME, "CNAME"] = _answer(QNAME, "CNAME", [HOPS[0][0]], 300)
    monkeypatch.setattr(managers, "_recursive_resolver", lambda: fake)
    # gather()'s gating A query goes through the name lookup imported.
    monkeypatch.setattr(lookup, "_recursive_resolver", lambda: fake)
    return fake


@pytest.fixture
def offline(monkeypatch, fake_dns):
    """gather()'s WHOIS, GeoIP and TLS legs, answered locally."""

    async def fake_whois(target):
        return {"source": "rdap", "name": target}

    monkeypatch.setattr(lookup, "lookup_whois", fake_whois)
    monkeypatch.setattr(lookup.geo_ip_manager, "fetch_location", lambda ip: {"ip": ip})
    monkeypatch.setattr(
        managers.SSLManager,
        "get_ssl_info",
        staticmethod(lambda hostname, verified_ip=None: None),
    )
    return fake_dns


JSON_UA = {"user-agent": "curl/8.0"}
client = TestClient(app, client=("118.235.14.201", 41234))
BROWSER_UA = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
    )
}


# --- get_records -----------------------------------------------------------


def test_the_chain_is_read_off_the_a_answer_in_hop_order(fake_dns):
    records = managers.DomainManager().get_records(QNAME, ip=EDGE_IP)

    assert records["cname_chain"] == [
        {"name": "www.microsoft.com.", "target": HOPS[0][0], "ttl": 300},
        {"name": HOPS[0][0], "target": HOPS[1][0], "ttl": 60},
    ]
    assert records["canonical_name"] == CANONICAL
    # Additive: the address rows, the first-hop `cname` and its status keep
    # their shape, and the A TTL is the A rrset's, not the chain's minimum.
    assert records["a"] == [{"ip": EDGE_IP, "ttl": 20}]
    assert records["status"]["a"] == "ok"
    assert records["cname"] == {"cname": HOPS[0][0], "ttl": 300}
    assert records["status"]["cname"] == "ok"
    assert records["queried_name"] == QNAME


def test_reading_the_chain_costs_no_query(fake_dns):
    """The completion condition's last leg. The hops are inside the A answer
    the sweep already has: nothing is asked about a hop's name, no (name,
    type) is asked twice -- a second A or CNAME query to rebuild the chain
    would be -- no type outside the sweep's own is asked, and the sweep asks
    exactly what it asks of the same name answering with no chain."""
    managers.DomainManager().get_records(QNAME, ip=EDGE_IP)
    chained = sorted(fake_dns.queries)
    hop_names = {target.rstrip(".") for target, _ in HOPS}
    assert not [query for query in chained if query[0] in hop_names]
    assert len(set(chained)) == len(chained), chained
    assert {rdtype for _, rdtype in chained} <= {
        "SOA",
        "NS",
        "A",
        "AAAA",
        "MX",
        "CNAME",
        "TXT",
        "PTR",
    }

    fake_dns.queries.clear()
    fake_dns.answers[QNAME, "A"] = _answer(QNAME, "A", [EDGE_IP], 20)
    managers.DomainManager().get_records(QNAME, ip=EDGE_IP)
    assert sorted(fake_dns.queries) == chained


def test_a_name_with_no_chain_is_its_own_canonical_name(fake_dns):
    fake_dns.answers["example.com", "A"] = _answer(
        "example.com", "A", ["93.184.216.34"], 300
    )

    records = managers.DomainManager().get_records("example.com")

    assert records["cname_chain"] == []
    assert records["canonical_name"] == "example.com"
    assert records["cname"] is None


def test_the_canonical_name_is_written_like_the_queried_name(fake_dns):
    """Lowercase and without the trailing dot, so the page and the MCP tool
    compare it to queried_name with ==. The hops keep DNS text, trailing dot
    and case included, like `cname` and the NS and MX hostnames."""
    fake_dns.answers["alias.example.org", "A"] = _answer(
        "alias.example.org",
        "A",
        ["192.0.2.1"],
        30,
        [("Edge.Example-Host.NET.", 120)],
    )

    records = managers.DomainManager().get_records("alias.example.org")

    assert records["canonical_name"] == "edge.example-host.net"
    assert records["cname_chain"] == [
        {"name": "alias.example.org.", "target": "Edge.Example-Host.NET.", "ttl": 120}
    ]


def test_a_name_without_a_chain_is_its_own_canonical_name_in_any_spelling(fake_dns):
    """dnspython spells the answer's name as an A-label even when it was asked
    a U-label, so read off the answer, bücher.example would come back as
    xn--bcher-kva.example and the page would say it 'Resolves via' a name
    that is only itself in another spelling. With no hop, canonical_name is
    queried_name, character for character."""
    fake_dns.answers["bücher.example", "A"] = _answer(
        "bücher.example", "A", ["192.0.2.7"], 300
    )

    records = managers.DomainManager().get_records("bücher.example")

    assert records["cname_chain"] == []
    assert records["canonical_name"] == records["queried_name"] == "bücher.example"


class TestWhichAnswerSuppliesTheChain:
    def test_an_ipv6_only_name_takes_its_chain_from_the_aaaa_answer(self, fake_dns):
        """Review Focus 2. The A query raised NoAnswer (the canonical name has
        no A record), so the chain is read off the AAAA answer: the same
        name's chain, from the same resolver."""
        fake_dns.answers["v6.example.org", "AAAA"] = _answer(
            "v6.example.org",
            "AAAA",
            ["2001:db8::1"],
            60,
            [("host6.example.net.", 600)],
        )

        records = managers.DomainManager().get_records("v6.example.org")

        assert records["status"]["a"] == "noanswer"
        assert records["status"]["aaaa"] == "ok"
        assert records["canonical_name"] == "host6.example.net"
        assert records["cname_chain"] == [
            {"name": "v6.example.org.", "target": "host6.example.net.", "ttl": 600}
        ]

    def test_the_a_answer_wins_when_both_answered(self, fake_dns):
        fake_dns.answers[QNAME, "AAAA"] = _answer(
            QNAME, "AAAA", ["2001:db8::2"], 20, [("other.example.net.", 10)]
        )

        records = managers.DomainManager().get_records(QNAME, ip=EDGE_IP)

        assert records["canonical_name"] == CANONICAL
        assert [hop["ttl"] for hop in records["cname_chain"]] == [300, 60]

    @pytest.mark.parametrize("outcome", ["timeout", "servfail", "nxdomain"])
    def test_no_answer_at_all_leaves_the_chain_unknown(self, fake_dns, outcome):
        """Review Focus 2. Neither query answered, so there is no chain to
        read: null and [] -- and status.a says why, which is where the page
        and the MCP tool look before they call [] "no chain"."""
        fake_dns.outcomes[QNAME, "A"] = outcome
        fake_dns.outcomes[QNAME, "AAAA"] = outcome

        records = managers.DomainManager().get_records(QNAME)

        assert records["canonical_name"] is None
        assert records["cname_chain"] == []
        assert records["status"]["a"] == outcome


# --- HTTP: JSON ---------------------------------------------------------------


def test_the_json_api_carries_the_chain_and_the_canonical_name(offline):
    body = client.get(f"/{QNAME}", headers=JSON_UA).json()

    assert body["resolved_ip"] == EDGE_IP
    assert body["domain"]["canonical_name"] == CANONICAL
    assert [hop["target"] for hop in body["domain"]["cname_chain"]] == [
        target for target, _ in HOPS
    ]
    # Unchanged beside them: the first-hop cname record.
    assert body["domain"]["cname"] == {"cname": HOPS[0][0], "ttl": 300}


# --- HTTP: the page ------------------------------------------------------------


def _dns_rows_of(html: str, rdtype: str) -> list[list[str]]:
    table = re.search(r'<table class="records records--dns">.*?</table>', html, re.S)
    assert table, "no DNS table"
    rows = re.findall(rf"<tr>\s*<td>{rdtype}</td>.*?</tr>", table.group(0), re.S)
    return [
        [cell.strip() for cell in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]
        for row in rows
    ]


def _geoip_rows_of(html: str) -> dict[str, str]:
    panel = re.search(r'id="acc-geoip".*?</details>', html, re.S)
    assert panel, "no GeoIP accordion"
    return {
        label.strip(): value.strip()
        for label, value in re.findall(
            r'<tr><td>(.*?)</td><td colspan="3" class="tone-\w+">(.*?)</td></tr>',
            panel.group(0),
            re.S,
        )
    }


def test_the_page_lists_every_hop_and_says_whose_location_it_shows(offline):
    """The completion condition: /www.microsoft.com shows one CNAME row per
    hop, under the hop's own name and TTL, and the GeoIP card says the
    address was reached through the Akamai edge name, so the location and
    ASN it shows are that name's."""
    html = client.get(f"/{QNAME}", headers=BROWSER_UA).text

    assert _dns_rows_of(html, "CNAME") == [
        ["CNAME", "www.microsoft.com", HOPS[0][0], "300"],
        ["CNAME", HOPS[0][0].rstrip("."), HOPS[1][0], "60"],
    ]
    assert _dns_rows_of(html, "A") == [["A", QNAME, EDGE_IP, "20"]]
    via = _geoip_rows_of(html)["Resolves via"]
    assert via == f"{CANONICAL} — the location and ASN above are its"
    # Only that the name differs is known, so the page does not call it a CDN.
    assert "CDN" not in via


def test_a_name_without_a_chain_gets_the_page_it_always_had(offline):
    offline.answers["example.com", "A"] = _answer(
        "example.com", "A", ["93.184.216.34"], 300
    )

    html = client.get("/example.com", headers=BROWSER_UA).text

    assert _dns_rows_of(html, "CNAME") == []
    assert "Resolves via" not in html


# --- MCP -----------------------------------------------------------------------


async def test_dns_records_returns_the_chain_beside_queried_name_and_zone(offline):
    """The completion condition's last leg: the tool relays the same chain
    and canonical name the page shows, beside queried_name and zone and not
    inside `records`, which lists _RECORD_TYPES alone."""
    payload = await mcp_server.dns_records(QNAME)

    assert payload["queried_name"] == QNAME
    assert payload["canonical_name"] == CANONICAL
    assert payload["cname_chain"] == [
        {"name": "www.microsoft.com.", "target": HOPS[0][0], "ttl": 300},
        {"name": HOPS[0][0], "target": HOPS[1][0], "ttl": 60},
    ]
    assert "cname_chain" not in payload["records"]
    assert "canonical_name" not in payload["records"]
    assert payload["records"]["cname"] == {"cname": HOPS[0][0], "ttl": 300}


async def test_narrowing_the_types_keeps_the_chain(offline):
    """Review Focus 3. `types` filters `records` alone, as it does for
    queried_name and zone."""
    payload = await mcp_server.dns_records(QNAME, types=["a"])

    assert set(payload["records"]) == {"a"}
    assert payload["canonical_name"] == CANONICAL
    assert [hop["ttl"] for hop in payload["cname_chain"]] == [300, 60]


async def test_a_failed_a_query_leaves_the_chain_empty_and_a_in_error(offline):
    """Review Focus 3. With neither A nor AAAA answered there is no chain to
    read, so the chain is [] and the name null while `a` carries the error:
    the description tells the model that this [] is unverified, not empty."""
    offline.outcomes[QNAME, "A"] = "timeout"
    offline.outcomes[QNAME, "AAAA"] = "timeout"

    payload = await mcp_server.dns_records(QNAME, types=["a"])

    assert payload["records"]["a"] == {"error": "timeout"}
    assert payload["cname_chain"] == []
    assert payload["canonical_name"] is None


MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "Host": "ip.1kko.com",
}
INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2026-07-28",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}


def test_the_tool_description_says_what_the_chain_is_and_when_it_is_unknown():
    """What a model reads before it relays the answer. `with TestClient(app)`
    runs the lifespan, which the MCP session manager needs."""
    with TestClient(app) as mcp_client:
        mcp_client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        response = mcp_client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers=MCP_HEADERS,
        )
    tools = {tool["name"]: tool for tool in response.json()["result"]["tools"]}
    description = tools["dns_records"]["description"]
    assert "`cname_chain`" in description and "`canonical_name`" in description
    assert "cost no query" in description
    assert "the chain is unverified, not empty" in description
