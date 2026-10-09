"""Zone-apex selection for the NS / MX / SPF lookups.

Counting labels cannot find a zone: keeping the last two turned naver.co.kr
into co.kr and www.bbc.co.uk into co.uk, so NS came back as the registry's
nameservers and MX came back empty -- which a model relays as "this domain has
no mail server". A PTR name made it worse: 'dns.google.' kept its trailing dot
and shrank to 'google.', a TLD.

Every query here goes to a small in-memory DNS standing in for the public
resolvers, and the real dnspython zone_for_name() walks it, so these pin the
behaviour a recursive resolver actually produces (an SOA answer at an apex, an
authority-section SOA below one) rather than a mocked return value. No network.
"""

import dns.exception
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.rrset
import pytest

import managers
from config import DNS_QUERY_LIFETIME

SOA_RDATA = "ns.invalid. hostmaster.invalid. 1 7200 3600 1209600 300"


class FakeAnswer:
    """The slice of dns.resolver.Answer that get_records() reads."""

    def __init__(self, rrset):
        self.rrset = rrset

    def __iter__(self):
        return iter(self.rrset)

    def __getitem__(self, index):
        return list(self.rrset)[index]


class FakeDNS:
    """A recursive resolver over a fixed set of zones.

    `zones` are the apexes that answer SOA; `records` maps (name, type) to
    rdata text. A name with no records of the asked type gets NoAnswer if it
    exists and NXDOMAIN if not, each carrying the enclosing zone's SOA in the
    authority section -- exactly what zone_for_name() reads to find an apex
    without walking every label.
    """

    def __init__(self, zones, records, fail_soa=False):
        self.zones = set(zones)
        self.records = records
        self.fail_soa = fail_soa
        self.queries = []

    def _enclosing_zone(self, name):
        labels = name.split(".")
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self.zones:
                return candidate
        return None

    def _exists(self, name):
        return name in self.zones or any(
            owner == name or owner.endswith("." + name) for owner, _ in self.records
        )

    def resolve(self, qname, rdtype="A", *args, **kwargs):
        name = str(qname).rstrip(".").lower()
        rdtype = dns.rdatatype.to_text(dns.rdatatype.RdataType.make(rdtype))
        self.queries.append((name, rdtype))
        absolute = dns.name.from_text(name)

        if rdtype == "SOA":
            if self.fail_soa:
                raise dns.resolver.LifetimeTimeout(
                    timeout=DNS_QUERY_LIFETIME, errors=[]
                )
            if name in self.zones:
                return FakeAnswer(
                    dns.rrset.from_text(absolute, 300, "IN", "SOA", SOA_RDATA)
                )
        elif (name, rdtype) in self.records:
            return FakeAnswer(
                dns.rrset.from_text(
                    absolute, 300, "IN", rdtype, *self.records[name, rdtype]
                )
            )

        response = dns.message.make_response(dns.message.make_query(absolute, rdtype))
        zone = self._enclosing_zone(name)
        if zone is not None:
            response.authority.append(
                dns.rrset.from_text(zone + ".", 300, "IN", "SOA", SOA_RDATA)
            )
        if self._exists(name):
            raise dns.resolver.NoAnswer(response=response)
        raise dns.resolver.NXDOMAIN(qnames=[absolute], responses={absolute: response})

    def asked(self, rdtype):
        return {name for name, kind in self.queries if kind == rdtype}


ZONES = [
    "kr",
    "co.kr",
    "naver.co.kr",
    "uk",
    "co.uk",
    "bbc.co.uk",
    "au",
    "net.au",
    "abc.net.au",
    "google",
    "dns.google",
    "in-addr.arpa",
]

RECORDS = {
    # Registry zones: these must never be presented as a domain's own.
    ("co.kr", "NS"): ["b.dns.kr.", "c.dns.kr."],
    ("co.uk", "NS"): ["nsa.nic.uk.", "nsb.nic.uk."],
    ("net.au", "NS"): ["a.au.", "b.au."],
    ("google", "NS"): ["ns-tld1.charlestonroadregistry.com."],
    # naver.co.kr: MX at the apex, queried at the apex.
    ("naver.co.kr", "A"): ["223.130.200.104"],
    ("naver.co.kr", "NS"): ["ns1.naver.com.", "ns2.naver.com."],
    ("naver.co.kr", "MX"): ["10 mx1.naver.com."],
    ("naver.co.kr", "TXT"): ['"v=spf1 include:_spf.naver.com ~all"'],
    ("www.naver.co.kr", "A"): ["223.130.200.104"],
    # bbc.co.uk: www has no MX of its own, but mail.bbc.co.uk does.
    ("bbc.co.uk", "NS"): ["dns0.bbc.co.uk.", "dns1.bbc.co.uk."],
    ("bbc.co.uk", "MX"): ["10 cluster1.eu.messagelabs.com."],
    ("bbc.co.uk", "TXT"): ['"v=spf1 ip4:212.58.224.0/19 ~all"'],
    ("www.bbc.co.uk", "A"): ["151.101.0.81"],
    ("mail.bbc.co.uk", "MX"): ["5 inbound.bbc.co.uk."],
    # abc.net.au
    ("abc.net.au", "NS"): ["ns1.abc.net.au.", "ns2.abc.net.au."],
    ("abc.net.au", "MX"): ["10 abc-net-au.mail.protection.outlook.com."],
    ("www.abc.net.au", "A"): ["23.40.42.10"],
    # 8.8.8.8 -> dns.google., a zone of its own one label below the TLD.
    ("8.8.8.8.in-addr.arpa", "PTR"): ["dns.google."],
    ("dns.google", "A"): ["8.8.8.8", "8.8.4.4"],
    ("dns.google", "NS"): ["ns1.zdns.google.", "ns2.zdns.google."],
}


@pytest.fixture
def fake_dns(monkeypatch):
    fake = FakeDNS(ZONES, RECORDS)
    monkeypatch.setattr(managers, "_recursive_resolver", lambda: fake)
    return fake


def ns_hosts(records):
    return sorted(r["hostname"] for r in records["ns"])


def mx_hosts(records):
    return sorted(r["hostname"] for r in records["mx"])


@pytest.mark.parametrize(
    "queried, zone, ns, mx, mx_from_zone",
    [
        # The completion condition: naver.co.kr is its own zone, not co.kr's.
        (
            "naver.co.kr",
            "naver.co.kr",
            ["ns1.naver.com.", "ns2.naver.com."],
            ["mx1.naver.com."],
            None,
        ),
        (
            "www.naver.co.kr",
            "naver.co.kr",
            ["ns1.naver.com.", "ns2.naver.com."],
            ["mx1.naver.com."],
            "naver.co.kr",
        ),
        (
            "www.bbc.co.uk",
            "bbc.co.uk",
            ["dns0.bbc.co.uk.", "dns1.bbc.co.uk."],
            ["cluster1.eu.messagelabs.com."],
            "bbc.co.uk",
        ),
        # A name with MX of its own keeps it: the zone's MX is only a fallback.
        (
            "mail.bbc.co.uk",
            "bbc.co.uk",
            ["dns0.bbc.co.uk.", "dns1.bbc.co.uk."],
            ["inbound.bbc.co.uk."],
            None,
        ),
        (
            "www.abc.net.au",
            "abc.net.au",
            ["ns1.abc.net.au.", "ns2.abc.net.au."],
            ["abc-net-au.mail.protection.outlook.com."],
            "abc.net.au",
        ),
    ],
)
def test_ns_and_mx_come_from_the_zone_apex_not_the_registry(
    fake_dns, queried, zone, ns, mx, mx_from_zone
):
    records = managers.DomainManager().get_records(queried)

    assert records["queried_name"] == queried
    assert records["zone"] == zone
    assert ns_hosts(records) == ns
    assert mx_hosts(records) == mx
    assert [r.get("from_zone") for r in records["mx"]] == [mx_from_zone] * len(mx)
    # The registry zone is never asked for this domain's NS or MX.
    registry = zone.split(".", 1)[1]
    assert registry not in fake_dns.asked("NS")
    assert registry not in fake_dns.asked("MX")


def test_mx_is_asked_of_the_exact_name_first(fake_dns):
    managers.DomainManager().get_records("www.bbc.co.uk")

    mx_queries = [name for name, kind in fake_dns.queries if kind == "MX"]
    assert mx_queries == ["www.bbc.co.uk", "bbc.co.uk"]


def test_a_name_that_does_not_exist_gets_no_zone_mx(fake_dns):
    """The zone's MX stands in only for a name that exists without MX of its
    own (NoAnswer). Mail to a name that does not exist (NXDOMAIN) goes nowhere,
    so lending it the zone's MX would describe a route that is not there."""
    records = managers.DomainManager().get_records("nosuch.bbc.co.uk")

    assert records["zone"] == "bbc.co.uk"
    assert records["mx"] == []
    assert fake_dns.asked("MX") == {"nosuch.bbc.co.uk"}


def test_spf_is_inherited_from_the_zone_apex(fake_dns):
    records = managers.DomainManager().get_records("www.bbc.co.uk")

    assert [s["text"] for s in records["spf"]] == ["v=spf1 ip4:212.58.224.0/19 ~all"]
    assert "co.uk" not in fake_dns.asked("TXT")


def test_the_zone_is_found_once_per_lookup_within_one_query_budget(
    fake_dns, monkeypatch
):
    """NS, MX and SPF all hang off the zone, so it is resolved once and shared,
    and the walk up the labels gets one query's budget in total rather than one
    per label."""
    calls = []
    real = dns.resolver.zone_for_name

    def spy(name, *args, **kwargs):
        calls.append(kwargs)
        return real(name, *args, **kwargs)

    monkeypatch.setattr(dns.resolver, "zone_for_name", spy)
    managers.DomainManager().get_records("www.bbc.co.uk")

    assert len(calls) == 1
    assert calls[0]["resolver"] is fake_dns
    assert 0 < calls[0]["lifetime"] <= DNS_QUERY_LIFETIME
    # The authority-section SOA names the apex from the first answer.
    assert fake_dns.asked("SOA") == {"www.bbc.co.uk"}


def test_a_failed_zone_lookup_falls_back_to_the_registrable_domain(monkeypatch):
    fake = FakeDNS(ZONES, RECORDS, fail_soa=True)
    monkeypatch.setattr(managers, "_recursive_resolver", lambda: fake)

    records = managers.DomainManager().get_records("www.naver.co.kr")

    assert records["zone"] == "naver.co.kr"
    assert ns_hosts(records) == ["ns1.naver.com.", "ns2.naver.com."]
    assert "co.kr" not in fake.asked("NS")


def test_a_nonexistent_domain_is_not_handed_the_registry_zone(fake_dns):
    """NXDOMAIN carries the registry's SOA, so zone_for_name answers co.kr. That
    is true of the DNS tree but would list the registry's nameservers as this
    name's own; the registrable domain is the floor."""
    records = managers.DomainManager().get_records("no-such-name-zz.co.kr")

    assert records["zone"] == "no-such-name-zz.co.kr"
    assert records["ns"] == []
    assert "co.kr" not in fake_dns.asked("NS")


def test_a_public_suffix_queried_directly_is_its_own_zone(fake_dns):
    records = managers.DomainManager().get_records("co.kr")

    assert records["zone"] == "co.kr"
    assert ns_hosts(records) == ["b.dns.kr.", "c.dns.kr."]


async def test_an_ip_whose_ptr_ends_in_a_dot_keeps_its_zone(fake_dns, monkeypatch):
    """perform_reverse_lookup returns the PTR target as DNS text, trailing dot
    and all; 'dns.google.' must not shrink to 'google.' on its way to the
    record sweep."""
    import lookup

    monkeypatch.setattr(
        lookup.domain_manager, "perform_reverse_lookup", lambda ip: "dns.google."
    )
    monkeypatch.setattr(lookup.geo_ip_manager, "fetch_location", lambda ip: {"ip": ip})

    async def fake_whois(target):
        return {"source": "rdap", "name": target}

    monkeypatch.setattr(lookup, "lookup_whois", fake_whois)

    result = await lookup.gather("8.8.8.8")
    domain = result["domain"]

    assert domain["queried_name"] == "dns.google"
    assert domain["zone"] == "dns.google"
    assert ns_hosts(domain) == ["ns1.zdns.google.", "ns2.zdns.google."]
    assert "google" not in fake_dns.asked("NS")
    assert "google" not in fake_dns.asked("MX")


async def test_dns_records_tool_reports_the_queried_name_and_zone(monkeypatch):
    import mcp_server

    async def fake_gather(target):
        return {
            "address": target,
            "resolved_ip": "151.101.0.81",
            "domain": {
                "queried_name": "www.bbc.co.uk",
                "zone": "bbc.co.uk",
                "a": [{"ip": "151.101.0.81", "ttl": 300}],
                "mx": [
                    {
                        "preference": 10,
                        "hostname": "cluster1.eu.messagelabs.com.",
                        "ttl": 300,
                        "ip": None,
                        "from_zone": "bbc.co.uk",
                    }
                ],
                "ns": [],
            },
        }

    monkeypatch.setattr(mcp_server, "gather", fake_gather)

    payload = await mcp_server.dns_records("www.bbc.co.uk", types=["mx"])

    assert payload["queried_name"] == "www.bbc.co.uk"
    assert payload["zone"] == "bbc.co.uk"
    # Additive: the existing keys keep their shape, and `records` still holds
    # record types only.
    assert payload["domain"] == "www.bbc.co.uk"
    assert payload["resolved_ip"] == "151.101.0.81"
    assert set(payload["records"]) == {"mx"}
    assert payload["records"]["mx"][0]["from_zone"] == "bbc.co.uk"
