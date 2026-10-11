"""A DNS query that failed is reported as a failure, never as "no records".

Every fetcher in get_records() used to end in `except Exception: return []`, so
a timeout, a SERVFAIL from a broken DNSSEC chain, a name that does not exist and
a name that simply has no record of that type all reached the page as "—" and
the MCP dns_records tool as a confident []. These pin the four apart at every
layer that shows them: get_records(), the JSON API, the page and MCP.

The resolver is a fake, and so are gather()'s other legs: no network.
"""

import re
import threading

import dns.exception
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest
from fastapi.testclient import TestClient

import lookup
import managers
import mcp_server
import viewmodel
from main import app

RAISE = {
    "timeout": lambda: dns.resolver.LifetimeTimeout(timeout=3.0, errors=[]),
    "servfail": dns.resolver.NoNameservers,
    "nxdomain": dns.resolver.NXDOMAIN,
    "noanswer": dns.resolver.NoAnswer,
    "error": lambda: OSError("network is unreachable"),
}

RECORDS = {
    ("example.com", "A"): ["93.184.216.34"],
    ("example.com", "NS"): ["a.iana-servers.net.", "b.iana-servers.net."],
    ("example.com", "MX"): ["10 mail.example.com."],
    ("example.com", "TXT"): ['"v=spf1 -all"'],
    ("www.example.com", "A"): ["93.184.216.34"],
    ("www.example.com", "TXT"): ['"v=spf1 include:_spf.example.net -all"'],
    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=none; rua=mailto:dmarc@example.com"'],
    ("34.216.184.93.in-addr.arpa", "PTR"): ["edge.example.net."],
}


class FakeAnswer:
    """The slice of dns.resolver.Answer that get_records() and gather() read."""

    def __init__(self, rrset):
        self.rrset = rrset
        # What dnspython derives from the CNAME hops it followed: none here,
        # so the answer's own name is the canonical name.
        self.chaining_result = dns.message.ChainingResult(
            rrset.name, rrset, rrset.ttl, []
        )
        self.canonical_name = rrset.name

    def __iter__(self):
        return iter(self.rrset)

    def __getitem__(self, index):
        return list(self.rrset)[index]


class FakeResolver:
    """Answers from RECORDS; `outcomes` makes one (name, type) query fail the
    way dnspython reports it, and `missing` names do not exist at all.

    SOA always fails, so zone_apex() falls back to the registrable domain and
    www.example.com's zone is example.com without a zone walk to fake.
    """

    def __init__(self, records):
        self.records = records
        self.outcomes = {}
        self.missing = set()
        self.queries = []

    def resolve(self, qname, rdtype="A", *args, **kwargs):
        name = str(qname).rstrip(".").lower()
        rdtype = dns.rdatatype.to_text(dns.rdatatype.RdataType.make(rdtype))
        self.queries.append((name, rdtype))
        if rdtype == "SOA":
            raise dns.resolver.NoNameservers()
        if name in self.missing:
            raise dns.resolver.NXDOMAIN()
        outcome = self.outcomes.get((name, rdtype))
        if outcome:
            raise RAISE[outcome]()
        if (name, rdtype) in self.records:
            return FakeAnswer(
                dns.rrset.from_text(
                    name + ".", 300, "IN", rdtype, *self.records[name, rdtype]
                )
            )
        raise dns.resolver.NoAnswer()

    def fail(self, name, outcome, *rdtypes):
        """Make every listed query for `name` come back as `outcome`."""
        if outcome == "nxdomain" and not rdtypes:
            self.missing.add(name)
        for rdtype in rdtypes or ("A", "MX", "NS", "CNAME", "TXT"):
            self.outcomes[name, rdtype] = outcome


@pytest.fixture
def fake_dns(monkeypatch):
    fake = FakeResolver(dict(RECORDS))
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


OUTCOMES = ["timeout", "servfail", "nxdomain", "noanswer"]


# --- the mapping ---------------------------------------------------------


@pytest.mark.parametrize(
    "exc, status",
    [
        (dns.resolver.NoAnswer(), "noanswer"),
        (dns.resolver.NXDOMAIN(), "nxdomain"),
        # What dnspython raises once every resolver answered SERVFAIL, as
        # 8.8.8.8 and 1.1.1.1 both do for dnssec-failed.org.
        (dns.resolver.NoNameservers(), "servfail"),
        (dns.resolver.LifetimeTimeout(timeout=3.0, errors=[]), "timeout"),
        (dns.exception.Timeout(), "timeout"),
        # Raised outside dnspython's resolver loop (which folds a server's
        # socket error into NoNameservers): no DNS outcome to name.
        (dns.name.LabelTooLong(), "error"),
        (OSError("network is unreachable"), "error"),
    ],
)
def test_dns_status_maps_dnspython_outcomes(exc, status):
    assert managers.dns_status(exc) == status


def test_the_page_has_words_for_every_failure_and_only_failures():
    """viewmodel mirrors the failure set rather than importing managers, which
    would load dnspython and the GeoIP readers into every template test."""
    assert set(viewmodel.DNS_FAILURE_TEXT) == managers.DNS_FAILURES
    assert managers.DNS_FAILURES == {"timeout", "servfail", "error"}


# --- get_records ---------------------------------------------------------


def test_every_record_type_reports_ok_alongside_unchanged_keys(fake_dns):
    records = managers.DomainManager().get_records("example.com", ip="93.184.216.34")

    assert records["status"] == {
        "a": "ok",
        "aaaa": "noanswer",
        "mx": "ok",
        "ns": "ok",
        "cname": "noanswer",
        "txt": "ok",
        "spf": "ok",
        "ptr": "ok",
    }
    # Additive: every key an API consumer already reads keeps its shape.
    assert records["a"] == [{"ip": "93.184.216.34", "ttl": 300}]
    assert records["cname"] is None
    assert [r["hostname"] for r in records["mx"]] == ["mail.example.com."]
    assert [r["hostname"] for r in records["ptr"]] == ["edge.example.net."]


@pytest.mark.parametrize("outcome", OUTCOMES)
@pytest.mark.parametrize(
    "rdtype, key, empty",
    [("A", "a", []), ("MX", "mx", []), ("NS", "ns", []), ("CNAME", "cname", None)],
)
def test_each_failure_reaches_its_own_type_only(fake_dns, outcome, rdtype, key, empty):
    fake_dns.fail("example.com", outcome, rdtype)

    records = managers.DomainManager().get_records("example.com", ip="93.184.216.34")

    assert records["status"][key] == outcome
    assert records[key] == empty
    # example.com has no CNAME or AAAA here, so those two answer noanswer.
    others = {
        k: v for k, v in records["status"].items() if k not in (key, "cname", "aaaa")
    }
    assert set(others.values()) == {"ok"}


def test_four_outcomes_are_four_statuses(fake_dns):
    seen = set()
    for outcome in OUTCOMES:
        fake_dns.outcomes.clear()
        fake_dns.fail("example.com", outcome, "TXT")
        records = managers.DomainManager().get_records("example.com")
        assert records["txt"] == []
        seen.add(records["status"]["txt"])
    assert seen == set(OUTCOMES)


def test_a_name_that_does_not_exist_is_nxdomain_not_empty(fake_dns):
    fake_dns.fail("nosuch.example.com", "nxdomain")

    records = managers.DomainManager().get_records("nosuch.example.com")

    for key in ("a", "mx", "cname", "txt"):
        assert records["status"][key] == "nxdomain", key
    # Its zone exists, and that answer is still the zone's.
    assert records["status"]["ns"] == "ok"


class TestMxZoneFallback:
    """A name with no MX of its own shows its zone's, so the MX status is the
    status of whichever query the row ends up standing on."""

    def test_the_zones_answer_is_ok_and_labelled(self, fake_dns):
        records = managers.DomainManager().get_records("www.example.com")

        assert records["status"]["mx"] == "ok"
        assert [r["from_zone"] for r in records["mx"]] == ["example.com"]

    @pytest.mark.parametrize("outcome", ["timeout", "servfail"])
    def test_a_zone_that_cannot_answer_is_a_failure_not_none(self, fake_dns, outcome):
        """The name said "no MX here", which sends the row to the zone; the
        zone never answered, so the row is unknown. Reporting the name's
        noanswer instead would render "no mail server" for a domain that may
        well have one -- the misreading the zone fallback exists to prevent."""
        fake_dns.fail("example.com", outcome, "MX")

        records = managers.DomainManager().get_records("www.example.com")

        assert records["mx"] == []
        assert records["status"]["mx"] == outcome

    def test_neither_having_mx_is_noanswer(self, fake_dns):
        fake_dns.fail("example.com", "noanswer", "MX")

        records = managers.DomainManager().get_records("www.example.com")

        assert records["status"]["mx"] == "noanswer"

    def test_the_names_own_failure_never_falls_back(self, fake_dns):
        fake_dns.fail("www.example.com", "timeout", "MX")

        records = managers.DomainManager().get_records("www.example.com")

        assert records["status"]["mx"] == "timeout"
        mx_asked = [name for name, kind in fake_dns.queries if kind == "MX"]
        assert mx_asked == ["www.example.com"]


class TestSpfAndPtr:
    def test_spf_found_in_either_place_is_ok(self, fake_dns):
        fake_dns.fail("www.example.com", "timeout", "TXT")

        records = managers.DomainManager().get_records("www.example.com")

        assert records["status"]["txt"] == "timeout"
        assert records["status"]["spf"] == "ok"
        assert [s["text"] for s in records["spf"]] == ["v=spf1 -all"]

    def test_no_spf_and_a_failed_query_is_that_failure(self, fake_dns):
        fake_dns.fail("www.example.com", "servfail", "TXT")
        fake_dns.fail("example.com", "noanswer", "TXT")

        records = managers.DomainManager().get_records("www.example.com")

        assert records["spf"] == []
        assert records["status"]["spf"] == "servfail"

    def test_no_spf_anywhere_is_noanswer(self, fake_dns):
        fake_dns.fail("www.example.com", "noanswer", "TXT")
        fake_dns.fail("example.com", "noanswer", "TXT")

        records = managers.DomainManager().get_records("www.example.com")

        assert records["status"]["spf"] == "noanswer"

    def test_ptr_failure_is_reported(self, fake_dns):
        fake_dns.fail("34.216.184.93.in-addr.arpa", "timeout", "PTR")

        records = managers.DomainManager().get_records(
            "example.com", ip="93.184.216.34"
        )

        assert records["ptr"] == []
        assert records["status"]["ptr"] == "timeout"

    def test_ptr_with_no_address_to_reverse_takes_the_a_status(self, fake_dns):
        """No caller IP and no A record: there was no PTR question to ask, so
        the PTR row is only as known as the A query that would have supplied
        the address."""
        fake_dns.fail("example.com", "timeout", "A")

        records = managers.DomainManager().get_records("example.com")

        assert records["ptr"] == []
        assert records["status"]["ptr"] == "timeout"


DMARC_TEXT = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"


def _dmarc_asked(fake):
    """The _dmarc names asked, in the order asked."""
    return [name for name, kind in fake.queries if name.startswith("_dmarc.")]


class TestDmarc:
    """The DMARC policy record: one TXT query at _dmarc.<name>, made only when
    the caller asks for it, filtered to v=DMARC1 and given a status of its own
    like every other type."""

    def test_the_record_comes_back_with_the_name_that_answered(self, fake_dns):
        records = managers.DomainManager().get_records("example.com", dmarc=True)

        assert records["dmarc"] == [
            {"text": DMARC_TEXT, "ttl": 300, "queried_name": "_dmarc.example.com"}
        ]
        assert records["status"]["dmarc"] == "ok"

    def test_the_sweep_asks_nothing_unless_told(self, fake_dns):
        """The self page sweeps the visitor's PTR name with get_records(), and
        the visitor's own address gets no query it did not get before."""
        records = managers.DomainManager().get_records(
            "example.com", ip="93.184.216.34"
        )

        assert "dmarc" not in records
        assert "dmarc" not in records["status"]
        assert _dmarc_asked(fake_dns) == []

    @pytest.mark.parametrize("outcome", OUTCOMES)
    def test_each_outcome_is_the_dmarc_status(self, fake_dns, outcome):
        fake_dns.fail("_dmarc.example.com", outcome, "TXT")

        records = managers.DomainManager().get_records("example.com", dmarc=True)

        assert records["dmarc"] == []
        assert records["status"]["dmarc"] == outcome

    def test_a_txt_that_is_not_dmarc_is_no_record(self, fake_dns):
        fake_dns.records["_dmarc.example.com", "TXT"] = ['"verification=abc123"']

        records = managers.DomainManager().get_records("example.com", dmarc=True)

        assert records["dmarc"] == []
        assert records["status"]["dmarc"] == "noanswer"

    def test_the_version_tag_is_read_leniently(self, fake_dns):
        fake_dns.records["_dmarc.example.com", "TXT"] = ['" V = DMARC1 ;p=reject"']

        records = managers.DomainManager().get_records("example.com", dmarc=True)

        assert [r["text"] for r in records["dmarc"]] == [" V = DMARC1 ;p=reject"]

    def test_the_version_value_must_be_exact(self, fake_dns):
        """RFC 7489 §6.3: DMARC1 must match precisely or a receiver ignores the
        record, so it must not be shown as the policy in force."""
        fake_dns.records["_dmarc.example.com", "TXT"] = ['"v=dmarc1; p=reject"']

        records = managers.DomainManager().get_records("example.com", dmarc=True)

        assert records["dmarc"] == []
        assert records["status"]["dmarc"] == "noanswer"

    def test_a_record_over_255_bytes_is_joined_without_a_separator(self, fake_dns):
        head = "v=DMARC1; p=reject; rua=mailto:dmarc-reports@exam"
        fake_dns.records["_dmarc.example.com", "TXT"] = [f'"{head}" "ple.com"']

        records = managers.DomainManager().get_records("example.com", dmarc=True)

        assert records["dmarc"][0]["text"] == head + "ple.com"

    def test_two_records_are_both_kept(self, fake_dns):
        """RFC 7489 ends policy discovery when a name has two: both are shown,
        and neither is passed off as the one in force."""
        fake_dns.records["_dmarc.example.com", "TXT"] = [
            '"v=DMARC1; p=none"',
            '"v=DMARC1; p=reject"',
        ]

        records = managers.DomainManager().get_records("example.com", dmarc=True)

        assert sorted(r["text"] for r in records["dmarc"]) == [
            "v=DMARC1; p=none",
            "v=DMARC1; p=reject",
        ]
        assert records["status"]["dmarc"] == "ok"


class TestDmarcDiscovery:
    """RFC 7489 §6.6.3: _dmarc.<name> first, and only when that holds no policy
    record, _dmarc.<registrable domain>, once. A failed query is not "no
    record", so it ends the search."""

    def test_a_name_without_its_own_record_gets_its_registrable_domains(self, fake_dns):
        records = managers.DomainManager().get_records("www.example.com", dmarc=True)

        assert _dmarc_asked(fake_dns) == [
            "_dmarc.www.example.com",
            "_dmarc.example.com",
        ]
        assert records["dmarc"] == [
            {"text": DMARC_TEXT, "ttl": 300, "queried_name": "_dmarc.example.com"}
        ]
        assert records["status"]["dmarc"] == "ok"

    def test_a_name_with_its_own_record_keeps_it(self, fake_dns):
        fake_dns.records["_dmarc.www.example.com", "TXT"] = ['"v=DMARC1; p=reject"']

        records = managers.DomainManager().get_records("www.example.com", dmarc=True)

        assert _dmarc_asked(fake_dns) == ["_dmarc.www.example.com"]
        assert records["dmarc"][0]["queried_name"] == "_dmarc.www.example.com"

    def test_a_txt_that_is_not_dmarc_sends_the_search_up(self, fake_dns):
        fake_dns.records["_dmarc.www.example.com", "TXT"] = ['"verification=abc123"']

        records = managers.DomainManager().get_records("www.example.com", dmarc=True)

        assert records["dmarc"][0]["queried_name"] == "_dmarc.example.com"

    @pytest.mark.parametrize("outcome", ["timeout", "servfail"])
    def test_a_failed_first_query_does_not_fall_back(self, fake_dns, outcome):
        fake_dns.fail("_dmarc.www.example.com", outcome, "TXT")

        records = managers.DomainManager().get_records("www.example.com", dmarc=True)

        assert _dmarc_asked(fake_dns) == ["_dmarc.www.example.com"]
        assert records["dmarc"] == []
        assert records["status"]["dmarc"] == outcome

    @pytest.mark.parametrize("outcome", ["timeout", "servfail"])
    def test_a_failed_fallback_is_the_rows_status(self, fake_dns, outcome):
        """The name said "no record here", which sends the row to the
        registrable domain; that query never answered, so the policy is
        unknown, not absent."""
        fake_dns.fail("_dmarc.example.com", outcome, "TXT")

        records = managers.DomainManager().get_records("www.example.com", dmarc=True)

        assert records["dmarc"] == []
        assert records["status"]["dmarc"] == outcome

    def test_neither_having_a_record_is_the_fallbacks_answer(self, fake_dns):
        fake_dns.fail("_dmarc.example.com", "nxdomain", "TXT")

        records = managers.DomainManager().get_records("www.example.com", dmarc=True)

        assert records["dmarc"] == []
        assert records["status"]["dmarc"] == "nxdomain"

    def test_the_registrable_domain_itself_is_asked_once(self, fake_dns):
        fake_dns.fail("_dmarc.example.com", "noanswer", "TXT")

        managers.DomainManager().get_records("example.com", dmarc=True)

        assert _dmarc_asked(fake_dns) == ["_dmarc.example.com"]

    def test_two_records_at_the_name_end_the_search(self, fake_dns):
        """Two policy records at the name end discovery there (RFC 7489
        §6.6.3): both are kept for the page to count, and the registrable
        domain's record is not asked for in their place."""
        fake_dns.records["_dmarc.www.example.com", "TXT"] = [
            '"v=DMARC1; p=none"',
            '"v=DMARC1; p=reject"',
        ]

        records = managers.DomainManager().get_records("www.example.com", dmarc=True)

        assert _dmarc_asked(fake_dns) == ["_dmarc.www.example.com"]
        assert [r["queried_name"] for r in records["dmarc"]] == [
            "_dmarc.www.example.com",
            "_dmarc.www.example.com",
        ]
        assert records["status"]["dmarc"] == "ok"

    def test_a_name_with_no_public_suffix_asks_only_its_own(self, fake_dns):
        """registrable_domain() is None for a name under no public suffix:
        there is no Organizational Domain to fall back to, and no
        "_dmarc.None" to ask."""
        records = managers.DomainManager().get_records(
            "host.example.invalid", dmarc=True
        )

        assert _dmarc_asked(fake_dns) == ["_dmarc.host.example.invalid"]
        assert records["dmarc"] == []
        assert records["status"]["dmarc"] == "noanswer"


class _AllAtOnce(FakeResolver):
    """Holds the sweep's first `parties` queries until all of them are in
    flight together. With fewer workers than fetchers one is left queued, the
    barrier times out, and the held queries fail."""

    def __init__(self, records, parties):
        super().__init__(records)
        self.barrier = threading.Barrier(parties, timeout=5)
        self.arrived = 0
        self.lock = threading.Lock()

    def resolve(self, qname, rdtype="A", *args, **kwargs):
        kind = dns.rdatatype.to_text(dns.rdatatype.RdataType.make(rdtype))
        hold = False
        if kind != "SOA":
            with self.lock:
                self.arrived += 1
                hold = self.arrived <= self.barrier.parties
        if hold:
            self.barrier.wait()
        return super().resolve(qname, rdtype, *args, **kwargs)


def test_every_fetcher_gets_a_worker_of_its_own(monkeypatch):
    """A name below its zone, with an address, has nine fetchers: NS, A,
    AAAA, MX, CNAME, TXT, the zone's TXT, PTR and DMARC. Each runs at once, so
    the DMARC query costs no extra round of waiting."""
    fake = _AllAtOnce(dict(RECORDS), parties=9)
    monkeypatch.setattr(managers, "_recursive_resolver", lambda: fake)

    records = managers.DomainManager().get_records(
        "www.example.com", ip="93.184.216.34", dmarc=True
    )

    assert "error" not in records["status"].values()
    assert records["status"]["dmarc"] == "ok"


# --- gather ----------------------------------------------------------------


@pytest.mark.parametrize("outcome", OUTCOMES)
async def test_gather_reports_why_the_target_has_no_address(offline, outcome):
    offline.fail("example.com", outcome, "A")

    data = await lookup.gather("example.com")

    assert data["resolved_ip"] is None
    assert data["resolution"] == outcome


async def test_gather_resolution_for_a_name_and_an_ip_literal(offline):
    by_name = await lookup.gather("example.com")
    assert by_name["resolved_ip"] == "93.184.216.34"
    assert by_name["resolution"] == "ok"

    literal = await lookup.gather("93.184.216.34")
    assert literal["resolved_ip"] == "93.184.216.34"
    assert literal["resolution"] == "literal"


# --- HTTP: JSON and page ---------------------------------------------------

JSON_UA = {"user-agent": "curl/8.0"}
BROWSER_UA = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
    )
}
client = TestClient(app, client=("118.235.14.201", 41234))


@pytest.mark.parametrize("outcome", OUTCOMES)
def test_json_carries_each_types_status(offline, outcome):
    offline.fail("example.com", outcome, "MX")

    body = client.get("/example.com", headers=JSON_UA).json()

    assert body["domain"]["mx"] == []
    assert body["domain"]["status"]["mx"] == outcome
    assert body["resolved_ip"] == "93.184.216.34"
    assert body["resolution"] == "ok"


@pytest.mark.parametrize("outcome", OUTCOMES)
def test_json_carries_resolved_ip_and_resolution(offline, outcome):
    offline.fail("example.com", outcome, "A")

    body = client.get("/example.com", headers=JSON_UA).json()

    assert body["resolved_ip"] is None
    assert body["resolution"] == outcome


def _dns_table_row(html: str, rdtype: str) -> list[str]:
    table = re.search(r'<table class="records records--dns">.*?</table>', html, re.S)
    assert table, "no DNS table"
    row = re.search(rf"<tr>\s*<td>{rdtype}</td>.*?</tr>", table.group(0), re.S)
    assert row, f"no {rdtype} row in the DNS table"
    # Each cell's text: a value that is a lookup target is wrapped in its link
    # (tests/test_page.py::TestLookupLinks pins that markup), and this file is
    # about what the cells say.
    return [
        re.sub(r"<[^>]+>", "", c).strip()
        for c in re.findall(r"<td[^>]*>(.*?)</td>", row.group(0), re.S)
    ]


def _facts_value(html: str, label: str) -> str:
    match = re.search(
        rf'<span class="kv-label">{label}</span>\s*'
        r'<span class="kv-value tone-(\w+)">(.*?)</span>',
        html,
        re.S,
    )
    assert match, f"no {label} fact"
    return match.group(1), match.group(2).strip()


@pytest.mark.parametrize(
    "outcome, text", [("timeout", "(timed out)"), ("servfail", "(server failure)")]
)
def test_page_says_a_type_failed_instead_of_dashing_it(offline, outcome, text):
    offline.fail("example.com", outcome, "MX")

    html = client.get("/example.com", headers=BROWSER_UA).text

    assert _dns_table_row(html, "MX") == ["MX", "example.com", text, ""]
    assert _facts_value(html, "MX") == ("warning", text)
    # The types that did answer are untouched.
    assert _dns_table_row(html, "A")[2] == "93.184.216.34"
    assert "does not resolve" not in html


def test_page_keeps_the_dash_for_a_type_that_has_no_records(offline):
    offline.fail("example.com", "noanswer", "MX")

    html = client.get("/example.com", headers=BROWSER_UA).text

    assert _facts_value(html, "MX") == ("default", viewmodel.DASH)
    assert "<td>MX</td>" not in html
    for text in viewmodel.DNS_FAILURE_TEXT.values():
        assert text not in html
    assert "does not resolve" not in html


def test_page_banners_a_name_that_does_not_exist(offline):
    offline.fail("nosuch.example.com", "nxdomain")

    html = client.get("/nosuch.example.com", headers=BROWSER_UA).text

    banner = re.search(r'<p class="dns-banner"[^>]*>(.*?)</p>', html, re.S)
    assert banner, "no NXDOMAIN banner"
    assert banner.group(1).strip() == "nosuch.example.com does not resolve (NXDOMAIN)"
    # A name that does not exist has no records; it did not fail to fetch them.
    for text in viewmodel.DNS_FAILURE_TEXT.values():
        assert text not in html


def test_four_outcomes_render_four_different_pages(offline):
    marks = {}
    for outcome in OUTCOMES:
        offline.outcomes.clear()
        offline.missing.clear()
        if outcome == "nxdomain":
            offline.fail("example.com", "nxdomain")
        else:
            offline.fail("example.com", outcome, "MX")
        html = client.get("/example.com", headers=BROWSER_UA).text
        marks[outcome] = (
            "(timed out)" in html,
            "(server failure)" in html,
            "does not resolve (NXDOMAIN)" in html,
        )
    assert marks == {
        "timeout": (True, False, False),
        "servfail": (False, True, False),
        "nxdomain": (False, False, True),
        "noanswer": (False, False, False),
    }


# --- MCP ---------------------------------------------------------------------


@pytest.mark.parametrize("outcome", ["timeout", "servfail", "error"])
async def test_mcp_marks_a_failed_type_as_an_error(offline, outcome):
    offline.fail("example.com", outcome, "MX")

    payload = await mcp_server.dns_records("example.com")

    assert payload["records"]["mx"] == {"error": outcome}
    assert payload["records"]["a"] == [{"ip": "93.184.216.34", "ttl": 300}]
    assert payload["resolution"] == "ok"


async def test_mcp_keeps_an_empty_answer_empty(offline):
    offline.fail("example.com", "noanswer", "MX")

    payload = await mcp_server.dns_records("example.com", types=["mx", "cname"])

    assert payload["records"] == {"mx": [], "cname": None}


async def test_mcp_says_a_name_does_not_exist(offline):
    offline.fail("nosuch.example.com", "nxdomain")

    payload = await mcp_server.dns_records("nosuch.example.com")

    assert payload["resolved_ip"] is None
    assert payload["resolution"] == "nxdomain"
    assert payload["records"]["a"] == []
    assert payload["records"]["mx"] == []


async def test_mcp_four_outcomes_are_four_answers(offline):
    answers = {}
    for outcome in OUTCOMES:
        offline.outcomes.clear()
        offline.missing.clear()
        if outcome == "nxdomain":
            offline.fail("example.com", "nxdomain")
        else:
            offline.fail("example.com", outcome, "MX")
        payload = await mcp_server.dns_records("example.com", types=["mx"])
        answers[outcome] = (payload["records"]["mx"], payload["resolution"])
    assert answers == {
        "timeout": ({"error": "timeout"}, "ok"),
        "servfail": ({"error": "servfail"}, "ok"),
        "nxdomain": ([], "nxdomain"),
        "noanswer": ([], "ok"),
    }
