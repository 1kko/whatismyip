"""Every DNS query goes to the fixed public resolvers with one time budget.

The reverse lookup and gather()'s gating A query used to call dnspython's
module-level resolve(), i.e. the system resolver. In the container that is
Docker's 127.0.0.11 with a 5-second lifetime, and production logs showed it
timing out on PTR queries while the self page waited on the answer before
starting its DNS sweep. These tests pin both queries to the resolver that
_recursive_resolver() builds, and fail if anything reaches the default one.
"""

import logging
from types import SimpleNamespace

import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.reversename
import pytest

import lookup
import managers
from config import DNS_QUERY_LIFETIME, DNS_QUERY_TIMEOUT, PUBLIC_RESOLVERS


def _answer(qname, rdtype: str, value: str) -> dns.resolver.Answer:
    """A real dnspython Answer, so callers can index, iterate or read .rrset."""
    qname = dns.name.from_text(qname) if isinstance(qname, str) else qname
    response = dns.message.make_response(dns.message.make_query(qname, rdtype))
    rrset = response.find_rrset(
        response.answer,
        qname,
        dns.rdataclass.IN,
        dns.rdatatype.from_text(rdtype),
        create=True,
    )
    rrset.update_ttl(300)
    rrset.add(dns.rdata.from_text("IN", rdtype, value))
    return dns.resolver.Answer(
        qname, dns.rdatatype.from_text(rdtype), dns.rdataclass.IN, response
    )


@pytest.fixture
def public_only(monkeypatch):
    """Record every query a Resolver instance makes; forbid the module default.

    Resolver.resolve is patched at class level, so this sees the query whatever
    helper reached it (resolve_address included). The module-level resolve()
    and get_default_resolver() are the path to the system resolver; they record
    the call and raise, and the tests assert the record stays empty because
    the code under test swallows exceptions.
    """
    queries = []
    forbidden = []
    answers = {}

    def fake_resolve(self, qname, rdtype="A", *args, **kwargs):
        rdtype = dns.rdatatype.to_text(dns.rdatatype.RdataType.make(rdtype))
        queries.append(
            {
                "qname": str(qname),
                "rdtype": rdtype,
                "nameservers": [str(ns) for ns in self.nameservers],
                "timeout": self.timeout,
                "lifetime": self.lifetime,
                "lifetime_override": kwargs.get("lifetime"),
            }
        )
        result = answers[rdtype]
        if isinstance(result, BaseException):
            raise result
        return _answer(qname, rdtype, result)

    def default_resolve(*args, **kwargs):
        forbidden.append(("dns.resolver.resolve", args))
        raise AssertionError("module-level dns.resolver.resolve() was called")

    def default_resolver(*args, **kwargs):
        forbidden.append(("dns.resolver.get_default_resolver", args))
        raise AssertionError("dns.resolver.get_default_resolver() was called")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
    monkeypatch.setattr(dns.resolver, "resolve", default_resolve)
    monkeypatch.setattr(dns.resolver, "get_default_resolver", default_resolver)

    return SimpleNamespace(queries=queries, forbidden=forbidden, answers=answers)


def _name(exc: BaseException) -> str:
    return type(exc).__name__


def _assert_public(query):
    assert query["nameservers"] == list(PUBLIC_RESOLVERS)
    assert query["timeout"] == DNS_QUERY_TIMEOUT
    assert query["lifetime"] == DNS_QUERY_LIFETIME
    # Same time budget as every other query: no per-call lifetime override.
    assert query["lifetime_override"] is None


class TestReverseLookup:
    def test_ptr_goes_to_the_public_resolver(self, public_only):
        public_only.answers["PTR"] = "dns.google."
        hostname = managers.DomainManager().perform_reverse_lookup("8.8.8.8")

        assert public_only.forbidden == []
        assert hostname.rstrip(".") == "dns.google"
        (query,) = public_only.queries
        assert query["qname"] == str(dns.reversename.from_address("8.8.8.8"))
        assert query["rdtype"] == "PTR"
        _assert_public(query)

    @pytest.mark.parametrize(
        "miss", [dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()], ids=_name
    )
    def test_a_missing_ptr_record_is_not_a_warning(self, public_only, caplog, miss):
        """Most visitor IPs have no PTR record. That is an answer, not a
        failure, and logging it at WARNING buried the real ones."""
        public_only.answers["PTR"] = miss
        caplog.set_level(logging.DEBUG)

        assert managers.DomainManager().perform_reverse_lookup("8.8.8.8") is None

        assert public_only.forbidden == []
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert [r for r in caplog.records if r.levelno == logging.DEBUG]

    @pytest.mark.parametrize(
        "failure",
        [
            dns.resolver.LifetimeTimeout(timeout=DNS_QUERY_LIFETIME, errors=[]),
            dns.resolver.NoNameservers(),
        ],
        ids=_name,
    )
    def test_a_failed_ptr_query_still_warns(self, public_only, caplog, failure):
        """A timeout or SERVFAIL is the resolver failing, not the record
        missing; that stays visible."""
        public_only.answers["PTR"] = failure
        caplog.set_level(logging.DEBUG)

        assert managers.DomainManager().perform_reverse_lookup("8.8.8.8") is None

        assert public_only.forbidden == []
        assert [r for r in caplog.records if r.levelno == logging.WARNING]


async def test_gather_gating_a_query_goes_to_the_public_resolver(
    public_only, monkeypatch
):
    public_only.answers["A"] = "93.184.216.34"
    monkeypatch.setattr(lookup.domain_manager, "is_valid_domain", lambda d: True)
    monkeypatch.setattr(lookup.domain_manager, "get_records", lambda *a, **k: {})
    monkeypatch.setattr(lookup.SSLManager, "get_ssl_info", lambda *a, **k: None)
    monkeypatch.setattr(lookup.geo_ip_manager, "fetch_location", lambda ip: {"ip": ip})

    async def fake_whois(target):
        return {"source": "rdap", "name": target}

    monkeypatch.setattr(lookup, "lookup_whois", fake_whois)

    result = await lookup.gather("example.com")

    assert public_only.forbidden == []
    assert result["resolved_ip"] == "93.184.216.34"
    (query,) = public_only.queries
    assert query["qname"] == "example.com"
    assert query["rdtype"] == "A"
    _assert_public(query)
