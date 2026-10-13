"""The security leg: gather() grades a domain's DNS security beside the sweep,
and only a domain's."""

import pytest
from fastapi.testclient import TestClient

import dnssecurity
import lookup
from main import app

client = TestClient(app)

GRADED = {
    c: {"state": "pass", "summary": c, "findings": []} for c in dnssecurity.CHECKS
}


@pytest.fixture
def legs(monkeypatch):
    calls = []

    async def fake_whois(target):
        return {"error": "skipped"}

    monkeypatch.setattr(lookup, "lookup_whois", fake_whois)
    monkeypatch.setattr(
        lookup.SSLManager, "get_ssl_info", staticmethod(lambda *a: None)
    )
    monkeypatch.setattr(
        lookup.domain_manager,
        "get_records",
        lambda name, ip=None, dmarc=False: {
            "queried_name": name,
            "zone": name,
            "spf": [],
            "dmarc": [],
            "status": {},
        },
    )
    monkeypatch.setattr(lookup.domain_manager, "zone_apex", lambda name: name)

    def fake_fetch(name, zone, registrable):
        calls.append((name, zone, registrable))
        return {"dkim": {"keys": [], "status": "noanswer"}}

    monkeypatch.setattr(dnssecurity, "fetch", fake_fetch)
    return calls


def _resolve_to(monkeypatch, outcome):
    class R:
        def resolve(self, name, rdtype):
            if outcome == "ok":
                return ["93.184.216.34"]
            import dns.resolver

            raise {
                "nxdomain": dns.resolver.NXDOMAIN,
                "timeout": dns.resolver.LifetimeTimeout,
            }[outcome]()

    monkeypatch.setattr(lookup, "_recursive_resolver", lambda: R())


async def test_domain_lookup_carries_dns_security(monkeypatch, legs):
    _resolve_to(monkeypatch, "ok")
    data = await lookup.gather("example.com")
    assert tuple(data["dns_security"]) == dnssecurity.CHECKS
    assert legs == [("example.com", "example.com", "example.com")]


async def test_ip_lookup_has_none(monkeypatch, legs):
    monkeypatch.setattr(
        lookup.domain_manager, "perform_reverse_lookup", lambda ip: None
    )
    data = await lookup.gather("93.184.216.34")
    assert data["dns_security"] is None
    assert legs == []


async def test_nxdomain_has_no_dns_security(monkeypatch, legs):
    _resolve_to(monkeypatch, "nxdomain")
    data = await lookup.gather("nope.example.com")
    assert data["dns_security"] is None
    assert legs == []


async def test_legs_without_security_skip_it(monkeypatch, legs):
    _resolve_to(monkeypatch, "ok")
    data = await lookup.gather("example.com", legs={"resolve", "dns"})
    assert data["dns_security"] is None
    assert legs == []


async def test_security_leg_exception_is_unknown_not_500(monkeypatch, legs):
    _resolve_to(monkeypatch, "ok")

    def broken(*a):
        raise RuntimeError("bug")

    monkeypatch.setattr(dnssecurity, "fetch", broken)
    data = await lookup.gather("example.com")
    states = {c: v["state"] for c, v in data["dns_security"].items()}
    assert states["dkim"] == states["caa"] == states["dnssec"] == "unknown"
    assert states["spf"] == "fail"  # graded from the sweep, which ran


def test_json_route_carries_the_key(monkeypatch, legs):
    _resolve_to(monkeypatch, "ok")
    body = client.get("/example.com", headers={"Accept": "application/json"}).json()
    assert tuple(body["dns_security"]) == dnssecurity.CHECKS


def test_json_route_leaves_it_out_for_an_ip(monkeypatch, legs):
    monkeypatch.setattr(
        lookup.domain_manager, "perform_reverse_lookup", lambda ip: None
    )
    body = client.get("/93.184.216.34", headers={"Accept": "application/json"}).json()
    assert "dns_security" not in body
