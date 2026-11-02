"""overview.py: the status cards, decided from the response dict."""

import ast
import datetime
import pathlib

import pytest

import dnssecurity
import managers
import overview
from overview import DKIM_NOT_FOUND, domain_cards, security_card

UTC = datetime.timezone.utc


def _ago(days):
    return datetime.datetime.now(UTC) - datetime.timedelta(days=days)


def _cert(days_left, **over):
    expires = datetime.datetime.now(UTC) + datetime.timedelta(days=days_left, hours=12)
    cert = {
        "issuer": [[["organizationName", "Let's Encrypt"]]],
        "notAfter": expires.strftime("%b %d %H:%M:%S %Y GMT"),
        "trusted": True,
        "verify_error": None,
    }
    return {**cert, **over}


def _check(state, summary="x"):
    return {"state": state, "summary": summary, "findings": []}


def _security(**states):
    checks = {
        name: _check("pass") for name in ("spf", "dmarc", "dkim", "caa", "dnssec")
    }
    checks.update({name: _check("info") for name in ("mta_sts", "tls_rpt", "bimi")})
    checks.update(states)
    return checks


def _nasa():
    """nasa.gov as the real lookup answered, cut to what the cards read."""
    return {
        "whois": {
            "source": "rdap",
            "registrar": "get.gov",
            "status": ["server transfer prohibited"],
            "created": _ago(10700).isoformat(),
            "expires": "2027-07-31T14:55:32+00:00",
        },
        "domain": {
            "queried_name": "nasa.gov",
            "a": [{"ip": "192.0.66.108"}],
            "aaaa": [{"ip": "2a04:fa87:fffd::c000:426c"}],
            "mx": [{"host": "mx"}],
            "ns": [{"host": f"ns{i}"} for i in range(6)],
            "txt": [{"text": f"t{i}"} for i in range(22)],
            "status": {k: "ok" for k in ("a", "aaaa", "mx", "ns", "txt", "ptr")},
        },
        "dns_security": _security(
            dkim=_check("warn", "DKIM: found at selector1 (1024-bit)"),
            caa=_check("warn", "CAA: none"),
        ),
        "ssl": _cert(69),
        "location": {
            "country_code": "US",
            "asn_number": 2635,
            "asn_name": "Automattic",
        },
        "as_info": {
            "asn": 2635,
            "name": "AUTOMATTIC - Automattic, Inc",
            "announced": True,
            "route": {
                "prefix": "192.0.66.0/24",
                "origins": [{"asn": 2635, "rpki": {"state": "valid"}}],
            },
            "unavailable": [],
        },
        "reputation": {"level": "none", "score": 0},
    }


def test_nasa_cards():
    cards = domain_cards(_nasa())
    assert [c["id"] for c in cards] == [
        "whois",
        "dns",
        "security",
        "ssl",
        "network",
        "reputation",
    ]
    assert [c["value"] for c in cards] == [
        "29 years",
        "31 records",
        "3 / 5",
        "69d left",
        "AS2635",
        "0 / 100",
    ]
    assert [c["state"] for c in cards] == [
        "info",
        "pass",
        "warn",
        "pass",
        "pass",
        "info",
    ]
    assert all(c["href"] == f"#sec-{c['id']}" for c in cards)
    assert cards[0]["sub"] == "get.gov · expires 2027-07-31"
    assert cards[1]["sub"] == "A 1 · AAAA 1 · MX 1 · NS 6 · TXT 22"
    assert cards[3]["sub"] == "Let's Encrypt"


def test_one_year_reads_singular():
    card = overview.registration_card(
        {"registrar": "r", "created": _ago(400).isoformat()}, is_ip=False
    )
    assert card["value"] == "1 year"
    young = overview.registration_card(
        {"registrar": "r", "created": _ago(100).isoformat()}, is_ip=False
    )
    assert young["value"] == "100 days"


def test_dkim_not_found_is_left_out():
    card = security_card(_security(dkim=_check("unknown", DKIM_NOT_FOUND)))
    assert card["value"] == "4 / 4 · DKIM ?"
    assert card["state"] == "pass"
    assert card["sub"] == "graded checks pass"


def test_other_unknown_makes_the_card_unknown():
    card = security_card(_security(caa=_check("unknown", "CAA: lookup timed out")))
    assert card["state"] == "unknown"
    assert card["value"] == "4 / 4"
    assert card["sub"] == "some checks did not run"


def test_warn_beats_unknown():
    card = security_card(
        _security(caa=_check("unknown", "CAA: lookup timed out"), spf=_check("warn"))
    )
    assert card["state"] == "warn"
    assert card["sub"] == "1 to review"


def test_fail_is_danger():
    card = security_card(_security(spf=_check("fail"), caa=_check("warn")))
    assert card["state"] == "danger"
    assert card["sub"] == "2 to review"


def test_info_checks_are_not_counted():
    card = security_card(_security(caa=_check("info")))
    assert card["value"] == "4 / 4"


def test_raised_leg():
    checks = {
        name: _check("unknown", f"{name.upper()}: not checked")
        for name in dnssecurity.CHECKS
    }
    card = security_card(checks)
    assert (card["value"], card["sub"], card["state"]) == (
        "?",
        "not checked",
        "unknown",
    )


def test_no_dns_security_is_no_card():
    assert security_card(None) is None
    response = _nasa()
    del response["dns_security"]
    assert "security" not in [c["id"] for c in domain_cards(response)]


def test_nxdomain_dns_card():
    domain = {"queried_name": "x.test", "status": {"a": "nxdomain"}}
    card = overview.dns_card(domain)
    assert (card["value"], card["state"]) == ("does not exist", "danger")


def test_failed_query_dns_card_is_unknown():
    response = _nasa()
    response["domain"]["status"]["mx"] = "timeout"
    assert overview.dns_card(response["domain"])["state"] == "unknown"


def test_a_failed_ptr_alone_leaves_the_dns_card_pass():
    response = _nasa()
    response["domain"]["status"]["ptr"] = "timeout"
    assert overview.dns_card(response["domain"])["state"] == "pass"


def test_no_address_dns_card_is_info():
    response = _nasa()
    response["domain"]["status"].update(a="noanswer", aaaa="noanswer")
    assert overview.dns_card(response["domain"])["state"] == "info"


@pytest.mark.parametrize(
    "whois, value, state",
    [
        (
            {"registrar": "r", "created": _ago(900), "status": ["client hold"]},
            None,
            "danger",
        ),
        ({"registrar": "r", "created": _ago(6)}, "6 days", "warn"),
        ({"error": "not registered"}, "no record", "info"),
        ({"error": "timeout"}, "?", "unknown"),
        ({}, "?", "unknown"),
        ({"source": "whois", "name": "x.kr", "thin": True}, "no details", "info"),
        ({"pending": True}, "loading…", "pending"),
    ],
)
def test_registration_states(whois, value, state):
    card = overview.registration_card(whois, is_ip=False)
    assert card["state"] == state
    if value:
        assert card["value"] == value


@pytest.mark.parametrize(
    "ssl, value, state",
    [
        (None, "none", "info"),
        ({"error": "port 443 unreachable"}, "?", "unknown"),
        (_cert(-3), "expired", "danger"),
        (_cert(10), "10d left", "warn"),
        (
            _cert(60, trusted=False, verify_error={"reason": "self_signed"}),
            "self-signed",
            "danger",
        ),
    ],
)
def test_certificate_states(ssl, value, state):
    card = overview.certificate_card(ssl)
    assert (card["value"], card["state"]) == (value, state)


def test_unreachable_certificate_sub_is_the_error():
    card = overview.certificate_card({"error": "port 443 unreachable"})
    assert card["sub"] == "port 443 unreachable"


def _as_info(rpki, **over):
    info = {
        "asn": 2635,
        "name": "AUTOMATTIC - Automattic, Inc",
        "announced": True,
        "route": {"origins": [{"asn": 2635, "rpki": {"state": rpki}}]},
        "unavailable": [],
    }
    return {**info, **over}


def test_network_rpki_states():
    location = {"country_code": "US", "asn_number": 2635}
    state = lambda info: overview.network_card(location, info)["state"]  # noqa: E731
    assert state(_as_info("valid")) == "pass"
    assert state(_as_info("invalid")) == "danger"
    assert state(_as_info("not-found")) == "info"
    assert state(None) == "info"
    card = overview.network_card(location, _as_info(None, announced=False, route=None))
    assert (card["state"], card["sub"]) == ("info", "not announced")


def test_network_route_missing_with_ris_unavailable_is_unknown():
    info = _as_info(
        None, route=None, unavailable=[{"dataset": "ris_v4", "reason": "x"}]
    )
    assert overview.network_card({}, info)["state"] == "unknown"


def test_network_sub_and_custom_id():
    card = overview.network_card(
        {"country_code": "US"},
        _as_info("valid"),
        card_id="organization",
        label="Organization",
    )
    assert card["id"] == "organization"
    assert card["label"] == "Organization"
    assert card["href"] == "#sec-organization"
    assert card["sub"] == "Automattic, Inc · RPKI valid · US"


def test_network_without_any_asn():
    assert overview.network_card(None, None)["value"] == "—"


@pytest.mark.parametrize(
    "level, state",
    [
        ("none", "info"),
        ("low", "warn"),
        ("medium", "warn"),
        ("high", "danger"),
        (None, "unknown"),
    ],
)
def test_reputation_is_never_pass(level, state):
    card = overview.reputation_card(
        {"level": level, "score": None if level is None else 5}
    )
    assert card["state"] == state != "pass"


def test_missing_score_is_not_zero():
    assert overview.reputation_card({"level": None, "score": None})["value"] == "?"
    assert overview.reputation_card(None) is None


def test_dns_failures_match_managers():
    assert overview._DNS_FAILURES == set(managers.DNS_FAILURES)


def test_dkim_constant_matches_dnssecurity():
    raw = {
        "caa": {"records": [], "queried_name": None, "status": "noanswer"},
        "dnssec": {
            "zone": "x.test",
            "ds": "noanswer",
            "dnskey": "ok",
            "validated": False,
        },
        "dkim": {"keys": [], "status": "noanswer"},
    }
    assert dnssecurity.evaluate(None, raw)["dkim"]["summary"] == DKIM_NOT_FOUND


def test_overview_is_pure():
    tree = ast.parse((pathlib.Path(__file__).parent.parent / "overview.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert not imported & {"lookup", "main", "managers", "dnssecurity", "asinfo"}


def _ip_response(**over):
    response = {
        "address": "121.53.204.130",
        "location": {
            "country_code": "KR",
            "country_name": "South Korea",
            "city_name": "Seoul",
            "precision": "city",
            "accuracy_km": 20,
            "reverse_dns": "ptr.example.net",
            "asn_number": 4766,
        },
        "whois": {"source": "rdap", "network": "KORNET", "rir": "apnic"},
    }
    return {**response, **over}


def test_ip_cards_order():
    cards = overview.ip_cards(
        _ip_response(
            reputation={"score": 0, "level": "none"},
            reverse_ip={"total": 3},
        )
    )
    assert [c["id"] for c in cards] == [
        "location",
        "organization",
        "domains",
        "reputation",
        "whois",
    ]
    assert cards[1]["label"] == "Organization"


@pytest.mark.parametrize(
    "ptr, domain, reverse_ip, sub, state",
    [
        (
            "ptr.example.net",
            {"a": [{"ip": "121.53.204.130"}]},
            {"total": 24783},
            "confirmed · 24,783 listed names",
            "info",
        ),
        (None, None, {"total": None}, "listed names unknown", "unknown"),
        (None, None, None, "", "info"),
        (
            "ptr.example.net",
            {"a": [{"ip": "10.9.9.9"}]},
            None,
            "does not point back",
            "info",
        ),
    ],
)
def test_domains_card(ptr, domain, reverse_ip, sub, state):
    location = {"reverse_dns": ptr}
    card = overview.domains_card(location, domain, reverse_ip, "121.53.204.130")
    assert card["id"] == "domains"
    assert card["value"] == (ptr or "no PTR")
    assert (card["sub"], card["state"]) == (sub, state)


def test_location_country_level():
    card = overview.location_card(
        {"country_code": "KR", "country_name": "South Korea", "precision": "country"}
    )
    assert (card["value"], card["sub"], card["state"]) == (
        "South Korea",
        "country-level",
        "info",
    )


def test_location_city_and_unknown():
    card = overview.location_card(_ip_response()["location"])
    assert (card["value"], card["sub"]) == ("Seoul", "South Korea · ±20 km")
    assert overview.location_card({"country_code": "--"})["state"] == "unknown"
    assert overview.location_card(None)["state"] == "unknown"


def test_pending_registration_card():
    card = overview.registration_card({"pending": True}, is_ip=True)
    assert (card["label"], card["value"], card["sub"], card["state"]) == (
        "Registration",
        "loading…",
        "",
        "pending",
    )


def test_ip_registration_card():
    card = overview.registration_card(
        {"network": "KORNET", "rir": "apnic", "updated": "2020-01-02T00:00:00+00:00"},
        is_ip=True,
    )
    assert card["value"] == "KORNET"
    assert card["sub"].startswith("APNIC")
    assert card["state"] == "info"
    assert overview.registration_card({"source": "rdap"}, is_ip=True)["value"] == (
        "record found"
    )


def test_organization_without_asinfo():
    card = overview.ip_cards(_ip_response())[1]
    assert (card["value"], card["state"]) == ("AS4766", "info")
