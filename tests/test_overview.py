"""overview.py: the status cards, decided from the response dict."""

import ast
import datetime
import pathlib

import pytest

import dnssecurity
import managers
import overview
from overview import DKIM_NOT_FOUND, build, domain_cards, security_card, sentence

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


# review chips

from overview import review_chips, reputation_chips  # noqa: E402


def _texts(chips):
    return [(c["text"], c["tone"], c["section"]) for c in chips]


def test_nasa_chips():
    chips = review_chips(_nasa(), is_ip=False)
    assert _texts(chips) == [
        ("DKIM: found at selector1 (1024-bit)", "warning", "security"),
        ("CAA: none", "warning", "security"),
    ]


def test_fail_check_is_a_danger_chip():
    response = _nasa()
    response["dns_security"] = _security(spf=_check("fail", "SPF: none"))
    assert _texts(review_chips(response, False)) == [
        ("SPF: none", "danger", "security")
    ]


def test_unconfirmed_ptr_is_no_chip():
    response = _ip_response()
    response["domain"] = {"a": [{"ip": "10.0.0.1"}], "status": {"a": "ok"}}
    assert review_chips(response, is_ip=True) == []


def test_failed_query_is_no_chip():
    response = _nasa()
    response["domain"]["status"]["a"] = "timeout"
    response["dns_security"] = _security(caa=_check("unknown", "CAA: query failed"))
    assert review_chips(response, False) == []


def test_dkim_not_found_is_no_chip():
    response = _nasa()
    response["dns_security"] = _security(dkim=_check("unknown", DKIM_NOT_FOUND))
    assert review_chips(response, False) == []


def test_info_checks_are_no_chip():
    response = _nasa()
    response["dns_security"] = _security(bimi=_check("info", "BIMI: absent"))
    assert review_chips(response, False) == []


def _clean():
    """nasa.gov with every check passing, so a test sees only its own chip."""
    return {**_nasa(), "dns_security": _security()}


def test_expired_certificate_chip():
    response = _clean()
    response["ssl"] = _cert(-3)
    assert _texts(review_chips(response, False)) == [("TLS expired", "danger", "ssl")]


def test_expiring_certificate_chip():
    response = _clean()
    response["ssl"] = _cert(5)
    assert _texts(review_chips(response, False)) == [
        ("certificate: 5d left", "warning", "ssl")
    ]


def test_young_domain_chip():
    response = _clean()
    response["whois"]["created"] = _ago(6).isoformat()
    assert _texts(review_chips(response, False)) == [
        ("registered 6 days ago", "warning", "whois")
    ]


def test_epp_danger_chip():
    response = _clean()
    response["whois"]["status"] = ["clientHold"]
    assert _texts(review_chips(response, False)) == [("clientHold", "danger", "whois")]


def test_chips_follow_section_order():
    response = _nasa()
    response["ssl"] = _cert(-3)
    response["whois"]["created"] = _ago(2).isoformat()
    sections = [c["section"] for c in review_chips(response, False)]
    assert sections == ["whois", "security", "security", "ssl"]


def test_reputation_chip():
    reputation = {
        "level": "medium",
        "signals": [{"label": "Tor exit", "weight": 40}],
    }
    assert _texts(reputation_chips(reputation, is_ip=True)) == [
        ("on Tor exit", "warning", "reputation")
    ]
    response = _nasa()
    response["reputation"] = reputation
    assert _texts(review_chips(response, False)) == [
        ("DKIM: found at selector1 (1024-bit)", "warning", "security"),
        ("CAA: none", "warning", "security"),
        ("on Tor exit", "warning", "reputation"),
    ]


def test_informational_signal_on_a_domain_is_no_chip():
    reputation = {
        "level": "low",
        "signals": [{"label": "Datacenter", "weight": 0}],
    }
    assert reputation_chips(reputation, is_ip=False) == []
    # on an IP it is kept
    assert _texts(reputation_chips(reputation, is_ip=True)) == [
        ("on Datacenter", "warning", "reputation")
    ]


def test_reputation_levels_and_gaps():
    sig = [{"label": "Spamhaus DROP", "weight": 90, "score": None}]
    high = reputation_chips({"level": "high", "signals": sig}, True)
    assert high[0]["tone"] == "danger"
    assert reputation_chips({"level": "none", "signals": []}, True) == []
    assert reputation_chips({"level": None, "signals": []}, True) == []
    assert reputation_chips(None, True) == []
    abuse = [{"label": "AbuseIPDB", "weight": 30, "score": 87}]
    assert reputation_chips({"level": "low", "signals": abuse}, True)[0]["text"] == (
        "on AbuseIPDB 87%"
    )


def test_rpki_invalid_chip_section_by_kind():
    info = _as_info("invalid")
    info["route"]["origins"][0]["rpki"]["reason"] = "origin"
    domain = {**_nasa(), "as_info": info}
    assert _texts(review_chips(domain, False))[-1] == (
        "RPKI invalid (origin)",
        "danger",
        "network",
    )
    ip = _ip_response(as_info=info)
    assert _texts(review_chips(ip, True)) == [
        ("RPKI invalid (origin)", "danger", "organization")
    ]
    info["route"]["origins"][0]["rpki"].pop("reason")
    assert review_chips(_ip_response(as_info=info), True)[0]["text"] == "RPKI invalid"


def _page():
    """nasa.gov as the page sees it: the fixture plus what the sentence reads."""
    response = _nasa()
    response["address"] = "nasa.gov"
    response["resolved_ip"] = "192.0.66.108"
    response["location"] = {
        **response["location"],
        "country_code": "US",
        "country_name": "United States",
        "city_name": "San Francisco",
        "precision": "city",
    }
    return response


def _joined(segments):
    return "".join(s["text"] for s in segments)


def _strong(segments):
    return [s["text"] for s in segments if s["strong"]]


def test_nasa_sentence():
    segments = sentence(_page(), False)
    assert _joined(segments) == (
        "nasa.gov has been registered through get.gov for 29 years. "
        "It resolves to 192.0.66.108 at Automattic, Inc (AS2635) in San Francisco, "
        "serves a valid Let's Encrypt certificate with 69 days left, "
        "and passes 3 of 5 graded DNS security checks."
    )
    assert _strong(segments) == [
        "nasa.gov",
        "29 years",
        "192.0.66.108",
        "69 days",
        "3 of 5",
    ]
    tones = {s["text"]: s["tone"] for s in segments if s["strong"]}
    assert tones["3 of 5"] == "warning"
    assert tones["29 years"] is None


def test_dkim_dropped_fraction_and_clean_tone():
    response = _page()
    response["dns_security"] = _security(dkim=_check("pass", DKIM_NOT_FOUND))
    segments = sentence(response, False)
    assert "passes 4 of 4 graded DNS security checks" in _joined(segments)
    assert {s["text"]: s["tone"] for s in segments}["4 of 4"] is None


def test_sentence_drops_failed_whois():
    response = _page()
    response["whois"] = {"error": "RDAP timed out"}
    text = _joined(sentence(response, False))
    assert text.startswith("nasa.gov resolves to 192.0.66.108")
    assert "registered" not in text and "?" not in text


def test_sentence_drops_failed_tls():
    for ssl in (None, {"error": "port 443 unreachable", "reason": "timed out"}):
        response = _page()
        response["ssl"] = ssl
        text = _joined(sentence(response, False))
        assert "certificate" not in text
        assert text.endswith(
            "in San Francisco and passes 3 of 5 graded DNS security checks."
        )


def test_sentence_drops_unknown_security():
    response = _page()
    response["dns_security"] = None
    text = _joined(sentence(response, False))
    assert "security" not in text
    assert text.endswith("with 69 days left.")


def test_nxdomain_sentence():
    response = {
        "address": "nasa.example",
        "domain": {"queried_name": "nasa.example", "status": {"a": "nxdomain"}},
    }
    assert _joined(sentence(response, False)) == "nasa.example does not resolve."


def test_expired_certificate_wording():
    response = _page()
    response["ssl"] = _cert(-3)
    segments = sentence(response, False)
    assert "serves a certificate that is expired" in _joined(segments)
    assert "valid" not in _joined(segments)
    problem = next(s for s in segments if s["text"] == "expired")
    assert problem["tone"] == "danger"


def test_untrusted_certificate_wording():
    response = _page()
    response["ssl"] = _cert(30, trusted=False, verify_error={"reason": "self-signed"})
    text = _joined(sentence(response, False))
    assert "serves a certificate that is " in text
    assert "valid" not in text


def test_young_domain_age_is_a_warning():
    response = _page()
    response["whois"]["created"] = _ago(6).isoformat()
    segments = sentence(response, False)
    assert "for 6 days." in _joined(segments)
    assert next(s for s in segments if s["text"] == "6 days")["tone"] == "warning"


def test_ip_sentence():
    response = _ip_response(
        reverse_ip={"total": 24783},
        as_info={"asn": 4766, "name": "KIXS-AS-KR - Kakao Corp"},
    )
    response["location"]["country_name"] = "South Korea"
    segments = sentence(response, True)
    text = _joined(segments)
    assert text.startswith("121.53.204.130 is an address of ")
    assert text == (
        "121.53.204.130 is an address of Kakao Corp (AS4766) in Seoul, South Korea. "
        "Its reverse DNS name is ptr.example.net and 24,783 names on public top "
        "lists point to it."
    )
    assert segments[0]["text"] == "121.53.204.130" and segments[0]["strong"]


def test_ip_sentence_without_ptr():
    response = _ip_response(reverse_ip={"total": 3})
    del response["location"]["reverse_dns"]
    text = _joined(sentence(response, True))
    assert "reverse DNS" not in text
    assert text.endswith("3 names on public top lists point to it.")
    bare = _ip_response()
    del bare["location"]["reverse_dns"]
    plain = _joined(sentence(bare, True))
    assert plain.endswith("South Korea.") or plain.endswith("Seoul.")
    assert "reverse DNS" not in plain and "top lists" not in plain


def test_ip_sentence_with_ptr_only():
    text = _joined(sentence(_ip_response(), True))
    assert text.endswith("Its reverse DNS name is ptr.example.net.")


def test_ip_sentence_drops_the_ptr_root_dot():
    """A PTR answer ends with the root dot ("dns.google."); the sentence's own
    full stop follows the name, so the name is written without it."""
    response = _ip_response()
    response["location"]["reverse_dns"] = "ptr.example.net."
    text = _joined(sentence(response, True))
    assert text.endswith("Its reverse DNS name is ptr.example.net.")
    assert ".." not in text


def test_third_party_text_is_data():
    response = _page()
    response["whois"]["registrar"] = "<b>x</b>"
    segments = sentence(response, False)
    assert "registered through <b>x</b> for" in _joined(segments)
    assert all(s["text"] for s in segments)


def test_build_states_follow_cards():
    response = _page()
    built = build(response)
    assert set(built) == {"sentence", "chips", "cards", "states"}
    assert built["states"] == {c["id"]: c["state"] for c in built["cards"]}
    assert built["states"]["security"] == "warn"
    assert [c["text"] for c in built["chips"]] == [
        c["text"] for c in overview.review_chips(response, False)
    ]
    ip = build(_ip_response())
    assert list(ip["states"]) == [c["id"] for c in ip["cards"]]
    assert "location" in ip["states"]


def test_domain_place_is_the_city_alone_or_the_country():
    response = _page()
    assert "in San Francisco," in _joined(sentence(response, False))
    response["location"]["precision"] = "country"
    assert " in United States," in _joined(sentence(response, False))


def test_expiring_certificate_tone_follows_the_chip():
    response = _page()
    response["ssl"] = _cert(5)
    segments = sentence(response, False)
    assert next(s for s in segments if s["text"] == "5 days")["tone"] == "warning"


def test_section_state():
    """A section takes its card's state; one without a card is `request` when
    it holds nothing until asked, `info` otherwise."""
    states = build(_page())["states"]
    assert overview.section_state("security", states) == "warn"
    assert overview.section_state("whois", states) == "info"
    for sid in ("subdomains", "raw", "browser"):
        assert overview.section_state(sid, states) == "request"
    assert overview.section_state("domains", {}) == "info"
    assert overview.section_state("location", {"location": "unknown"}) == "unknown"
    assert all(
        overview.section_state(sid, states) in overview.STATES
        for sid in ("whois", "dns", "raw", "anything")
    )
