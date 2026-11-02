"""viewmodel._sections, the page sections they render, and the keys build_view
adds for the blocks (rdns_row, ptr_row, org_rows)."""

import re

import pytest

import main
import overview
from test_viewmodel import ANSWER_4_NAMES, DOMAIN_RESPONSE, IP_RESPONSE
from viewmodel import build_view

DNS_SECURITY = {
    "spf": {"state": "pass", "summary": "SPF: -all", "findings": []},
    "dmarc": {"state": "warn", "summary": "DMARC: p=none", "findings": []},
}
REPUTATION = {
    "level": None,
    "score": None,
    "signals": [],
    "checked": [],
    "unavailable": [],
    "attribution": [],
}
AS_INFO = {
    "asn": 15169,
    "name": "GOOGLE",
    "country": "US",
    "source": "route",
    "announced": True,
    "attribution": [],
    "unavailable": [],
}


def _domain(**extra):
    return {
        **DOMAIN_RESPONSE,
        "dns_security": DNS_SECURITY,
        "reputation": REPUTATION,
        "as_info": AS_INFO,
        **extra,
    }


def _ip(**extra):
    return {
        **IP_RESPONSE,
        "reputation": REPUTATION,
        "reverse_ip": ANSWER_4_NAMES,
        **extra,
    }


def _ids(view):
    return [s["id"] for s in view["sections"]]


def _section(view, id):
    return next(s for s in view["sections"] if s["id"] == id)


def _names(section):
    return [b["name"] for b in section["blocks"]]


def test_domain_section_order():
    view = build_view(_domain(), is_self=False, subdomains_enabled=True)
    assert _ids(view) == [
        "whois",
        "dns",
        "security",
        "ssl",
        "network",
        "reputation",
        "subdomains",
        "raw",
    ]


def test_ip_section_order():
    view = build_view(_ip(), is_self=False, subdomains_enabled=True)
    assert _ids(view) == [
        "location",
        "organization",
        "domains",
        "reputation",
        "whois",
        "raw",
    ]


def test_self_section_order():
    view = build_view(_ip(), is_self=True, subdomains_enabled=True)
    assert _ids(view) == [
        "location",
        "organization",
        "domains",
        "reputation",
        "whois",
        "browser",
        "raw",
    ]
    assert _names(_section(view, "browser")) == ["fingerprint", "headers"]
    assert _section(view, "browser")["blocks"][1]["heading"] == (
        "Headers your browser sent"
    )


def test_ip_pages_have_no_ssl_or_headers_section():
    view = build_view(_ip(), is_self=False, subdomains_enabled=True)
    assert "ssl" not in _ids(view)
    assert "headers" not in _ids(view)
    assert "browser" not in _ids(view)


def test_network_blocks():
    network = _section(
        build_view(_domain(), is_self=False, subdomains_enabled=True), "network"
    )
    assert network["blocks"] == [
        {"name": "geoip", "heading": "Location"},
        {"name": "as", "heading": "Autonomous system"},
    ]
    assert (
        network["hint"]
        == build_view(_domain(), is_self=False, subdomains_enabled=True)["as_info"][
            "hint"
        ]
    )


def test_network_without_an_as_card_is_the_location_alone():
    view = build_view(_domain(as_info=None), is_self=False, subdomains_enabled=True)
    assert _names(_section(view, "network")) == ["geoip"]


def test_organization_falls_back_to_org():
    view = build_view(_ip(), is_self=False, subdomains_enabled=True)
    organization = _section(view, "organization")
    assert _names(organization) == ["org"]
    assert organization["hint"] == "Google LLC"
    with_as = build_view(_ip(as_info=AS_INFO), is_self=False, subdomains_enabled=True)
    assert _names(_section(with_as, "organization")) == ["as"]


def test_domains_blocks_with_ptr():
    domains = _section(
        build_view(_ip(), is_self=False, subdomains_enabled=True), "domains"
    )
    assert domains["blocks"] == [
        {"name": "ptr", "heading": "Reverse DNS"},
        {"name": "reverseip", "heading": "Listed names"},
        {"name": "dns", "heading": "Records for dns.google."},
    ]
    assert domains["hint"].startswith("dns.google. · ")


def test_domains_blocks_without_ptr():
    response = _ip()
    response["location"] = {**response["location"], "reverse_dns": None}
    domains = _section(
        build_view(response, is_self=False, subdomains_enabled=True), "domains"
    )
    assert _names(domains) == ["ptr", "reverseip"]
    assert domains["hint"].startswith("no PTR · ")


def test_request_group():
    view = build_view(_domain(), is_self=False, subdomains_enabled=True)
    groups = {s["id"]: s["group"] for s in view["sections"]}
    assert groups["subdomains"] == "request"
    assert groups["raw"] == "request"
    assert groups["whois"] == "main"
    assert _section(view, "subdomains")["hint"] == "on request"
    off = build_view(_domain(), is_self=False, subdomains_enabled=False)
    assert "subdomains" not in _ids(off)


def test_rdns_row_domain_only():
    domain = build_view(_domain(), is_self=False, subdomains_enabled=True)
    assert domain["rdns_row"]["label"] == "rDNS"
    ip = build_view(_ip(), is_self=False, subdomains_enabled=True)
    assert ip["rdns_row"] is None


@pytest.mark.parametrize("kind", ["domain", "ip", "self"])
def test_blocks_never_hold_a_section(kind):
    response = _domain() if kind == "domain" else _ip()
    view = build_view(response, is_self=kind == "self", subdomains_enabled=True)
    summary = overview.build(response)
    html = main.templates.env.get_template("browser.html").render(
        view=view,
        overview=summary,
        section_states={
            s["id"]: overview.section_state(s["id"], summary["states"])
            for s in view["sections"]
        },
        view_map=False,
        mcp_tools=[],
        stun_url="",
        stun_host="",
        api_base="",
        site_domain="example.test",
        dns_rows=[],
        headers=response.get("headers") or {},
        whois={},
        json_data="{}",
        map_data="null",
        nonce="",
    )
    found = re.findall(r'id="sec-[^"]+".*?</section>', html, flags=re.S)
    assert [re.match(r'id="sec-([^"]+)"', f).group(1) for f in found] == _ids(view)
    for body in found:
        assert "<section" not in body[len('id="sec-') :].split(">", 1)[1]
