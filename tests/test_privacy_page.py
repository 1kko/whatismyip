"""/privacy: what this service records, for how long, and who else is contacted.

The server logs every lookup's client address and target, ships logs to an
observability backend, and the page's browser fetches map tiles from
OpenStreetMap and, on request, asks a STUN server. None of that was written
down anywhere a visitor could read it. /privacy now is, every page links it
from the footer, and every page and lookup answer carries
`Link: </privacy>; rel="privacy-policy"` (RFC 6903) for clients that never
render the footer.

/privacy is a fixed page, not a lookup: like /robots.txt it is answered by its
own route ahead of the /{domain_ip} catch-all and stays out of the lookup
rate limit. Every lookup is mocked; nothing here touches the network.
"""

import contextlib
import copy
import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import config
import main
from main import app, ip_ban_manager, rate_limiter
from security import SuspiciousPatternDetector, WhitelistManager

VISITOR_IP = "118.235.14.201"
client = TestClient(app, client=(VISITOR_IP, 41234))
# Peer 127.0.0.1 is in TRUSTED_PROXIES, so x-real-ip picks the client address.
proxy_client = TestClient(app, client=("127.0.0.1", 41234))

CHROME = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}
CURL = {"user-agent": "curl/8.7.1"}
PRIVACY_LINK = '</privacy>; rel="privacy-policy"'

VISITOR_LOCATION = {
    "ip": VISITOR_IP,
    "country_code": "KR",
    "country_name": "South Korea",
    "city_name": "Seoul",
    "cidr": "118.235.0.0/16",
    "asn_name": "Korea Telecom",
    "is_private": False,
}
NASA = {
    "address": "nasa.gov",
    "domain": {"a": [{"ip": "192.0.66.108", "ttl": 300}], "mx": [], "ns": []},
    "location": {**VISITOR_LOCATION, "ip": "192.0.66.108", "country_code": "US"},
    "whois": {"source": "rdap", "registrar": "Example Registrar"},
    "ssl": None,
    "resolved_ip": "192.0.66.108",
    "reverse_dns": None,
}


@pytest.fixture(autouse=True)
def lookups():
    """Every entry point into the lookup pipeline, mocked, so a test can tell
    whether one ran; geo-blocking pinned open so a GEO_RULES_FILE left by
    another run cannot 403 a request."""
    allowed = {"allowed": True, "country": "KR", "region": None, "reason": "test"}
    mocks = {
        "gather": AsyncMock(side_effect=lambda *_, **__: copy.deepcopy(NASA)),
        "lookup_whois": AsyncMock(return_value={"source": "rdap", "name": "KT"}),
        "lookup_location": AsyncMock(side_effect=lambda *_: dict(VISITOR_LOCATION)),
        "perform_reverse_lookup": MagicMock(return_value=None),
    }
    with contextlib.ExitStack() as stack:
        stack.enter_context(
            patch("main.geo_block_manager.check_access", return_value=allowed)
        )
        for name in ("gather", "lookup_whois", "lookup_location"):
            stack.enter_context(patch(f"main.{name}", mocks[name]))
        stack.enter_context(
            patch(
                "main.domain_manager.perform_reverse_lookup",
                mocks["perform_reverse_lookup"],
            )
        )
        yield mocks
    # conftest clears the in-memory bans; persist that, so no ban from here
    # survives into BANNED_IPS_FILE for the next run to load.
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.save_bans()


def _text(html):
    """What a reader sees: no scripts, no icons, no tags."""
    html = re.sub(r"<(script|svg)\b.*?</\1>", " ", html, flags=re.S | re.I)
    return " ".join(re.sub(r"<[^>]+>", " ", html).split())


def _footer(html):
    return re.search(r"<footer\b.*?</footer>", html, re.S).group(0)


def _links(response):
    return [v.strip() for v in response.headers.get_list("link")]


# --- The route -------------------------------------------------------------------


class TestRoute:
    @pytest.mark.parametrize("headers", [CHROME, CURL], ids=["browser", "curl"])
    def test_is_an_html_page_for_everyone(self, headers):
        response = client.get("/privacy", headers=headers)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert "<h1" in response.text

    def test_runs_no_lookup(self, lookups):
        """Before this route the catch-all would have taken "privacy" as a
        lookup target."""
        client.get("/privacy", headers=CHROME)
        for name, mock in lookups.items():
            assert not mock.called, f"{name} ran"

    def test_head(self):
        get = client.get("/privacy", headers=CURL)
        head = client.head("/privacy", headers=CURL)
        assert head.status_code == 200
        assert head.headers["content-type"] == get.headers["content-type"]
        assert head.content == b""

    def test_keeps_the_security_headers(self):
        response = client.get("/privacy", headers=CHROME)
        assert "default-src 'self'" in response.headers["content-security-policy"]
        assert response.headers["x-frame-options"] == "DENY"

    def test_has_the_search_box_and_its_script(self):
        html = client.get("/privacy", headers=CHROME).text
        assert 'id="lookup-form"' in html
        assert re.search(r'<script src="/static/js/app\.js" nonce="[^"]+"', html)

    def test_a_domain_that_starts_the_same_is_still_a_lookup(self, lookups):
        """The route is exact: privacy.com is somebody's domain."""
        client.get("/privacy.com", headers=CURL)
        assert lookups["gather"].called


class TestNotALookupForTheSecurityMiddleware:
    def test_does_not_spend_the_lookup_budget(self):
        client.get("/privacy", headers=CHROME)
        assert not rate_limiter.request_history.get(VISITOR_IP)

    def test_a_burst_is_not_banned(self):
        """Over the per-second limit a lookup path would earn a 429 and a ban."""
        limit = config.RATE_LIMIT_REQUESTS_PER_SECOND
        for _ in range(limit + 5):
            response = client.get("/privacy", headers=CHROME)
            assert response.status_code == 200
        assert not ip_ban_manager.is_banned(VISITOR_IP)

    def test_exemption_is_exact_and_case_sensitive(self):
        """/PRIVACY falls through to the catch-all, a lookup, which must keep
        its rate limit."""
        wm = WhitelistManager()
        assert wm.is_static("/privacy")
        for path in ("/PRIVACY", "/Privacy", "/privacy.com", "/privacy/", "/xprivacy"):
            assert not wm.is_static(path), path

    def test_the_detector_does_not_flag_it(self):
        assert not SuspiciousPatternDetector().is_suspicious("/privacy")

    def test_a_banned_address_still_gets_403(self):
        ip_ban_manager.ban_ip("203.0.113.50", reason="test", duration=3600)
        response = proxy_client.get(
            "/privacy", headers={**CHROME, "x-real-ip": "203.0.113.50"}
        )
        assert response.status_code == 403


# --- What the page says --------------------------------------------------------


def _privacy_text(**patches):
    with contextlib.ExitStack() as stack:
        for name, value in patches.items():
            stack.enter_context(patch(f"main.{name}", value))
        return _text(client.get("/privacy", headers=CHROME).text)


def _mentions(text: str, name: str) -> bool:
    """Whether the page names `name` as a word. A regex rather than `in`:
    CodeQL reads a hostname literal tested with `in` as a URL check."""
    return re.search(rf"(?<![\w.]){re.escape(name)}(?![\w])", text) is not None


class TestContent:
    def test_says_what_a_lookup_logs(self):
        text = _privacy_text()
        assert "IP address" in text
        assert "service.log" in text

    def test_log_retention_matches_the_handler(self):
        """The page and the rotating handler read the same constant."""
        assert main.LOG_RETENTION_DAYS == 7
        assert main.file_handler.backupCount == main.LOG_RETENTION_DAYS
        assert f"{main.LOG_RETENTION_DAYS} days" in _privacy_text()

    def test_ban_durations_match_the_config(self):
        text = _privacy_text()
        assert f"{config.BAN_DURATION_RATE_LIMIT // 3600} hour" in text
        assert f"{config.BAN_DURATION_SUSPICIOUS // 3600} hours" in text

    def test_names_the_dns_resolvers_from_the_config(self):
        text = _privacy_text()
        for resolver in config.PUBLIC_RESOLVERS:
            assert resolver in text

    def test_names_the_other_servers_the_server_contacts(self):
        text = _privacy_text()
        for party in ("RDAP", "IANA", "WHOIS", "crt.sh", "port 443"):
            assert _mentions(text, party), party

    def test_crt_sh_is_not_listed_when_subdomains_are_off(self):
        assert not _mentions(_privacy_text(SUBDOMAIN_ENABLED=False), "crt.sh")

    def test_names_what_the_browser_contacts(self):
        text = _privacy_text()
        assert _mentions(text, "tile.openstreetmap.org")
        assert _mentions(text, config.WEBRTC_STUN_HOST)

    def test_no_stun_server_when_the_test_is_off(self):
        text = _privacy_text(WEBRTC_STUN_URL="", WEBRTC_STUN_HOST="")
        assert "STUN" not in text

    def test_says_the_fingerprint_stays_in_the_browser(self):
        text = _privacy_text()
        assert "never sent" in text
        assert "cookie" in text.lower()


# --- The Link header -------------------------------------------------------------


class TestLinkHeader:
    @pytest.mark.parametrize(
        "path, headers",
        [
            ("/privacy", CHROME),
            ("/", CHROME),
            ("/nasa.gov", CHROME),
            ("/192.168.0.1", CHROME),  # the error page
        ],
        ids=["privacy", "self page", "lookup page", "error page"],
    )
    def test_on_every_page(self, path, headers):
        response = client.get(path, headers=headers)
        assert response.headers["content-type"].startswith("text/html")
        assert _links(response) == [PRIVACY_LINK]

    @pytest.mark.parametrize(
        "path", ["/", "/nasa.gov", "/nasa.gov?format=text", "/192.168.0.1"]
    )
    def test_on_every_api_answer_from_the_lookup_routes(self, path):
        """An API client is logged exactly as a browser is, so it can find the
        policy without rendering a page."""
        response = client.get(path, headers=CURL)
        assert not response.headers["content-type"].startswith("text/html")
        assert _links(response) == [PRIVACY_LINK]

    def test_on_head(self):
        assert _links(client.head("/nasa.gov", headers=CURL)) == [PRIVACY_LINK]

    @pytest.mark.parametrize(
        "path", ["/static/css/whatismyip.css", "/healthz", "/robots.txt"]
    )
    def test_not_on_assets_and_machine_endpoints(self, path):
        assert _links(client.get(path, headers=CURL)) == []


# --- Links to it -----------------------------------------------------------------


class TestFooter:
    @pytest.mark.parametrize("path", ["/", "/nasa.gov", "/192.168.0.1", "/privacy"])
    def test_every_footer_links_the_page(self, path):
        footer = _footer(client.get(path, headers=CHROME).text)
        assert '<a href="/privacy">' in footer

    @pytest.mark.parametrize("path", ["/", "/nasa.gov", "/192.168.0.1", "/privacy"])
    def test_it_sits_with_the_source_link(self, path):
        """One group at the end of the footer row, not a line of its own."""
        footer = _footer(client.get(path, headers=CHROME).text)
        group = re.search(r'<span class="footer__links">(.*?)</span>', footer, re.S)
        assert group, footer
        assert '<a href="/privacy">' in group.group(1)
        assert re.search(r'href="https://github\.com/1kko/whatismyip"', group.group(1))
        assert "footer__note" not in footer


class TestFingerprintPanel:
    def _panel(self, **patches):
        with contextlib.ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(patch(f"main.{name}", value))
            html = client.get("/", headers=CHROME).text
        return _text(
            re.search(
                r'<details class="accordion" id="acc-fingerprint">.*?</details>',
                html,
                re.S,
            ).group(0)
        )

    def test_says_it_is_computed_locally(self):
        assert "computed in your browser and never sent to testserver" in (
            self._panel().lower()
        )

    def test_names_the_configured_host(self):
        """The host a visitor reached, not a hard-coded one."""
        panel = self._panel(PUBLIC_BASE_URL="https://ip.example.org")
        assert "never sent to ip.example.org" in panel

    def test_fingerprint_js_no_longer_credits_the_csp(self):
        """default-src 'self' allows a same-origin fetch, so the CSP is not
        what keeps the fingerprint in the browser."""
        source = Path("static/js/fingerprint.js").read_text(encoding="utf-8")
        assert "CSP forbids" not in source
