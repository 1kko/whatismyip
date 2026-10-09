"""/robots.txt, /favicon.ico and HEAD requests stay off the lookup pipeline.

Before these had routes of their own, the /{domain_ip} catch-all took them as
lookup targets: a crawler got an HTML page where it expected robots.txt, every
/favicon.ico cost an RDAP query and a port-43 WHOIS attempt, and an uptime
monitor's `HEAD /` got 405 because FastAPI's @app.get answers GET alone.
"""

import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from main import app, ip_ban_manager, rate_limiter
from security import WhitelistManager

# A public peer address, so the request is treated as an ordinary visitor.
client = TestClient(app, client=("8.8.8.8", 41234))
# Peer 127.0.0.1 is in TRUSTED_PROXIES, so x-real-ip picks the client address.
proxy_client = TestClient(app, client=("127.0.0.1", 41234))

CURL = {"user-agent": "curl/8"}
BROWSER = {"user-agent": "Mozilla/5.0 (Macintosh) Safari/605.1.15"}
# What gather() returns when nothing resolves, so a GET that does reach it
# renders normally and a test fails on its own assertion, not a KeyError.
EMPTY_LOOKUP = {
    "address": "",
    "domain": {},
    "location": {},
    "whois": {"error": "mocked"},
    "ssl": None,
    "resolved_ip": None,
    "reverse_dns": None,
}


@pytest.fixture
def lookups():
    """Every entry point into the expensive pipeline, mocked so that a test can
    assert none of them ran. lookup.lookup_whois is patched as well as
    main.lookup_whois because gather() reaches it through the lookup module,
    and both sit above the WHOIS cache, so an earlier test's cached answer for
    the same target cannot hide a call."""
    mocks = {
        "gather": AsyncMock(return_value=dict(EMPTY_LOOKUP)),
        "lookup_whois": AsyncMock(return_value={"error": "mocked"}),
        "lookup_location": AsyncMock(return_value={}),
        "get_subdomains": AsyncMock(return_value=[]),
        "perform_reverse_lookup": MagicMock(return_value=None),
        "lookup_rdap": MagicMock(return_value=None),
        "whois": MagicMock(return_value={}),
    }
    with contextlib.ExitStack() as stack:
        for name in ("gather", "lookup_whois", "lookup_location", "get_subdomains"):
            stack.enter_context(patch(f"main.{name}", mocks[name]))
        stack.enter_context(patch("lookup.lookup_whois", mocks["lookup_whois"]))
        stack.enter_context(
            patch(
                "main.domain_manager.perform_reverse_lookup",
                mocks["perform_reverse_lookup"],
            )
        )
        stack.enter_context(patch("lookup.lookup_rdap", mocks["lookup_rdap"]))
        stack.enter_context(patch("lookup.whois.whois", mocks["whois"]))
        yield mocks


def assert_no_lookup(mocks):
    for name, mock in mocks.items():
        assert not mock.called, f"{name} ran"


class TestRobotsTxt:
    def test_is_plain_text(self, lookups):
        response = client.get("/robots.txt", headers=CURL)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/plain")
        assert_no_lookup(lookups)

    def test_keeps_crawlers_off_subdomain_listings(self):
        """The page links "Load subdomains" for every domain it shows, and on a
        cache miss that link is a crt.sh round trip."""
        lines = client.get("/robots.txt", headers=CURL).text.splitlines()
        assert "User-agent: *" in lines
        assert "Disallow: /*?subdomains=" in lines

    def test_same_for_a_browser(self, lookups):
        response = client.get("/robots.txt", headers=BROWSER)
        assert response.headers["content-type"].startswith("text/plain")
        assert_no_lookup(lookups)


class TestFavicon:
    def test_redirects_permanently_to_the_static_copy(self, lookups):
        response = client.get("/favicon.ico", headers=BROWSER, follow_redirects=False)
        assert response.status_code == 301
        assert response.headers["location"] == "/static/favicon.ico"
        assert_no_lookup(lookups)

    @patch("main.geo_ip_manager.fetch_location", return_value={})
    @patch("lookup.lookup_whois", new_callable=AsyncMock)
    def test_never_reaches_whois(self, mock_whois, mock_geo):
        """gather() runs for real here, so the count is of what the catch-all
        used to do with this path: one RDAP query, then port-43 WHOIS."""
        mock_whois.return_value = {"error": "mocked"}
        client.get("/favicon.ico", headers=CURL, follow_redirects=False)
        assert mock_whois.call_count == 0

    def test_redirect_target_is_served(self):
        response = client.get("/favicon.ico", headers=BROWSER)
        assert response.status_code == 200
        assert response.content[:4] == b"\x00\x00\x01\x00"  # ICO magic


class TestFixedRoutesAndTheRateLimiter:
    """robots.txt and favicon.ico are a constant answer, cheaper than a file
    from /static, so like /static they stay out of the per-IP bucket that
    guards the lookup surface."""

    def test_do_not_spend_the_lookup_budget(self):
        client.get("/robots.txt", headers=CURL)
        client.get("/favicon.ico", headers=CURL, follow_redirects=False)
        assert not rate_limiter.request_history.get("8.8.8.8")

    def test_exemption_is_exact_and_case_sensitive(self):
        """The routes are case-sensitive. /ROBOTS.TXT still falls through to
        the catch-all, so an exemption that matched it would leave a lookup
        path with no rate limit at all."""
        wm = WhitelistManager()
        assert wm.is_static("/robots.txt")
        assert wm.is_static("/favicon.ico")
        assert not wm.is_static("/ROBOTS.TXT")
        assert not wm.is_static("/Favicon.ico")
        assert not wm.is_static("/robots.txt.com")
        assert not wm.is_static("/xrobots.txt")


class TestHead:
    def test_head_root_is_not_405(self, lookups):
        response = client.head("/", headers=CURL)
        assert response.status_code == 200
        assert_no_lookup(lookups)

    def test_head_target_runs_no_lookup(self, lookups):
        response = client.head("/nasa.gov?subdomains=include", headers=CURL)
        assert response.status_code == 200
        assert response.content == b""
        assert_no_lookup(lookups)

    def test_head_carries_the_content_type_get_would(self, lookups):
        api = client.head("/nasa.gov", headers=CURL)
        page = client.head("/nasa.gov", headers=BROWSER)
        assert api.headers["content-type"] == "application/json"
        assert page.headers["content-type"].startswith("text/html")
        assert_no_lookup(lookups)

    def test_head_does_not_claim_an_empty_body(self, lookups):
        """A HEAD response may only carry Content-Length if it equals what GET
        would send (RFC 9110 8.6). The lookup's size is unknown without running
        it, so the header is left out rather than sent as 0."""
        response = client.head("/nasa.gov", headers=CURL)
        assert "content-length" not in response.headers

    def test_head_keeps_the_security_headers(self, lookups):
        response = client.head("/", headers=BROWSER)
        assert "content-security-policy" in response.headers
        assert response.headers["x-frame-options"] == "DENY"

    def test_get_still_reaches_the_lookup(self, lookups):
        """The HEAD routes must not shadow GET on the same paths."""
        client.get("/nasa.gov", headers=CURL)
        assert lookups["gather"].called

    @pytest.mark.parametrize(
        "path, status",
        [
            ("/healthz", 200),
            ("/robots.txt", 200),
            ("/favicon.ico", 301),
            ("/static/favicon.ico", 200),
        ],
    )
    def test_head_on_fixed_paths(self, lookups, path, status):
        get = client.get(path, headers=CURL, follow_redirects=False)
        head = client.head(path, headers=CURL, follow_redirects=False)
        assert head.status_code == status == get.status_code
        assert head.headers.get("content-type") == get.headers.get("content-type")
        assert head.content == b""
        assert_no_lookup(lookups)


class TestHeadStaysBehindTheMiddleware:
    """HEAD is answered by routes, after the security middleware has run, so a
    lighter answer is not a way around any of its checks."""

    def test_banned_address_still_gets_403(self, lookups):
        ip_ban_manager.ban_ip("203.0.113.40", reason="test", duration=3600)
        for path in ("/", "/nasa.gov", "/robots.txt", "/healthz"):
            response = proxy_client.head(path, headers={"x-real-ip": "203.0.113.40"})
            assert response.status_code == 403, path

    def test_head_on_the_lookup_surface_is_rate_limited(self, lookups):
        proxy_client.head("/nasa.gov", headers={"x-real-ip": "203.0.113.41"})
        assert len(rate_limiter.request_history["203.0.113.41"]) == 1

    def test_head_on_a_probe_path_is_still_banned(self, lookups):
        proxy_client.head("/admin.php", headers={"x-real-ip": "203.0.113.42"})
        assert ip_ban_manager.is_banned("203.0.113.42")

    def test_head_on_mcp_is_left_to_the_mcp_app(self, lookups):
        """/mcp is a single segment too. Its route is registered first, so the
        lookup HEAD route never answers for it and the transport's own 405
        stands."""
        response = client.head("/mcp", headers=CURL)
        assert response.status_code == 405
        assert_no_lookup(lookups)
