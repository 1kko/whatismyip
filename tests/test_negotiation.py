"""Response-format negotiation for the lookup routes (`/`, `/{domain_ip}`).

Order of precedence: `?format=` first, then the Accept header, and only when
Accept says nothing about our formats does the User-Agent decide — which is how
every client was answered before this existed.

The negotiate() matrix is checked against bare Requests (no I/O at all); the
route tests below it mock every lookup, so no test here touches the network.
"""

import copy
from contextlib import contextmanager
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

import main
from main import BrowserDetector, app

CLIENT_IP = "8.8.8.8"
client = TestClient(app, client=(CLIENT_IP, 41234))

CHROME = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
)
CURL = "curl/8.7.1"
# Both PowerShell generations borrow "Mozilla/5.0", which the browser patterns
# match on, yet Invoke-RestMethod parses JSON and has no use for a page.
WINDOWS_POWERSHELL = (
    "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.5007"
)
POWERSHELL_7 = (
    "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.22631; en-US) "
    "PowerShell/7.4.6"
)
# What Chrome sends on a top-level navigation.
CHROME_NAVIGATION_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
)


def _request(user_agent=None, accept=None, query=""):
    headers = []
    if user_agent is not None:
        headers.append((b"user-agent", user_agent.encode()))
    if accept is not None:
        headers.append((b"accept", accept.encode()))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": query.encode(),
            "headers": headers,
        }
    )


class TestUserAgentFallback:
    """Step 3: no Accept header, or one that is only */*. This is every client
    that existed before negotiation — browsers' fetch(), curl, wget — so it must
    answer exactly as BrowserDetector always has."""

    @pytest.mark.parametrize("accept", [None, "", "*/*", "*/*;q=0.8"])
    def test_a_browser_gets_html(self, accept):
        assert main.negotiate(_request(CHROME, accept)) == "html"

    @pytest.mark.parametrize("accept", [None, "", "*/*"])
    def test_curl_gets_json(self, accept):
        assert main.negotiate(_request(CURL, accept)) == "json"

    def test_no_user_agent_at_all_gets_json(self):
        assert main.negotiate(_request()) == "json"

    @pytest.mark.parametrize("user_agent", [WINDOWS_POWERSHELL, POWERSHELL_7])
    def test_powershell_is_not_a_browser(self, user_agent):
        assert not BrowserDetector.is_browser(user_agent)
        assert main.negotiate(_request(user_agent)) == "json"

    def test_an_accept_naming_none_of_our_formats_defers_to_the_user_agent(self):
        """An image prefetch names image types and */*; that says nothing about
        HTML versus JSON, so it must not be read as a preference for either."""
        accept = "image/avif,image/webp,*/*;q=0.8"
        assert main.negotiate(_request(CHROME, accept)) == "html"
        assert main.negotiate(_request(CURL, accept)) == "json"


class TestAcceptHeader:
    """Step 2: an Accept header that names one of our formats beats the UA."""

    def test_a_browser_asking_for_json_gets_json(self):
        """The case the item exists for: fetch() from a page, which carries a
        browser UA, sending Accept: application/json."""
        assert main.negotiate(_request(CHROME, "application/json")) == "json"

    def test_curl_asking_for_html_gets_html(self):
        assert main.negotiate(_request(CURL, "text/html")) == "html"

    def test_text_plain_selects_text(self):
        assert main.negotiate(_request(CHROME, "text/plain")) == "text"

    def test_a_browser_navigation_gets_html(self):
        assert main.negotiate(_request(CHROME, CHROME_NAVIGATION_ACCEPT)) == "html"
        assert main.negotiate(_request(CURL, CHROME_NAVIGATION_ACCEPT)) == "html"

    def test_q_values_decide_between_named_types(self):
        assert (
            main.negotiate(_request(CURL, "application/json;q=0.5, text/html"))
            == "html"
        )
        assert main.negotiate(
            _request(CHROME, "text/html;q=0.5, application/json")
        ) == ("json")

    def test_a_named_type_beats_one_reached_only_through_a_wildcard(self):
        """httpie's default. */* lends text/html a q of 0.5 as well, but the
        client named application/json, which is the one it wants."""
        accept = "application/json, */*;q=0.5"
        assert main.negotiate(_request(CHROME, accept)) == "json"

    def test_equal_q_goes_to_the_one_listed_first(self):
        assert main.negotiate(_request(CURL, "text/html, application/json")) == "html"
        assert main.negotiate(_request(CHROME, "application/json, text/html")) == "json"

    def test_the_most_specific_range_sets_the_q(self):
        """text/* allows text/html, but text/html;q=0 refuses it explicitly."""
        assert main.negotiate(_request(CHROME, "text/*, text/html;q=0")) == "text"

    def test_a_subtype_wildcard_matches(self):
        assert main.negotiate(_request(CHROME, "application/*")) == "json"

    def test_matching_ignores_case_and_whitespace(self):
        assert main.negotiate(_request(CHROME, " Application/JSON ; Q=1 ")) == "json"

    def test_a_malformed_q_does_not_raise(self):
        assert main.negotiate(_request(CURL, "text/html;q=abc, application/json")) == (
            "json"
        )


class TestFormatParameter:
    """Step 1: ?format= beats everything, so a link or a shell one-liner can
    pick the format without setting a header."""

    def test_format_beats_accept(self):
        request = _request(CHROME, "text/html", "format=json")
        assert main.negotiate(request) == "json"
        request = _request(CURL, "application/json", "format=html")
        assert main.negotiate(request) == "html"

    def test_format_beats_the_user_agent(self):
        assert main.negotiate(_request(CHROME, None, "format=json")) == "json"
        assert main.negotiate(_request(CURL, None, "format=html")) == "html"

    def test_text_is_a_recognised_format(self):
        assert main.negotiate(_request(CHROME, None, "format=text")) == "text"

    def test_the_value_is_case_insensitive(self):
        assert main.negotiate(_request(CHROME, None, "format=JSON")) == "json"

    @pytest.mark.parametrize("value", ["xml", "", "1", "jsonp"])
    def test_an_unknown_value_is_rejected_rather_than_ignored(self, value):
        """Following ?subdomains=: a value the server does not understand must
        not be answered as though it were understood."""
        with pytest.raises(HTTPException) as caught:
            main.negotiate(_request(CHROME, None, f"format={value}"))
        assert caught.value.status_code == 400
        assert "html, json, text" in caught.value.detail


# --- The routes -------------------------------------------------------------

LOCATION = {
    "ip": CLIENT_IP,
    "country_code": "US",
    "country_name": "United States",
    "city_name": "Mountain View",
    "lat": 37.386,
    "lon": -122.084,
    "accuracy_km": 20,
    "cidr": "8.8.8.0/24",
    "asn_name": "Google LLC",
    "is_private": False,
}
GATHERED = {
    "address": "example.com",
    "domain": {"a": [{"ip": "93.184.216.34", "ttl": 300}], "mx": [], "ns": []},
    "location": {**LOCATION, "ip": "93.184.216.34"},
    "whois": {"source": "rdap", "registrar": "Example Registrar"},
    "ssl": None,
    "resolved_ip": "93.184.216.34",
    "reverse_dns": None,
}


@contextmanager
def mocked_lookups():
    """Every lookup either route makes. Yields the mocks so a test can assert
    that a rejected request never reached them."""
    with (
        patch(
            "main.gather",
            new_callable=AsyncMock,
            side_effect=lambda *_, **__: copy.deepcopy(GATHERED),
        ) as gather,
        patch(
            "main.lookup_location",
            new_callable=AsyncMock,
            side_effect=lambda *_: dict(LOCATION),
        ),
        patch(
            "main.lookup_whois",
            new_callable=AsyncMock,
            return_value={"source": "rdap", "name": "8.8.8.0/24"},
        ) as whois,
        patch("main.domain_manager.perform_reverse_lookup", return_value=None),
    ):
        yield {"gather": gather, "whois": whois}


def _is_html(response):
    return response.headers["content-type"].startswith("text/html")


def _is_json(response):
    return response.headers["content-type"].startswith("application/json")


ROUTES = ["/", "/example.com"]


class TestRoutes:
    @pytest.mark.parametrize("path", ROUTES)
    def test_a_browser_asking_for_json_gets_json(self, path):
        with mocked_lookups():
            response = client.get(
                path, headers={"user-agent": CHROME, "accept": "application/json"}
            )
        assert response.status_code == 200
        assert _is_json(response)
        assert "address" in response.json()

    @pytest.mark.parametrize("path", ROUTES)
    def test_curl_asking_for_html_gets_html(self, path):
        with mocked_lookups():
            response = client.get(
                path, headers={"user-agent": CURL, "accept": "text/html"}
            )
        assert response.status_code == 200
        assert _is_html(response)
        assert "WhatIsMyIP" in response.text

    @pytest.mark.parametrize("path", ROUTES)
    def test_format_beats_accept(self, path):
        with mocked_lookups():
            response = client.get(
                f"{path}?format=json",
                headers={"user-agent": CHROME, "accept": "text/html"},
            )
        assert response.status_code == 200
        assert _is_json(response)

    @pytest.mark.parametrize("path", ROUTES)
    def test_the_user_agent_still_decides_without_a_preference(self, path):
        """TestClient sends Accept: */*, as fetch(), curl and wget do."""
        with mocked_lookups():
            page = client.get(path, headers={"user-agent": CHROME})
            data = client.get(path, headers={"user-agent": CURL})
        assert _is_html(page)
        assert _is_json(data)

    @pytest.mark.parametrize("path", ROUTES)
    def test_powershell_gets_json(self, path):
        with mocked_lookups():
            response = client.get(path, headers={"user-agent": WINDOWS_POWERSHELL})
        assert response.status_code == 200
        assert _is_json(response)

    @pytest.mark.parametrize("path", ROUTES)
    def test_an_unknown_format_is_a_400_before_any_lookup(self, path):
        with mocked_lookups() as mocks:
            response = client.get(f"{path}?format=xml", headers={"user-agent": CURL})
        assert response.status_code == 400
        assert "html, json, text" in response.json()["detail"]
        mocks["gather"].assert_not_called()
        mocks["whois"].assert_not_called()

    @pytest.mark.parametrize("path", ROUTES)
    def test_format_text_is_accepted(self, path):
        """Only that it is not a 400; tests/test_text_format.py has the body."""
        with mocked_lookups():
            response = client.get(f"{path}?format=text", headers={"user-agent": CURL})
        assert response.status_code == 200

    def test_subdomains_only_stays_json_whatever_is_negotiated(self):
        """`only` is a data fragment the page fetches; there is no HTML
        rendering of it to give, so it answers JSON even to ?format=html."""
        fake = {"names": ["a.example.com"], "count": 1, "error": None}
        with patch("main.get_subdomains", new_callable=AsyncMock, return_value=fake):
            response = client.get(
                "/example.com?subdomains=only&format=html",
                headers={"user-agent": CHROME},
            )
        assert response.status_code == 200
        assert _is_json(response)


def _vary(response):
    return {token.strip().lower() for token in response.headers["vary"].split(",")}


class TestCacheHeaders:
    """The same URL now answers HTML or JSON depending on headers, and every
    answer carries the visitor's own IP and request headers. A shared cache in
    front must neither mix the two formats nor store either."""

    @pytest.mark.parametrize("path", ROUTES)
    @pytest.mark.parametrize("user_agent", [CHROME, CURL])
    def test_both_formats_carry_vary_and_no_store(self, path, user_agent):
        with mocked_lookups():
            response = client.get(path, headers={"user-agent": user_agent})
        assert response.status_code == 200
        assert {"accept", "user-agent"} <= _vary(response)
        assert response.headers["cache-control"] == "no-store"

    @pytest.mark.parametrize("path", ROUTES)
    def test_an_error_from_the_route_carries_them_too(self, path):
        with mocked_lookups():
            response = client.get(f"{path}?format=xml", headers={"user-agent": CURL})
        assert response.status_code == 400
        assert {"accept", "user-agent"} <= _vary(response)
        assert response.headers["cache-control"] == "no-store"

    def test_subdomains_only_carries_them(self):
        fake = {"names": [], "count": 0, "error": None}
        with patch("main.get_subdomains", new_callable=AsyncMock, return_value=fake):
            response = client.get(
                "/example.com?subdomains=only", headers={"user-agent": CHROME}
            )
        assert response.headers["cache-control"] == "no-store"

    @pytest.mark.parametrize("path", ROUTES)
    def test_head_negotiates_like_get_and_carries_them(self, path):
        """HEAD skips the lookup but must still describe what GET would send."""
        with mocked_lookups() as mocks:
            response = client.head(
                path, headers={"user-agent": CHROME, "accept": "application/json"}
            )
            bad = client.head(f"{path}?format=xml", headers={"user-agent": CURL})
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert {"accept", "user-agent"} <= _vary(response)
        assert response.headers["cache-control"] == "no-store"
        assert bad.status_code == 400
        assert all(not m.called for m in mocks.values())

    def test_other_routes_are_left_alone(self):
        """Matched on the route, not a path prefix: /healthz is not a lookup."""
        response = client.get("/healthz", headers={"user-agent": CURL})
        assert "user-agent" not in response.headers.get("vary", "").lower()


class TestSecurityClassification:
    """?format= is a query parameter, and the security middleware classifies
    requests by request.url.path alone — so adding it changes nothing there.
    These pin that down rather than take it on trust."""

    def test_format_on_root_is_rate_limited_like_any_lookup(self):
        with mocked_lookups():
            response = client.get("/?format=json", headers={"user-agent": CURL})
        assert response.status_code == 200
        assert len(main.rate_limiter.request_history[CLIENT_IP]) == 1

    @pytest.mark.parametrize("path", ROUTES)
    def test_a_probe_shaped_value_is_a_400_not_a_ban(self, path):
        """`.env` and `.json` are detector rules; in the query string they never
        reach the detector, which reads the path."""
        for value in (".env", "config.json"):
            with mocked_lookups():
                response = client.get(
                    f"{path}?format={value}", headers={"user-agent": CURL}
                )
            assert response.status_code == 400
        assert not main.ip_ban_manager.is_banned(CLIENT_IP)
