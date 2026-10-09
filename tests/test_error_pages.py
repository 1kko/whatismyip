"""A browser that hits an error gets a page; every other client's JSON is unchanged.

Searching for a router's address (192.168.0.1) used to end on
{"detail": "Private or reserved IP addresses are not allowed"}: no search box,
no explanation, no way back. The security middleware's 403 and 429 were the
same bare JSON. "A browser" here means negotiate() picked the page, so a
browser sending ?format=json or Accept: application/json still gets JSON.

The JSON bodies are pinned byte for byte, because they are the API contract.
Every lookup is mocked; nothing here touches the network.
"""

import ipaddress
import json
import re
import shutil
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import main
from lookup import PrivateAddressError
from main import app, ip_ban_manager, rate_limiter

CLIENT_IP = "8.8.8.8"
client = TestClient(app, client=(CLIENT_IP, 41234))
# Peer 127.0.0.1 is in TRUSTED_PROXIES, so x-real-ip picks the client address.
proxy_client = TestClient(app, client=("127.0.0.1", 41234))

CHROME = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    ),
    # What Chrome sends on a top-level navigation.
    "accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
        "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
}
CURL = {"user-agent": "curl/8.7.1", "accept": "*/*"}

PRIVATE_BYTES = b'{"detail":"Private or reserved IP addresses are not allowed"}'
INVALID_BYTES = b'{"error":"not a domain name or IP address","code":"invalid_target"}'
IPV6_BYTES = (
    b'{"error":"IPv6 addresses are not supported yet","code":"ipv6_not_supported"}'
)
DENIED_BYTES = b'{"error":"Access denied due to the policy"}'
TOO_MANY_BYTES = b'{"error":"Too many requests"}'

LOCATION = {
    "ip": CLIENT_IP,
    "country_code": "US",
    "country_name": "United States",
    "city_name": "",
    "cidr": "8.8.8.0/24",
    "asn_name": "GOOGLE",
    "is_private": False,
}


@pytest.fixture(autouse=True)
def _quiet_lookups():
    """No lookup leaves the process, and geo-blocking is pinned open so that
    whatever GEO_RULES_FILE a previous run left behind cannot 403 a request
    a test expects to reach the route."""
    allowed = {"allowed": True, "country": "US", "region": None, "reason": "test"}
    with (
        patch("main.geo_block_manager.check_access", return_value=allowed),
        patch(
            "main.lookup_location",
            new_callable=AsyncMock,
            side_effect=lambda *_: dict(LOCATION),
        ),
        patch(
            "main.lookup_whois",
            new_callable=AsyncMock,
            return_value={"source": "rdap", "name": "8.8.8.0/24"},
        ),
        patch("main.domain_manager.perform_reverse_lookup", return_value=None),
    ):
        yield
    # conftest clears the in-memory bans; persist that, so no ban from here
    # survives into BANNED_IPS_FILE for the next run to load.
    ip_ban_manager.banned_ips.clear()
    ip_ban_manager.save_bans()


def _is_html(response):
    return response.headers["content-type"].startswith("text/html")


def _is_json(response):
    return response.headers["content-type"].startswith("application/json")


def _visible_text(html):
    """What a reader sees: no scripts, no icons, no tags, no attributes."""
    html = re.sub(r"<(script|svg)\b.*?</\1>", " ", html, flags=re.S | re.I)
    return " ".join(re.sub(r"<[^>]+>", " ", html).split())


def _has_search_box(html):
    return 'id="lookup-form"' in html and 'id="lookup-input"' in html


def _same_page(html):
    """The page minus the one thing that differs per request."""
    return re.sub(r'nonce="[^"]*"', 'nonce=""', html)


def _vary(response):
    return {t.strip().lower() for t in response.headers.get("vary", "").split(",")}


# --- 400: a private or reserved address --------------------------------------


class TestPrivateAddress:
    def test_a_browser_gets_a_page_with_a_search_box(self):
        response = client.get("/192.168.0.1", headers=CHROME)
        assert response.status_code == 400
        assert _is_html(response)
        assert _has_search_box(response.text)
        text = _visible_text(response.text)
        assert "192.168.0.1 is a local network address" in text
        assert "public IP" in text
        assert 'href="/"' in response.text

    def test_an_api_client_gets_the_json_it_always_did(self):
        response = client.get("/192.168.0.1", headers=CURL)
        assert response.status_code == 400
        assert _is_json(response)
        assert response.content == PRIVATE_BYTES

    @pytest.mark.parametrize(
        "address",
        [
            "10.0.0.1",
            "172.16.5.4",
            "172.31.255.254",
            "192.168.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",  # CGNAT: carriers, and Tailscale's MagicDNS
            "100.127.255.254",
        ],
    )
    def test_every_local_range_gets_the_local_network_explanation(self, address):
        response = client.get(f"/{address}", headers=CHROME)
        assert response.status_code == 400
        assert f"{address} is a local network address" in _visible_text(response.text)

    @pytest.mark.parametrize("address", ["240.0.0.1", "224.0.0.1", "192.0.2.1"])
    def test_a_reserved_address_is_not_called_local(self, address):
        """Multicast, class E and the documentation range are refused too, but
        telling the visitor they are on their own network would be wrong."""
        response = client.get(f"/{address}", headers=CHROME)
        assert response.status_code == 400
        text = _visible_text(response.text)
        assert "local network" not in text
        assert f"{address} is a reserved IP address" in text

    def test_a_domain_resolving_to_a_private_address_says_so(self):
        """router.asus.com is the real-world case: it answers 192.168.50.1."""
        with patch(
            "main.gather",
            new_callable=AsyncMock,
            side_effect=PrivateAddressError("router.example.com"),
        ):
            page = client.get("/router.example.com", headers=CHROME)
            data = client.get("/router.example.com", headers=CURL)
        assert page.status_code == 400
        assert "router.example.com resolves to a private or reserved" in (
            _visible_text(page.text)
        )
        assert data.status_code == 400
        assert data.content == PRIVATE_BYTES

    def test_format_json_from_a_browser_gets_json(self):
        response = client.get("/192.168.0.1?format=json", headers=CHROME)
        assert response.status_code == 400
        assert response.content == PRIVATE_BYTES

    def test_accept_json_from_a_browser_gets_json(self):
        """A fetch() from the page itself."""
        headers = {**CHROME, "accept": "application/json"}
        response = client.get("/192.168.0.1", headers=headers)
        assert response.status_code == 400
        assert response.content == PRIVATE_BYTES

    def test_the_page_keeps_the_lookup_cache_headers(self):
        response = client.get("/192.168.0.1", headers=CHROME)
        assert {"accept", "user-agent"} <= _vary(response)
        assert response.headers["cache-control"] == "no-store"


# --- 400: not a target at all ------------------------------------------------


class TestInvalidTarget:
    def test_a_browser_gets_a_page_with_a_search_box(self):
        response = client.get("/%7Btarget%7D", headers=CHROME)
        assert response.status_code == 400
        assert _is_html(response)
        assert _has_search_box(response.text)
        assert "Not a domain name or IP address" in _visible_text(response.text)

    def test_the_page_does_not_echo_free_text(self):
        """A target that is neither a hostname nor an address is arbitrary
        text, and putting it on our page would let a link write on it."""
        response = client.get("/call-1-800-555-0100-now%21", headers=CHROME)
        assert response.status_code == 400
        assert "call-1-800" not in response.text

    def test_an_api_client_gets_the_json_it_always_did(self):
        response = client.get("/%7Btarget%7D", headers=CURL)
        assert response.status_code == 400
        assert response.content == INVALID_BYTES

    def test_ipv6_gets_its_own_page(self):
        response = client.get("/2001:4860:4860::8888", headers=CHROME)
        assert response.status_code == 400
        assert _is_html(response)
        assert _has_search_box(response.text)
        assert "IPv6 addresses are not supported yet" in _visible_text(response.text)

    def test_ipv6_api_json_is_unchanged(self):
        response = client.get("/2001:4860:4860::8888", headers=CURL)
        assert response.status_code == 400
        assert response.content == IPV6_BYTES

    def test_format_json_from_a_browser_gets_json(self):
        response = client.get("/%7Btarget%7D?format=json", headers=CHROME)
        assert response.status_code == 400
        assert response.content == INVALID_BYTES


# --- 403 and 429 from the security middleware ---------------------------------


def _ban():
    ip_ban_manager.ban_ip(CLIENT_IP, reason="manual", duration=3600)


class TestAccessDenied:
    def test_a_banned_browser_gets_a_page_with_a_search_box(self):
        _ban()
        response = client.get("/", headers=CHROME)
        assert response.status_code == 403
        assert _is_html(response)
        assert _has_search_box(response.text)
        assert main.ACCESS_DENIED["error"] in _visible_text(response.text)

    def test_a_banned_api_client_gets_the_json_it_always_did(self):
        _ban()
        response = client.get("/", headers=CURL)
        assert response.status_code == 403
        assert _is_json(response)
        assert response.content == DENIED_BYTES

    def test_every_403_page_is_the_same_page(self):
        """The rule from commit a9941fc holds for the page as for the JSON: a
        blocked visitor learns that they were blocked and nothing else. A ban,
        the country filter and the probe detector must be indistinguishable."""
        pages = []

        _ban()
        pages.append(client.get("/", headers=CHROME))  # banned
        pages.append(client.get("/example.com", headers=CHROME))  # banned
        ip_ban_manager.banned_ips.clear()

        pages.append(client.get("/admin.php", headers=CHROME))  # probe
        ip_ban_manager.banned_ips.clear()
        pages.append(client.get("/.git/config", headers=CHROME))  # nested probe
        ip_ban_manager.banned_ips.clear()

        blocked = {"allowed": False, "country": "CN", "region": None, "reason": "x"}
        with patch("main.geo_block_manager.check_access", return_value=blocked):
            pages.append(client.get("/", headers=CHROME))  # geo-blocked

        assert [p.status_code for p in pages] == [403] * len(pages)
        assert len({_same_page(p.text) for p in pages}) == 1
        words = set(re.findall(r"[a-z]+", _visible_text(pages[0].text).lower()))
        for leak in ("ban", "banned", "country", "reason", "geo", "rule", "cn"):
            assert leak not in words, leak

    def test_format_json_from_a_browser_gets_json(self):
        _ban()
        response = client.get("/?format=json", headers=CHROME)
        assert response.status_code == 403
        assert response.content == DENIED_BYTES

    def test_accept_json_from_a_browser_gets_json(self):
        """The page's own subdomain fetch() sends exactly this."""
        _ban()
        headers = {**CHROME, "accept": "application/json"}
        response = client.get("/example.com?subdomains=only", headers=headers)
        assert response.status_code == 403
        assert response.content == DENIED_BYTES

    @pytest.mark.parametrize(
        ("headers", "page"), [(CHROME, True), (CURL, False)], ids=["browser", "api"]
    )
    def test_a_bad_format_does_not_turn_a_403_into_a_400(self, headers, page):
        """negotiate() raises on ?format=xml; the middleware answers before
        the route ever sees it, so it falls back to Accept and the UA."""
        _ban()
        response = client.get("/?format=xml", headers=headers)
        assert response.status_code == 403
        if page:
            assert _is_html(response)
        else:
            assert response.content == DENIED_BYTES

    def test_the_refusal_says_it_varies(self):
        _ban()
        response = client.get("/", headers=CHROME)
        assert {"accept", "user-agent"} <= _vary(response)


@pytest.fixture
def ip_rules(tmp_path):
    """Point the live rule manager at a throwaway file for one test."""
    path = tmp_path / "ip_rules.json"
    original = main.ip_rule_manager.rules_file

    def write(entries):
        path.write_text(json.dumps(entries), encoding="utf-8")
        main.ip_rule_manager.rules_file = str(path)
        main.ip_rule_manager.reload()

    yield write
    main.ip_rule_manager.rules_file = original
    main.ip_rule_manager.reload()


class TestIpRuleBlock:
    """`block: true` is refused before the path is even classified, so this is
    the one 403 that can land on /mcp."""

    def test_a_blocked_browser_gets_the_page(self, ip_rules):
        ip_rules([{"name": "scanner", "ipv4": "203.0.113.9", "block": True}])
        response = proxy_client.get("/", headers={**CHROME, "x-real-ip": "203.0.113.9"})
        assert response.status_code == 403
        assert _is_html(response)
        assert main.ACCESS_DENIED["error"] in _visible_text(response.text)

    def test_mcp_stays_json_even_for_a_browser(self, ip_rules):
        """/mcp is a JSON-RPC surface, and its responses go out without a CSP,
        so it never serves a page."""
        ip_rules([{"name": "scanner", "ipv4": "203.0.113.9", "block": True}])
        response = proxy_client.post(
            "/mcp", json={}, headers={**CHROME, "x-real-ip": "203.0.113.9"}
        )
        assert response.status_code == 403
        assert response.content == DENIED_BYTES


class TestTooManyRequests:
    @pytest.fixture(autouse=True)
    def _limit_everything(self, monkeypatch):
        # The first lookup request breaches the per-second limit.
        monkeypatch.setattr(rate_limiter, "requests_per_second", 0)

    def test_a_browser_gets_a_page_with_a_search_box(self):
        response = client.get("/", headers=CHROME)
        assert response.status_code == 429
        assert _is_html(response)
        assert _has_search_box(response.text)
        text = _visible_text(response.text)
        assert "Too many requests" in text
        # Says to wait, not for how long or what the limit is.
        for leak in ("ban", "hour", "minute", "second", "limit"):
            assert leak not in text.lower(), leak

    def test_an_api_client_gets_the_json_it_always_did(self):
        response = client.get("/", headers=CURL)
        assert response.status_code == 429
        assert _is_json(response)
        assert response.content == TOO_MANY_BYTES

    def test_format_json_from_a_browser_gets_json(self):
        response = client.get("/?format=json", headers=CHROME)
        assert response.status_code == 429
        assert response.content == TOO_MANY_BYTES

    def test_the_ban_policy_is_unchanged(self):
        """Settled: a lookup over the limit is a 429 and a one-hour ban."""
        client.get("/", headers=CHROME)
        assert ip_ban_manager.banned_ips[CLIENT_IP]["reason"] == "rate_limit"


# --- The page itself ----------------------------------------------------------


class TestErrorPageMarkup:
    @pytest.fixture
    def page(self):
        return client.get("/192.168.0.1", headers=CHROME)

    def test_csp_is_intact(self, page):
        """No inline script and no inline style: every script is a file, and
        carries the nonce the CSP header names."""
        csp = page.headers["content-security-policy"]
        nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
        scripts = re.findall(r"<script\b[^>]*>", page.text)
        assert scripts
        for tag in scripts:
            assert 'src="/static/' in tag, tag
            assert f'nonce="{nonce}"' in tag, tag
        assert "<style" not in page.text
        assert " style=" not in page.text

    def test_it_shares_the_page_assets(self, page):
        assert 'href="/static/css/whatismyip.css"' in page.text
        assert 'src="/static/js/app.js"' in page.text
        assert 'href="/static/favicon.ico"' in page.text

    def test_the_search_box_is_the_same_one_the_page_has(self, page):
        """app.js finds the search box by id; both templates include one copy."""
        with patch(
            "main.gather",
            new_callable=AsyncMock,
            return_value={
                "address": "example.com",
                "domain": {"a": [{"ip": "93.184.216.34", "ttl": 300}]},
                "location": {**LOCATION, "ip": "93.184.216.34"},
                "whois": {"source": "rdap", "registrar": "Example Registrar"},
                "ssl": None,
                "resolved_ip": "93.184.216.34",
                "reverse_dns": None,
            },
        ):
            lookup_page = client.get("/example.com", headers=CHROME).text

        def search(html):
            return re.search(r'<div class="search-wrap">.*?</div>', html, re.S).group(0)

        assert search(page.text) == search(lookup_page)


# --- The search box hint (static/js/app.js) -----------------------------------

APP_JS = Path("static/js/app.js")
NODE = shutil.which("node")


def _js_is_local(addresses):
    """Run app.js's isLocalAddress() in node over `addresses`."""
    source = APP_JS.read_text(encoding="utf-8")
    ipv4 = re.search(r"^const IPV4 = .*;$", source, re.M).group(0)
    func = re.search(
        r"^function isLocalAddress\(value\) \{.*?^\}$", source, re.M | re.S
    ).group(0)
    script = (
        f"{ipv4}\n{func}\n"
        f"console.log(JSON.stringify({json.dumps(addresses)}.map(isLocalAddress)));"
    )
    # The script is app.js's own source plus a fixed list of addresses.
    out = subprocess.run(  # noqa: S603
        [NODE, "-e", script], capture_output=True, text=True, check=True, timeout=30
    )
    return json.loads(out.stdout)


@pytest.mark.skipif(NODE is None, reason="needs node")
def test_the_search_box_and_the_server_agree_on_what_is_local():
    """The hint is decided in the browser, before any request, and the error
    page's explanation on the server; the boundaries of each range are where
    the two would drift apart."""
    addresses = [
        "10.0.0.0", "10.255.255.255", "11.0.0.0", "9.255.255.255",
        "172.15.255.255", "172.16.0.0", "172.31.255.255", "172.32.0.0",
        "192.168.0.1", "192.168.255.255", "192.169.0.0", "192.167.255.255",
        "127.0.0.1", "127.255.255.255", "128.0.0.0",
        "169.254.0.0", "169.254.255.255", "169.253.255.255", "169.255.0.0",
        "100.63.255.255", "100.64.0.0", "100.127.255.255", "100.128.0.0",
        "8.8.8.8", "1.1.1.1", "240.0.0.1", "224.0.0.1",
        "example.com", "",
    ]  # fmt: skip

    def server_is_local(value):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(address in network for network in main._LOCAL_NETWORKS)

    assert _js_is_local(addresses) == [server_is_local(a) for a in addresses]


def test_the_hint_links_home_without_a_request():
    """No fetch, no navigation: the hint is a link the visitor can follow."""
    source = APP_JS.read_text(encoding="utf-8")
    hint = re.search(
        r"^function showLocalHint\(target\) \{.*?^\}$", source, re.M | re.S
    ).group(0)
    assert 'href = "/"' in hint
    assert "fetch(" not in hint
    assert "location" not in hint
    # Built with textContent: the target is whatever the visitor typed.
    assert "innerHTML" not in hint
