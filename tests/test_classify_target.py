"""A lookup target is classified before any network work starts.

gather() used to create the WHOIS task before it asked what the target was, so
"favicon.ico", "{target}" and anything else that reached /{domain_ip} went
through RDAP and port-43 WHOIS -- python-whois writes CR/LF into its query as
given -- and came back as an empty 200 page tagged DOMAIN. Those failures were
58 of the 61 ERROR log lines in 30 days of production logs.
"""

import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import lookup
import main
from main import app

API_UA = {"user-agent": "curl/8"}
BROWSER_UA = {"user-agent": "Mozilla/5.0 Chrome/120"}

INVALID_BODY = {"error": "not a domain name or IP address", "code": "invalid_target"}

client = TestClient(app, client=("8.8.8.8", 41234))


@contextlib.contextmanager
def _legs():
    """Patch every outbound leg a lookup can reach and hand back the mocks.

    lookup_whois is an AsyncMock so that merely creating the WHOIS task counts
    as a call: a task created and then cancelled might never reach RDAP, and a
    test watching only the lower levels would pass on exactly the ordering bug
    this file exists to catch.
    """
    resolver = MagicMock()
    resolver.resolve.return_value = ["93.184.216.34"]
    mocks = {
        "whois": AsyncMock(side_effect=lambda t: {"source": "rdap", "name": t}),
        "rdap": MagicMock(return_value=None),
        "port43": MagicMock(return_value=None),
        "resolver": MagicMock(return_value=resolver),
        "records": MagicMock(return_value={}),
        "reverse": MagicMock(return_value=None),
        "ssl": MagicMock(return_value=None),
        "subdomains": AsyncMock(return_value={"names": [], "count": 0}),
    }
    with (
        patch("lookup.lookup_whois", mocks["whois"]),
        patch("lookup.lookup_rdap", mocks["rdap"]),
        patch("lookup.whois.whois", mocks["port43"]),
        patch("lookup._recursive_resolver", mocks["resolver"]),
        patch.object(lookup.domain_manager, "get_records", mocks["records"]),
        patch.object(lookup.domain_manager, "perform_reverse_lookup", mocks["reverse"]),
        patch("managers.SSLManager.get_ssl_info", mocks["ssl"]),
        patch("main.get_subdomains", mocks["subdomains"]),
    ):
        yield mocks


def _assert_nothing_went_out(mocks):
    for name in ("whois", "rdap", "port43", "resolver", "records", "reverse", "ssl"):
        mocks[name].assert_not_called()


# --- classify_target: pure string work ----------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "example.com",
        "EXAMPLE.COM",
        "example.com.",  # the FQDN form
        "naver.co.kr",
        "_dmarc.example.com",  # service names carry underscores
        "xn--3e0b707e.kr",
        "한국.kr",  # an IDN, checked in its xn-- form
        "münchen.de",
    ],
)
def test_domains_classify_as_domain(target):
    assert lookup.classify_target(target) == "domain"


@pytest.mark.parametrize("target", ["8.8.8.8", "10.0.0.1", "169.254.169.254"])
def test_ipv4_literals_classify_as_ipv4(target):
    # Classification is not the safety check: a private address is still an
    # address, and is_safe_ip refuses it afterwards with its own message.
    assert lookup.classify_target(target) == "ipv4"


@pytest.mark.parametrize("target", ["2001:4860:4860::8888", "::1", "fe80::1"])
def test_ipv6_literals_classify_as_ipv6(target):
    assert lookup.classify_target(target) == "ipv6"


@pytest.mark.parametrize(
    "target",
    [
        "",
        "robots.txt",
        "favicon.ico",
        "{target}",
        "localhost",
        "test-xss",
        "999.1.1.1",
        # get_tld parses its input as a URL, so is_valid_domain says yes to
        # every one of these; none of them is a name DNS could be asked about.
        "foo bar.com",
        "example.com:443",
        "user@example.com",
        "*.example.com",
        "ex<a>mple.com",
        "%41.com",
        "a..b.com",
        "a" * 64 + ".com",
        ".".join(["a" * 60] * 5) + ".com",  # over 253 characters
    ],
)
def test_everything_else_is_invalid(target):
    assert lookup.classify_target(target) == "invalid"


@pytest.mark.parametrize(
    "target",
    [
        "foo\r\nbar.com",
        "foo\nbar.com",
        "foo\rbar.com",
        "foo\x00bar.com",
        "foo\tbar.com",
        "foo\x7fbar.com",
        "foo\x85bar.com",  # C1 control (NEL)
        "8.8.8.8\r\n",
        "example.com\r\nWHOIS-INJECTED",
    ],
)
def test_control_characters_are_invalid(target):
    assert lookup.classify_target(target) == "invalid"


# --- gather(): refused before any task exists ---------------------------------


@pytest.mark.parametrize("target", ["favicon.ico", "{target}", "foo\r\nbar.com"])
async def test_gather_refuses_an_invalid_target_before_any_lookup(target):
    with _legs() as mocks:
        with pytest.raises(lookup.InvalidTargetError) as raised:
            await lookup.gather(target)
    assert raised.value.code == "invalid_target"
    assert raised.value.message == "not a domain name or IP address"
    _assert_nothing_went_out(mocks)


# --- HTTP ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/%7Btarget%7D",
        "/foo%0D%0Abar.com",
        "/foo%20bar.com",
        "/localhost",
        "/test-xss",
        "/wpad.dat",
        "/example.com:443",
    ],
)
def test_invalid_target_is_a_400_with_no_outbound_call(path):
    with _legs() as mocks:
        response = client.get(path, headers=API_UA)
    assert response.status_code == 400
    assert response.json() == INVALID_BODY
    _assert_nothing_went_out(mocks)


def test_invalid_target_is_a_400_for_a_browser_too():
    # Status only: the body a browser gets is the HTML error page's to decide.
    with _legs() as mocks:
        response = client.get("/%7Btarget%7D", headers=BROWSER_UA)
    assert response.status_code == 400
    _assert_nothing_went_out(mocks)


def test_invalid_target_with_subdomains_include_contacts_nothing():
    with _legs() as mocks:
        response = client.get("/foo%20bar.com?subdomains=include", headers=API_UA)
    assert response.status_code == 400
    assert response.json() == INVALID_BODY
    _assert_nothing_went_out(mocks)
    mocks["subdomains"].assert_not_called()


@pytest.mark.parametrize("path", ["/::1", "/fe80::1"])
def test_a_private_ipv6_target_is_a_400_with_no_outbound_call(path):
    # IPv6 is looked up now (tests/test_ipv6.py), so a private one gets the
    # private-address 400 an IPv4 one does, before anything goes out.
    with _legs() as mocks:
        response = client.get(path, headers=API_UA)
    assert response.status_code == 400
    assert response.json() == {
        "detail": "Private or reserved IP addresses are not allowed"
    }
    _assert_nothing_went_out(mocks)


@pytest.mark.parametrize(
    "target",
    ["example.com", "EXAMPLE.com", "example.com.", "_dmarc.example.com", "8.8.8.8"],
)
def test_valid_targets_are_looked_up_as_before(target):
    with _legs() as mocks:
        response = client.get(f"/{target}", headers=API_UA)
    assert response.status_code == 200
    assert response.json()["address"] == target
    mocks["whois"].assert_called_once_with(target)


def test_private_address_keeps_its_own_400():
    with _legs() as mocks:
        response = client.get("/10.0.0.1", headers=API_UA)
    assert response.status_code == 400
    assert response.json() == {
        "detail": "Private or reserved IP addresses are not allowed"
    }
    _assert_nothing_went_out(mocks)


def test_invalid_targets_do_not_escalate_to_a_ban():
    # The 400 comes from the route, after the security middleware has already
    # let the request through; nothing reads the status back. Each request is
    # still one ordinary hit on the lookup rate limit, and no more.
    with _legs():
        statuses = [
            client.get("/%7Btarget%7D", headers=API_UA).status_code for _ in range(5)
        ]
        after = client.get("/example.com", headers=API_UA).status_code
    assert statuses == [400] * 5
    assert after == 200
    assert not main.ip_ban_manager.is_banned("8.8.8.8")


# --- self lookup from a private client ----------------------------------------


@pytest.mark.parametrize("peer", ["192.168.1.10", "10.1.2.3", "100.64.0.1", "::1"])
def test_self_lookup_from_a_private_client_skips_registries_and_ptr(peer):
    private_client = TestClient(app, client=(peer, 41234))
    with (
        patch("main.lookup_whois", new=AsyncMock(return_value={})) as whois_mock,
        patch.object(
            main.domain_manager, "perform_reverse_lookup", return_value=None
        ) as reverse_mock,
        patch.object(
            main.domain_manager, "get_records", return_value={}
        ) as records_mock,
    ):
        response = private_client.get("/", headers=API_UA)
    assert response.status_code == 200
    body = response.json()
    assert body["address"] == peer
    # Not looked up is not "no registration": say which it is.
    assert "private" in body["whois"]["error"]
    whois_mock.assert_not_called()
    reverse_mock.assert_not_called()
    records_mock.assert_not_called()


def test_self_lookup_from_a_public_client_still_asks():
    with (
        patch(
            "main.lookup_whois",
            new=AsyncMock(return_value={"source": "rdap", "name": "8.8.8.0/24"}),
        ) as whois_mock,
        patch.object(
            main.domain_manager, "perform_reverse_lookup", return_value=None
        ) as reverse_mock,
    ):
        response = client.get("/", headers=API_UA)
    assert response.status_code == 200
    assert response.json()["whois"]["source"] == "rdap"
    whois_mock.assert_called_once_with("8.8.8.8")
    reverse_mock.assert_called_once_with("8.8.8.8")


# --- MCP ----------------------------------------------------------------------

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "Host": "ip.1kko.com",
}
MCP_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2026-07-28",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}


def _call_tool(mcp_client, name, arguments):
    body = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    response = mcp_client.post("/mcp", json=body, headers=MCP_HEADERS)
    return response.json()["result"]["structuredContent"]


@pytest.mark.parametrize(
    "tool, argument",
    [("lookup", "target"), ("dns_records", "domain"), ("ssl_certificate", "domain")],
)
def test_mcp_tools_report_an_invalid_target_as_an_error(tool, argument):
    main.mcp_rate_limiter.request_history.clear()
    with TestClient(app) as mcp_client, _legs() as mocks:
        mcp_client.post("/mcp", json=MCP_INIT, headers=MCP_HEADERS)
        payload = _call_tool(mcp_client, tool, {argument: "foo\r\nbar.com"})
    assert payload == {"error": "not a domain name or IP address"}
    _assert_nothing_went_out(mocks)
