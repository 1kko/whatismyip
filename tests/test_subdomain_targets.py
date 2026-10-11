"""Which targets may reach the Certificate Transparency source at all.

crt.sh is queried as `%.{domain}`, so the target IS the query: a public suffix
asks for every subdomain of every domain under it, and a `%` in the target is a
wildcard of the caller's choosing. Either spends a slot of the global outbound
budget on a query crt.sh may answer by blocking this service's IP, which would
take the feature down for everyone. Three entry points could send one — the
HTTP gate, the MCP tool, and get_subdomains() itself — and every test here
asserts on the real fetcher, not just on a status code.
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import subdomains
from main import app, ip_ban_manager

JSON_UA = {"user-agent": "curl/8.0"}

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

GATHERED = {
    "address": "example.com",
    "domain": {"a": [{"ip": "93.184.216.34", "ttl": 300}], "mx": [], "ns": []},
    "location": {"country_code": "US", "country_name": "United States"},
    "whois": {"registrar": "Example Registrar"},
    "ssl": None,
    "resolved_ip": "93.184.216.34",
    "reverse_dns": None,
}

# The backlog's own list, plus the shapes that slip past a suffix-only check.
REJECTED = [
    "",
    "%",
    "com",
    "co.uk",
    "github.io",
    "%.com",
    "a%b.com",
    "*.example.com",
    "8.8.8.8",
    "2001:db8::1",
    "localhost",
    "example.notatld",
    "a..com",
    ".example.com",
    "-a.com",
    "a-.com",
    "a" * 64 + ".com",
    ".".join(["a"] * 126) + ".com",  # 255 characters
    "한국.kr",  # IDN must arrive as punycode
    # `_` is a single-character wildcard in a SQL LIKE pattern, and a
    # registered name can never contain one: "___.com" would ask for the
    # subdomains of every three-letter .com.
    "___.com",
    "a_b.com",
    "https://example.com",
    # On the public suffix list, so the suffix check alone lets them through,
    # and a Tor hidden service's name is not sent to crt.sh any more than to
    # the DNS (config.SPECIAL_USE_NAMES).
    "x.onion",
    "X.ONION.",
    "router.home.arpa",
]

# The route reduces a pasted URL to its host before the gate sees it (see
# normalize_lookup_target), so a URL is not a rejected target there.
HTTP_REJECTED = [
    target for target in REJECTED if "/" not in target and target.isascii()
]

ACCEPTED = [
    "example.com",
    "sub.example.co.uk",
    "xn--3e0b707e.kr",
    "foo.github.io",
    "_dmarc.example.com",
    "Example.COM.",
    # The special-use rule matches on a label boundary, and only those two
    # suffixes: the rest of .arpa is public, and a lookalike is a domain.
    "1.0.0.10.in-addr.arpa",
    "notonion.com",
    "x.onion.example.com",
]


def _rows(domain: str) -> list[dict]:
    return [{"name_value": f"www.{domain}", "common_name": None}]


def _path(target: str) -> str:
    """The target as a single path segment. An empty target cannot be one, so
    it travels as a space, which the route's normalization strips back off."""
    if not target:
        return "%20"
    return target.replace("%", "%25")


@pytest.fixture(autouse=True)
def isolated(tmp_path):
    """A throwaway subdomain store for each test."""
    subdomains.reset_state(store_path=str(tmp_path / "s.sqlite3"))
    yield
    subdomains.reset_state()


class TestInvalidTargetReason:
    @pytest.mark.parametrize("target", REJECTED)
    def test_rejects(self, target):
        assert subdomains.invalid_target_reason(target)

    @pytest.mark.parametrize("target", ACCEPTED)
    def test_accepts(self, target):
        assert subdomains.invalid_target_reason(target) is None

    def test_a_public_suffix_is_named_as_one(self):
        """A model reading "invalid domain" for `com` learns nothing it can act
        on; "is a public suffix" tells it to name a registered domain."""
        assert "public suffix" in subdomains.invalid_target_reason("co.uk")

    def test_the_length_limits_are_inclusive(self):
        label = "a" * 63
        assert subdomains.invalid_target_reason(f"{label}.com") is None
        # 63 + 1 + 63 + 1 + 63 + 1 + 57 + 4 = 253
        name = f"{label}.{label}.{label}.{'a' * 57}.com"
        assert len(name) == 253
        assert subdomains.invalid_target_reason(name) is None

    @pytest.mark.parametrize(
        ("target", "words"),
        [
            ("x.onion", "Tor onion address"),
            ("onion", "Tor onion address"),
            ("router.home.arpa", "home network"),
        ],
    )
    def test_a_special_use_name_is_named_as_one(self, target, words):
        """x.onion has a public suffix and passes every shape check, so this is
        the one rule that refuses it; like the suffix rule, the reason says
        why, so a model does not retry with another label."""
        reason = subdomains.invalid_target_reason(target)
        assert "special-use name" in reason
        assert words in reason

    @pytest.mark.parametrize("mark", ("\u200c", "\u200d", "\u1806"))
    @pytest.mark.parametrize(
        ("shape", "words"),
        [
            ("router.ho{0}me.arpa", "home network"),
            ("x.on{0}ion", "Tor onion address"),
            ("not{0}home.arpa", None),
        ],
    )
    def test_a_mark_idna2003_deletes_uses_the_wire_name(self, mark, shape, words):
        """The charset rule used to answer these first. A mark nameprep deletes
        inside home or onion is the special-use name; between not and home it
        is nothome.arpa, which is still not a name crt.sh may be asked."""
        reason = subdomains.invalid_target_reason(shape.format(mark))
        assert reason
        if words is None:
            assert "special-use name" not in reason
        else:
            assert "special-use name" in reason
            assert words in reason


class TestGetSubdomainsRefusesInvalidTargets:
    """The backstop: a future caller that forgets the gate still cannot send a
    wildcard or a suffix to the source, or spend a budget slot trying."""

    @pytest.mark.parametrize("target", REJECTED)
    async def test_never_fetches(self, target):
        with patch.object(subdomains, "_fetch_sync", side_effect=AssertionError) as f:
            result = await subdomains.get_subdomains(target)
        f.assert_not_called()
        assert result["error"]
        assert result["names"] == []
        assert not subdomains._budget._hits
        assert not subdomains._failures

    @pytest.mark.parametrize("target", ACCEPTED)
    async def test_still_fetches_a_valid_target(self, target):
        normalized = target.strip().lower().rstrip(".")
        with patch.object(
            subdomains, "_fetch_sync", return_value=_rows(normalized)
        ) as f:
            result = await subdomains.get_subdomains(target)
        f.assert_called_once_with(normalized)
        assert result["error"] is None
        assert result["names"] == [f"www.{normalized}"]


class TestHttpGate:
    client = TestClient(app)

    @pytest.mark.parametrize("target", HTTP_REJECTED)
    def test_only_is_a_400_and_never_fetches(self, target):
        gate = AsyncMock(wraps=subdomains.get_subdomains)
        with patch("main.get_subdomains", gate):
            with patch.object(
                subdomains, "_fetch_sync", side_effect=AssertionError
            ) as f:
                response = self.client.get(
                    f"/{_path(target)}?subdomains=only", headers=JSON_UA
                )
        assert response.status_code == 400
        assert response.json()["detail"]
        gate.assert_not_called()
        f.assert_not_called()
        # A bad query parameter on an ordinary-looking path is a mistake, not
        # a probe.
        assert not ip_ban_manager.is_banned("testclient")

    @pytest.mark.parametrize("target", HTTP_REJECTED)
    def test_include_skips_the_fetch_but_still_looks_up(self, target):
        """Same contract as an IP target: `include` is additive, so the lookup
        itself still answers, only without a subdomains fetch."""
        gate = AsyncMock(wraps=subdomains.get_subdomains)
        with patch("main.gather", new_callable=AsyncMock, return_value=GATHERED):
            with patch("main.get_subdomains", gate):
                with patch.object(
                    subdomains, "_fetch_sync", side_effect=AssertionError
                ) as f:
                    response = self.client.get(
                        f"/{_path(target)}?subdomains=include", headers=JSON_UA
                    )
        assert response.status_code == 200
        assert "subdomains" not in response.json()
        gate.assert_not_called()
        f.assert_not_called()

    @pytest.mark.parametrize(
        "target", ["example.com", "sub.example.co.uk", "xn--3e0b707e.kr"]
    )
    def test_only_still_answers_a_valid_target(self, target):
        with patch.object(subdomains, "_fetch_sync", return_value=_rows(target)) as f:
            response = self.client.get(f"/{target}?subdomains=only", headers=JSON_UA)
        assert response.status_code == 200
        assert response.json()["subdomains"]["names"] == [f"www.{target}"]
        f.assert_called_once_with(target)

    @pytest.mark.parametrize(
        "typed, canonical",
        [
            ("münchen.de", "xn--mnchen-3ya.de"),
            ("straße.de", "xn--strae-oqa.de"),
        ],
    )
    def test_an_idn_reaches_the_gate_as_its_a_label(self, typed, canonical):
        gate = AsyncMock(wraps=subdomains.get_subdomains)
        with patch("main.get_subdomains", gate):
            with patch.object(
                subdomains, "_fetch_sync", return_value=_rows(canonical)
            ) as fetch:
                response = self.client.get(f"/{typed}?subdomains=only", headers=JSON_UA)
        assert response.status_code == 200
        assert response.json()["address"] == canonical
        assert response.json()["subdomains"]["names"] == [f"www.{canonical}"]
        gate.assert_awaited_once_with(canonical)
        fetch.assert_called_once_with(canonical)


def _call_subdomains_tool(client, domain: str) -> dict:
    client.post("/mcp", json=MCP_INIT, headers=MCP_HEADERS)
    body = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "subdomains", "arguments": {"domain": domain}},
    }
    response = client.post("/mcp", json=body, headers=MCP_HEADERS)
    return response.json()["result"]["structuredContent"]


class TestMcpTool:
    @pytest.mark.parametrize("target", REJECTED)
    def test_rejects_with_an_error_never_an_empty_list(self, target):
        gate = AsyncMock(wraps=subdomains.get_subdomains)
        with TestClient(app) as client:
            with patch("mcp_server.get_subdomains", gate):
                with patch.object(
                    subdomains, "_fetch_sync", side_effect=AssertionError
                ) as f:
                    payload = _call_subdomains_tool(client, target)
        assert payload["error"]
        assert "names" not in payload
        gate.assert_not_called()
        f.assert_not_called()

    @pytest.mark.parametrize("target", ["example.com", "xn--3e0b707e.kr"])
    def test_still_answers_a_valid_target(self, target):
        with TestClient(app) as client:
            with patch.object(
                subdomains, "_fetch_sync", return_value=_rows(target)
            ) as f:
                payload = _call_subdomains_tool(client, target)
        assert "error" not in payload
        assert payload["names"] == [f"www.{target}"]
        f.assert_called_once_with(target)
