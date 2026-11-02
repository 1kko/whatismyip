"""GET /?abuseipdb=only: AbuseIPDB for the visitor's own address, on request.

The self page never asks AbuseIPDB on its own: that would hand every visitor's
address to a third party unasked. The "Check with AbuseIPDB" button calls this
route, and only a press does. Every test runs over the fake transport of
test_abuseipdb.py, so none can spend the real quota.
"""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import lookup
import main
from test_abuseipdb import CURL, IP, OTHER, make_client
from viewmodel import reputation_view
import overview

BROWSER = {"user-agent": "Mozilla/5.0 (Macintosh) Safari/605.1.15"}
# Peer 127.0.0.1 is in TRUSTED_PROXIES, so x-real-ip names the visitor.
proxy = TestClient(main.app, client=("127.0.0.1", 41234))


def visitor(ip=IP, **headers):
    return {"x-real-ip": ip, **headers}


@pytest.fixture
def abuse(monkeypatch):
    def install(*responses):
        enabled = make_client(*responses)
        monkeypatch.setattr(lookup, "abuseipdb_client", enabled)
        monkeypatch.setattr(main, "abuseipdb_client", enabled)
        return enabled

    return install


@pytest.fixture(autouse=True)
def local_geo():
    location = AsyncMock(side_effect=lambda ip: {"ip": ip, "country_code": "DE"})
    with patch("main.lookup_location", location):
        yield


def test_press_checks_the_callers_own_address(abuse):
    api = abuse().api
    response = proxy.get("/?abuseipdb=only", headers=visitor(**CURL))
    assert response.status_code == 200
    assert api.asked() == [IP]
    body = response.json()
    assert body["address"] == IP
    assert body["reputation"]["level"] == "high"
    assert [s["id"] for s in body["reputation"]["signals"]] == ["abuseipdb"]


def test_query_address_is_ignored(abuse):
    api = abuse().api
    body = proxy.get(
        f"/?abuseipdb=only&ip={OTHER}&address={OTHER}", headers=visitor(**CURL)
    ).json()
    assert api.asked() == [IP]
    assert body["address"] == IP


def test_always_json_whatever_was_negotiated(abuse):
    abuse()
    response = proxy.get("/?abuseipdb=only&format=text", headers=visitor(**CURL))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")


def test_private_caller_is_not_asked(abuse):
    api = abuse().api
    body = proxy.get("/?abuseipdb=only", headers=visitor("192.168.1.5", **CURL)).json()
    assert api.calls == []
    assert body["address"] == "192.168.1.5"
    [reason] = body["reputation"]["unavailable"]
    assert "not a public address" in str(reason)


def test_disabled_is_400():
    response = proxy.get("/?abuseipdb=only", headers=visitor(**CURL))
    assert response.status_code == 400
    assert "AbuseIPDB is not configured" in response.text


def test_disabled_is_400_as_text():
    response = proxy.get("/?abuseipdb=only&format=text", headers=visitor(**CURL))
    assert response.status_code == 400
    assert response.headers["content-type"].startswith("text/plain")
    assert "AbuseIPDB is not configured" in response.text


@pytest.mark.parametrize("value", ["all", "", "yes"])
def test_bad_value_is_400(abuse, value):
    api = abuse().api
    response = proxy.get(f"/?abuseipdb={value}", headers=visitor(**CURL))
    assert response.status_code == 400
    assert "abuseipdb must be: only" in response.text
    assert api.calls == []


def test_bad_value_as_text_is_plain(abuse):
    abuse()
    response = proxy.get("/?abuseipdb=all&format=text", headers=visitor(**CURL))
    assert response.status_code == 400
    assert response.headers["content-type"].startswith("text/plain")
    assert "abuseipdb must be: only" in response.text


def test_display_matches_reputation_view(abuse):
    abuse()
    body = proxy.get("/?abuseipdb=only", headers=visitor(**CURL)).json()
    merged = body["reputation"]
    assert body["display"]["reputation"] == reputation_view(merged)
    assert body["display"]["card"] == overview.reputation_card(merged)
    assert body["display"]["chips"] == overview.reputation_chips(merged, is_ip=True)


def test_quota_spent_reads_unavailable_not_zero(abuse):
    abuse((429, {"x-ratelimit-remaining": "0"}, b""))
    body = proxy.get("/?abuseipdb=only", headers=visitor(**CURL)).json()
    assert body["reputation"]["score"] is None or body["reputation"]["score"] > 0
    assert body["reputation"]["unavailable"]
    assert body["display"]["card"]["value"] != "0"
    assert body["display"]["card"]["value"] == "?"


def test_cached_answer_is_reused(abuse):
    api = abuse().api
    first = proxy.get("/?abuseipdb=only", headers=visitor(**CURL)).json()
    second = proxy.get("/?abuseipdb=only", headers=visitor(**CURL)).json()
    assert len(api.calls) == 1
    assert first["reputation"] == second["reputation"]


def test_self_page_load_never_asks(abuse):
    api = abuse().api
    for headers in (CURL, BROWSER):
        proxy.get("/", headers=visitor(**headers))
    proxy.get("/?format=text", headers=visitor(**CURL))
    assert api.calls == []


def test_log_line(abuse, caplog):
    abuse()
    with caplog.at_level("INFO"):
        proxy.get("/?abuseipdb=only", headers=visitor(**CURL))
    assert f"client={IP} lookup={IP} (self, abuseipdb)" in caplog.text


def test_head_answers_json(abuse):
    api = abuse().api
    response = proxy.head("/?abuseipdb=only", headers=visitor(**BROWSER))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert api.calls == []
    assert proxy.head("/?abuseipdb=no", headers=visitor(**BROWSER)).status_code == 400


def test_whoami_caller_unchanged(abuse):
    from test_mcp import INIT, MCP_HEADERS, _rpc

    api = abuse().api
    with TestClient(main.app, client=(IP, 41234)) as client:
        client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch(
            "mcp_server.lookup_location",
            AsyncMock(return_value={"ip": IP, "country_code": "DE"}),
        ):
            response = _rpc(
                client, "tools/call", {"name": "whoami_caller", "arguments": {}}
            )
    assert response.status_code == 200
    assert api.calls == []


# --- the button --------------------------------------------------------------


@pytest.fixture
def reputation_on(monkeypatch):
    # The Reputation section exists only while the lists are on.
    monkeypatch.setattr(
        main,
        "ip_reputation",
        lambda ip, location=None: {
            "level": "none",
            "signals": [],
            "checked": [
                {
                    "id": "tor",
                    "label": "Tor exit",
                    "source": "Tor Project",
                    "as_of": "2026-11-02T00:00:00+00:00",
                }
            ],
            "attribution": [],
            "unavailable": [],
            "score": 0,
        },
    )


def page(path, abuse_on, **headers):
    return proxy.get(path, headers=visitor(**{**BROWSER, **headers})).text


def test_button_only_on_self_page_with_a_key(abuse, reputation_on, monkeypatch):
    abuse()
    with_key = page("/", True)
    assert 'id="abuseipdb-run"' in with_key
    assert "Check with AbuseIPDB" in with_key
    assert 'id="abuseipdb-status"' in with_key
    assert 'role="status"' in with_key
    assert "<noscript>" in with_key
    for path in ("/example.com", f"/{OTHER}"):
        assert 'id="abuseipdb-run"' not in page(path, True)
    monkeypatch.setattr(main, "abuseipdb_client", make_client())
    monkeypatch.setattr(main.abuseipdb_client, "enabled", False)
    assert 'id="abuseipdb-run"' not in page("/", False)


def test_button_needs_no_request_on_load(abuse, reputation_on):
    api = abuse().api
    page("/", True)
    assert api.calls == []


def test_app_js_writes_text_only():
    source = open("static/js/app.js").read()
    start = source.index("abuseipdb-run")
    handler = source[start : source.index("Look up subdomains", start)]
    assert "innerHTML" not in handler
    assert "insertAdjacentHTML" not in handler
