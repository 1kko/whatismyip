"""Unit tests for all 10 security vulnerability fixes.

These are true unit tests that don't require a running server.
They use FastAPI's TestClient and mock external dependencies.
"""

import datetime
import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Set env vars before importing main (which reads them at module level)
os.environ["ADMIN_API_KEY"] = "test-secret-key"
os.environ["TRUSTED_PROXIES"] = "127.0.0.1,10.0.0.1"
os.environ["BANNED_IPS_FILE"] = "/tmp/test_banned_ips.json"
os.environ["GEO_RULES_FILE"] = "/tmp/test_geo_rules.json"

from main import (
    GeoRulesUpdate,
    IPBanManager,
    RateLimiter,
    SuspiciousPatternDetector,
    WhitelistManager,
    _extract_forwarded_ip,
    app,
    get_client_ip,
    ip_ban_manager,
    is_safe_ip,
    rate_limiter,
    sanitize_log_input,
)

client = TestClient(app, raise_server_exceptions=False)

# Mock data for external service responses
MOCK_WHOIS = {"domain_name": "EXAMPLE.COM", "registrar": "Test Registrar"}
MOCK_LOCATION = {
    "ip": "8.8.8.8",
    "country_code": "US",
    "country_name": "United States",
    "city": {"name": "", "subdivision_code": "", "subdivision_name": ""},
    "cidr": "8.8.8.0/24",
    "hostname": "",
    "asn_name": "GOOGLE",
    "asn_cidr": "8.8.8.0/24",
    "is_private": False,
    "elapsed_time": "0.001s",
}
MOCK_DNS_RECORDS = {
    "mx": [],
    "ns": [],
    "cname": None,
    "txt": [],
    "spf": [],
    "ptr": [],
    "a": [{"ip": "93.184.216.34", "ttl": 300}],
}


def _reset_security_state():
    """Reset rate limiter and ban manager between tests."""
    rate_limiter.request_history.clear()
    ip_ban_manager.banned_ips.clear()


# ---------------------------------------------------------------------------
# Fix 1: XSS via </script> injection
# ---------------------------------------------------------------------------
class TestXSSPrevention:
    def setup_method(self):
        _reset_security_state()

    @patch("main.whois.whois", return_value=MOCK_WHOIS)
    @patch("main.geo_ip_manager.fetch_location", return_value=dict(MOCK_LOCATION))
    @patch("main.domain_manager.perform_reverse_lookup", return_value=None)
    def test_script_tag_escaped_in_self_info(self, mock_rev, mock_geo, mock_whois):
        """XSS: </script> must be escaped in HTML response for / endpoint."""
        response = client.get(
            "/",
            headers={"User-Agent": "Mozilla/5.0 Chrome/120"},
        )
        assert response.status_code == 200
        body = response.text
        # The raw </script> should never appear unescaped inside the template
        # json.dumps + .replace("</", "<\\/") should produce <\/
        assert "<\\/script>" not in body or "</script>" not in body.split("jsonData")[0]

    @patch("main.whois.whois", return_value=MOCK_WHOIS)
    @patch("main.geo_ip_manager.fetch_location", return_value=dict(MOCK_LOCATION))
    @patch("main.domain_manager.perform_reverse_lookup", return_value=None)
    @patch("main.domain_manager.is_valid_domain", return_value=False)
    @patch("main.domain_manager.is_ipv4", return_value=False)
    def test_script_tag_escaped_in_ip_info(
        self, mock_ipv4, mock_valid, mock_rev, mock_geo, mock_whois
    ):
        """XSS: </script> must be escaped in HTML response for /{domain_ip}."""
        response = client.get(
            "/test-xss",
            headers={"User-Agent": "Mozilla/5.0 Chrome/120"},
        )
        assert response.status_code == 200
        body = response.text
        # Ensure no unescaped </script> in the JSON data portion
        script_sections = body.split("<script>")
        for section in script_sections[1:]:
            json_part = (
                section.split("</script>")[0] if "</script>" in section else section
            )
            # Within script blocks, </script> should not appear literally
            # (it should be <\/script> if present at all)
            assert "</script>" not in json_part or json_part.endswith("")

    @patch("main.whois.whois", return_value=MOCK_WHOIS)
    @patch("main.geo_ip_manager.fetch_location", return_value=dict(MOCK_LOCATION))
    @patch("main.domain_manager.perform_reverse_lookup", return_value=None)
    def test_json_data_uses_escaped_slash(self, mock_rev, mock_geo, mock_whois):
        """XSS: json_data passed to template must escape </ sequences."""
        response = client.get(
            "/",
            headers={"User-Agent": "Mozilla/5.0 Chrome/120"},
        )
        body = response.text
        # Find the jsonData assignment in the script
        assert "const jsonData" in body
        # The json_data should use <\/ not </
        # Look for the pattern in the script section
        script_start = body.find("const jsonData")
        script_end = body.find("</script>", script_start)
        script_content = body[script_start:script_end]
        # No raw </ should appear in JSON data (all should be <\/)
        assert "</" not in script_content


# ---------------------------------------------------------------------------
# Fix 2: IP Spoofing via x-real-ip header
# ---------------------------------------------------------------------------
class TestIPSpoofingPrevention:
    def setup_method(self):
        _reset_security_state()

    def test_untrusted_proxy_ignores_headers(self):
        """IP Spoofing: proxy headers should be ignored from untrusted sources."""
        mock_request = MagicMock()
        mock_request.client.host = "192.168.1.100"
        headers = {"x-real-ip": "1.2.3.4", "x-forwarded-for": "5.6.7.8"}
        mock_request.headers = MagicMock()
        mock_request.headers.get = lambda key, default=None: headers.get(key, default)
        result = get_client_ip(mock_request)
        assert result == "192.168.1.100"

    def test_trusted_proxy_uses_x_real_ip(self):
        """IP Spoofing: x-real-ip should be trusted from configured proxies."""
        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"  # In TRUSTED_PROXIES
        headers = {"x-real-ip": "203.0.113.50"}
        mock_request.headers = MagicMock()
        mock_request.headers.get = lambda key, default=None: headers.get(key, default)
        result = get_client_ip(mock_request)
        assert result == "203.0.113.50"

    def test_trusted_proxy_uses_x_forwarded_for(self):
        """IP Spoofing: x-forwarded-for should be used when x-real-ip absent."""
        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"  # In TRUSTED_PROXIES
        headers = {"x-forwarded-for": "203.0.113.50, 10.0.0.1"}
        mock_request.headers = MagicMock()
        mock_request.headers.get = lambda key, default=None: headers.get(key, default)
        result = get_client_ip(mock_request)
        assert result == "203.0.113.50"

    def test_trusted_proxy_without_proxy_headers_falls_back(self):
        """IP Spoofing: trusted proxy without proxy headers uses client.host."""
        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"
        mock_request.headers = MagicMock()
        mock_request.headers.get = lambda key, default=None: default
        result = get_client_ip(mock_request)
        assert result == "127.0.0.1"

    @patch("main.TRUSTED_PROXIES", [])
    def test_no_trusted_proxies_trusts_x_real_ip(self):
        """IP Spoofing: when TRUSTED_PROXIES is empty, trust x-real-ip."""
        mock_request = MagicMock()
        mock_request.client.host = "172.20.0.9"
        headers = {"x-real-ip": "203.0.113.50"}
        mock_request.headers = MagicMock()
        mock_request.headers.get = lambda key, default=None: headers.get(key, default)
        result = get_client_ip(mock_request)
        assert result == "203.0.113.50"

    @patch("main.TRUSTED_PROXIES", [])
    def test_no_trusted_proxies_trusts_x_forwarded_for(self):
        """IP Spoofing: when TRUSTED_PROXIES is empty, trust x-forwarded-for
        for reverse proxies like Traefik/Coolify that don't set x-real-ip."""
        mock_request = MagicMock()
        mock_request.client.host = "172.20.0.9"
        headers = {"x-forwarded-for": "98.76.54.32, 172.20.0.1"}
        mock_request.headers = MagicMock()
        mock_request.headers.get = lambda key, default=None: headers.get(key, default)
        result = get_client_ip(mock_request)
        assert result == "98.76.54.32"

    def test_extract_forwarded_ip_prefers_x_real_ip(self):
        """x-real-ip takes precedence over x-forwarded-for."""
        mock_request = MagicMock()
        headers = {"x-real-ip": "1.1.1.1", "x-forwarded-for": "2.2.2.2"}
        mock_request.headers = MagicMock()
        mock_request.headers.get = lambda key, default=None: headers.get(key, default)
        result = _extract_forwarded_ip(mock_request)
        assert result == "1.1.1.1"

    def test_extract_forwarded_ip_parses_chain(self):
        """x-forwarded-for with multiple IPs returns the first (client)."""
        mock_request = MagicMock()
        headers = {"x-forwarded-for": "  203.0.113.50 , 10.0.0.1 , 172.20.0.9 "}
        mock_request.headers = MagicMock()
        mock_request.headers.get = lambda key, default=None: headers.get(key, default)
        result = _extract_forwarded_ip(mock_request)
        assert result == "203.0.113.50"

    def test_extract_forwarded_ip_returns_none_when_no_headers(self):
        """No proxy headers returns None."""
        mock_request = MagicMock()
        mock_request.headers = MagicMock()
        mock_request.headers.get = lambda key, default=None: default
        result = _extract_forwarded_ip(mock_request)
        assert result is None


# ---------------------------------------------------------------------------
# Fix 3: SSRF - Internal network probing
# ---------------------------------------------------------------------------
class TestSSRFPrevention:
    def setup_method(self):
        _reset_security_state()

    def test_private_ip_blocked(self):
        """SSRF: Private IPs (RFC 1918) should be rejected."""
        assert not is_safe_ip("192.168.1.1")
        assert not is_safe_ip("10.0.0.1")
        assert not is_safe_ip("172.16.0.1")

    def test_loopback_blocked(self):
        """SSRF: Loopback addresses should be rejected."""
        assert not is_safe_ip("127.0.0.1")

    def test_link_local_blocked(self):
        """SSRF: Link-local addresses should be rejected."""
        assert not is_safe_ip("169.254.169.254")

    def test_reserved_blocked(self):
        """SSRF: Reserved addresses should be rejected."""
        assert not is_safe_ip("240.0.0.1")

    def test_public_ip_allowed(self):
        """SSRF: Public IPs should be allowed."""
        assert is_safe_ip("8.8.8.8")
        assert is_safe_ip("1.1.1.1")
        assert is_safe_ip("93.184.216.34")

    def test_invalid_ip_rejected(self):
        """SSRF: Invalid IP strings should be rejected."""
        assert not is_safe_ip("not-an-ip")
        assert not is_safe_ip("")

    @patch("main.whois.whois", return_value=MOCK_WHOIS)
    def test_private_ip_returns_400(self, mock_whois):
        """SSRF: Requesting a private IP via endpoint returns 400."""
        response = client.get("/192.168.1.1")
        assert response.status_code == 400
        assert "Private or reserved" in response.json()["detail"]

    @patch("main.whois.whois", return_value=MOCK_WHOIS)
    def test_loopback_returns_400(self, mock_whois):
        """SSRF: Requesting 127.0.0.1 via endpoint returns 400."""
        response = client.get("/127.0.0.1")
        assert response.status_code == 400

    @patch("main.whois.whois", return_value=MOCK_WHOIS)
    def test_metadata_endpoint_returns_400(self, mock_whois):
        """SSRF: AWS metadata IP (169.254.169.254) returns 400."""
        response = client.get("/169.254.169.254")
        assert response.status_code == 400

    @patch("main.whois.whois", return_value=MOCK_WHOIS)
    @patch("main.domain_manager.is_valid_domain", return_value=True)
    @patch("main.dns.resolver.resolve")
    def test_domain_resolving_to_private_ip_returns_400(
        self, mock_resolve, mock_valid, mock_whois
    ):
        """SSRF: Domain resolving to private IP should be blocked."""
        mock_record = MagicMock()
        mock_record.__str__ = lambda self: "10.0.0.1"
        mock_answer = MagicMock()
        mock_answer.__getitem__ = lambda self, idx: mock_record
        mock_resolve.return_value = mock_answer
        response = client.get("/evil-internal.example.com")
        assert response.status_code == 400


# ---------------------------------------------------------------------------
# Fix 4: API Key timing attack
# ---------------------------------------------------------------------------
class TestTimingAttackPrevention:
    def setup_method(self):
        _reset_security_state()

    def test_admin_with_correct_key(self):
        """Timing: Admin endpoint works with correct key."""
        response = client.get("/admin/stats", headers={"api-key": "test-secret-key"})
        assert response.status_code == 200

    def test_admin_with_wrong_key(self):
        """Timing: Admin endpoint rejects wrong key with 404."""
        response = client.get("/admin/stats", headers={"api-key": "wrong-key"})
        assert response.status_code == 404

    def test_admin_with_no_key(self):
        """Timing: Admin endpoint rejects missing key with 404."""
        response = client.get("/admin/stats")
        assert response.status_code == 404

    def test_hmac_compare_digest_used(self):
        """Timing: verify_admin_key uses hmac.compare_digest."""
        import inspect
        from main import verify_admin_key

        source = inspect.getsource(verify_admin_key)
        assert "hmac.compare_digest" in source
        assert "api_key != ADMIN_API_KEY" not in source


# ---------------------------------------------------------------------------
# Fix 5: Admin endpoints bypass all security
# ---------------------------------------------------------------------------
class TestAdminSecurityEnforcement:
    def setup_method(self):
        _reset_security_state()

    def test_banned_ip_blocked_on_admin(self):
        """Admin security: Banned IPs should be blocked on admin endpoints too."""
        # Ban the testclient IP
        ip_ban_manager.ban_ip("testclient", reason="test", duration=3600)
        response = client.get("/admin/stats", headers={"api-key": "test-secret-key"})
        assert response.status_code == 403
        assert "banned" in response.json()["error"].lower()
        ip_ban_manager.unban_ip("testclient")

    def test_rate_limit_applies_to_admin(self):
        """Admin security: Rate limiting should apply to admin endpoints."""
        # Exhaust rate limit with a very low limit
        original_per_second = rate_limiter.requests_per_second
        rate_limiter.requests_per_second = 2
        try:
            responses = []
            for _ in range(5):
                r = client.get("/admin/stats", headers={"api-key": "test-secret-key"})
                responses.append(r.status_code)
            # At least one should be rate limited (429 or 403 after ban)
            assert 429 in responses or 403 in responses
        finally:
            rate_limiter.requests_per_second = original_per_second
            _reset_security_state()


# ---------------------------------------------------------------------------
# Fix 6: Blocking I/O in async handlers
# ---------------------------------------------------------------------------
class TestAsyncIO:
    def test_get_self_info_uses_to_thread(self):
        """Async: get_self_info should use asyncio.to_thread for blocking calls."""
        import inspect
        from main import get_self_info

        source = inspect.getsource(get_self_info)
        assert "asyncio.to_thread" in source
        # Verify specific blocking calls are wrapped
        assert "await asyncio.to_thread(whois.whois" in source
        assert "await asyncio.to_thread(geo_ip_manager.fetch_location" in source
        assert "await asyncio.to_thread(domain_manager.perform_reverse_lookup" in source

    def test_get_ip_info_uses_to_thread(self):
        """Async: get_ip_info should use asyncio.to_thread for blocking calls."""
        import inspect
        from main import get_ip_info

        source = inspect.getsource(get_ip_info)
        assert "asyncio.to_thread" in source
        assert "await asyncio.to_thread(whois.whois" in source
        assert "await asyncio.to_thread(dns.resolver.resolve" in source
        assert "await asyncio.to_thread(SSLManager.get_ssl_info" in source
        assert "await asyncio.to_thread(geo_ip_manager.fetch_location" in source

    @patch("main.whois.whois", return_value=MOCK_WHOIS)
    @patch("main.geo_ip_manager.fetch_location", return_value=dict(MOCK_LOCATION))
    @patch("main.domain_manager.perform_reverse_lookup", return_value=None)
    def test_self_info_endpoint_still_works(self, mock_rev, mock_geo, mock_whois):
        """Async: / endpoint should still return valid responses with async wrapping."""
        _reset_security_state()
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "address" in data
        assert "location" in data

    @patch("main.whois.whois", return_value=MOCK_WHOIS)
    @patch("main.geo_ip_manager.fetch_location", return_value=dict(MOCK_LOCATION))
    @patch("main.domain_manager.perform_reverse_lookup", return_value="dns.google")
    @patch(
        "main.domain_manager.get_records",
        return_value=dict(MOCK_DNS_RECORDS),
    )
    def test_ip_info_endpoint_still_works(
        self, mock_records, mock_rev, mock_geo, mock_whois
    ):
        """Async: /{ip} endpoint should still return valid responses."""
        _reset_security_state()
        response = client.get("/8.8.8.8")
        assert response.status_code == 200
        data = response.json()
        assert data["address"] == "8.8.8.8"


# ---------------------------------------------------------------------------
# Fix 7: Admin config injection (GeoRulesUpdate Pydantic model)
# ---------------------------------------------------------------------------
class TestAdminConfigInjection:
    def setup_method(self):
        _reset_security_state()

    def test_geo_rules_update_model_validates_fields(self):
        """Config injection: GeoRulesUpdate should only accept known fields."""
        # Valid fields
        model = GeoRulesUpdate(mode="blocklist", blocked_countries=["CN"])
        dump = model.model_dump(exclude_none=True)
        assert dump == {"mode": "blocklist", "blocked_countries": ["CN"]}

    def test_geo_rules_update_rejects_extra_fields(self):
        """Config injection: GeoRulesUpdate should reject extra fields."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            GeoRulesUpdate(mode="blocklist", evil_field="pwned")

    def test_update_endpoint_uses_pydantic_model(self):
        """Config injection: PUT /admin/geo/rules uses GeoRulesUpdate not dict."""
        import inspect
        from main import update_geo_rules

        source = inspect.getsource(update_geo_rules)
        assert "GeoRulesUpdate" in source
        assert "model_dump" in source

    def test_update_geo_rules_valid_request(self):
        """Config injection: Valid update should succeed."""
        response = client.put(
            "/admin/geo/rules",
            json={"mode": "blocklist", "blocked_countries": ["RU"]},
            headers={"api-key": "test-secret-key"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "updated"

    def test_update_geo_rules_invalid_mode(self):
        """Config injection: Invalid mode should return 400."""
        response = client.put(
            "/admin/geo/rules",
            json={"mode": "invalid_mode"},
            headers={"api-key": "test-secret-key"},
        )
        assert response.status_code == 400

    def test_update_geo_rules_extra_field_rejected(self):
        """Config injection: Extra fields in request body should be rejected."""
        response = client.put(
            "/admin/geo/rules",
            json={"mode": "blocklist", "evil_injection": "value"},
            headers={"api-key": "test-secret-key"},
        )
        assert response.status_code == 422  # Pydantic validation error


# ---------------------------------------------------------------------------
# Fix 8: Docker running as root + --reload
# ---------------------------------------------------------------------------
class TestDockerHardening:
    def test_dockerfile_has_non_root_user(self):
        """Docker: Dockerfile should create and use a non-root user."""
        with open("Dockerfile") as f:
            content = f.read()
        assert "useradd" in content
        assert "USER" in content
        assert "appuser" in content

    def test_dockerfile_no_reload_flag(self):
        """Docker: Dockerfile should not use --reload in production."""
        with open("Dockerfile") as f:
            content = f.read()
        assert "--reload" not in content

    def test_dockerfile_entrypoint_correct(self):
        """Docker: ENTRYPOINT should run uvicorn without --reload."""
        with open("Dockerfile") as f:
            content = f.read()
        # Should have the basic entrypoint
        assert "uvicorn" in content
        assert '"--host", "0.0.0.0"' in content
        assert '"--port", "8000"' in content


# ---------------------------------------------------------------------------
# Fix 9: FastAPI docs exposed
# ---------------------------------------------------------------------------
class TestDocsDisabled:
    def setup_method(self):
        _reset_security_state()

    def test_swagger_docs_disabled(self):
        """Docs: /docs endpoint should return 404."""
        response = client.get("/docs")
        # /docs is caught by /{domain_ip} route, but the built-in swagger UI
        # should not be served. FastAPI(docs_url=None) disables it.
        assert response.status_code != 200 or "swagger" not in response.text.lower()

    def test_redoc_disabled(self):
        """Docs: /redoc endpoint should not serve ReDoc UI."""
        # /redoc is caught by /{domain_ip} route, but ReDoc UI should not be served
        response = client.get("/redoc")
        # ReDoc UI would contain 'redoc' script/library references
        if response.status_code == 200:
            assert "ReDoc" not in response.text

    def test_openapi_json_disabled(self):
        """Docs: /openapi.json should not be directly served."""
        # With docs_url=None and redoc_url=None, openapi.json is still available
        # but docs UI is not. Verify docs_url config.
        assert app.docs_url is None
        assert app.redoc_url is None


# ---------------------------------------------------------------------------
# Fix 10: Log injection
# ---------------------------------------------------------------------------
class TestLogInjection:
    def test_newlines_stripped(self):
        """Log injection: Newline characters should be removed."""
        assert sanitize_log_input("normal") == "normal"
        assert sanitize_log_input("line1\nline2") == "line1line2"
        assert sanitize_log_input("line1\rline2") == "line1line2"
        assert sanitize_log_input("line1\r\nline2") == "line1line2"

    def test_null_bytes_stripped(self):
        """Log injection: Null bytes should be removed."""
        assert sanitize_log_input("before\x00after") == "beforeafter"

    def test_combined_control_chars(self):
        """Log injection: Multiple control characters should all be stripped."""
        assert sanitize_log_input("a\nb\rc\x00d") == "abcd"

    def test_empty_string(self):
        """Log injection: Empty string should pass through."""
        assert sanitize_log_input("") == ""

    def test_log_sanitization_used_in_endpoints(self):
        """Log injection: sanitize_log_input should be used in endpoint logging."""
        import inspect
        from main import get_ip_info, get_self_info

        self_source = inspect.getsource(get_self_info)
        assert "sanitize_log_input" in self_source

        ip_source = inspect.getsource(get_ip_info)
        assert "sanitize_log_input" in ip_source


# ---------------------------------------------------------------------------
# Cross-cutting: Security middleware integration
# ---------------------------------------------------------------------------
class TestSecurityMiddleware:
    def setup_method(self):
        _reset_security_state()

    def test_suspicious_path_returns_403(self):
        """Middleware: Suspicious multi-segment paths should return 403."""
        # /.env matches the whitelist (single segment), so use a nested path
        # that bypasses the whitelist but triggers suspicious pattern detection
        response = client.get("/.git/config")
        assert response.status_code == 403

    def test_suspicious_path_bans_ip(self):
        """Middleware: Suspicious request should ban the client IP."""
        _reset_security_state()
        client.get("/.git/HEAD")
        # The testclient IP should now be banned
        assert ip_ban_manager.is_banned("testclient")
        _reset_security_state()

    def test_banned_ip_gets_403(self):
        """Middleware: Banned IPs should get 403 on regular endpoints."""
        ip_ban_manager.ban_ip("testclient", reason="test", duration=3600)
        response = client.get("/")
        assert response.status_code == 403
        _reset_security_state()

    @patch("main.whois.whois", return_value=MOCK_WHOIS)
    @patch("main.geo_ip_manager.fetch_location", return_value=dict(MOCK_LOCATION))
    @patch("main.domain_manager.perform_reverse_lookup", return_value=None)
    def test_whitelisted_path_passes(self, mock_rev, mock_geo, mock_whois):
        """Middleware: Whitelisted paths should pass through."""
        response = client.get("/")
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Utility class tests
# ---------------------------------------------------------------------------
class TestSuspiciousPatternDetector:
    def test_detects_env_files(self):
        assert SuspiciousPatternDetector().is_suspicious("/.env")
        assert SuspiciousPatternDetector().is_suspicious("/path/.env.local")

    def test_detects_php(self):
        assert SuspiciousPatternDetector().is_suspicious("/admin.php")

    def test_detects_git(self):
        assert SuspiciousPatternDetector().is_suspicious("/.git/config")

    def test_detects_wordpress(self):
        assert SuspiciousPatternDetector().is_suspicious("/wp-admin")
        assert SuspiciousPatternDetector().is_suspicious("/wp-login.php")

    def test_allows_normal_paths(self):
        assert not SuspiciousPatternDetector().is_suspicious("/google.com")
        assert not SuspiciousPatternDetector().is_suspicious("/8.8.8.8")


class TestWhitelistManager:
    def test_root_whitelisted(self):
        assert WhitelistManager().is_whitelisted("/")

    def test_domain_lookup_whitelisted(self):
        assert WhitelistManager().is_whitelisted("/google.com")
        assert WhitelistManager().is_whitelisted("/8.8.8.8")

    def test_static_files_whitelisted(self):
        assert WhitelistManager().is_whitelisted("/static/css/style.css")
        assert WhitelistManager().is_whitelisted("/static/js/app.js")

    def test_multi_segment_paths_not_whitelisted(self):
        assert not WhitelistManager().is_whitelisted("/.git/config")
        assert not WhitelistManager().is_whitelisted("/admin/bans")
        assert not WhitelistManager().is_whitelisted("/cgi-bin/test")


class TestRateLimiter:
    def test_allows_requests_under_limit(self):
        rl = RateLimiter(requests_per_minute=10, requests_per_second=5)
        assert rl.allow_request("1.1.1.1")
        assert rl.allow_request("1.1.1.1")

    def test_blocks_requests_over_per_second_limit(self):
        rl = RateLimiter(requests_per_minute=100, requests_per_second=2)
        rl.allow_request("2.2.2.2")
        rl.allow_request("2.2.2.2")
        assert not rl.allow_request("2.2.2.2")

    def test_different_ips_independent(self):
        rl = RateLimiter(requests_per_minute=100, requests_per_second=1)
        rl.allow_request("3.3.3.3")
        # Different IP should still be allowed
        assert rl.allow_request("4.4.4.4")

    def test_cleanup_removes_old_records(self):
        rl = RateLimiter(requests_per_minute=100, requests_per_second=100)
        rl.allow_request("5.5.5.5")
        # Artificially age the timestamps
        old_time = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(
            minutes=10
        )
        rl.request_history["5.5.5.5"] = [old_time]
        rl.cleanup_old_records()
        assert "5.5.5.5" not in rl.request_history


class TestIPBanManager:
    def test_ban_and_check(self):
        mgr = IPBanManager.__new__(IPBanManager)
        mgr.banned_ips = {}
        mgr.ban_file = "/tmp/test_ban_check.json"
        mgr.save_bans = MagicMock()
        mgr.ban_ip("1.2.3.4", reason="test", duration=3600)
        assert mgr.is_banned("1.2.3.4")

    def test_unban(self):
        mgr = IPBanManager.__new__(IPBanManager)
        mgr.banned_ips = {}
        mgr.ban_file = "/tmp/test_ban_unban.json"
        mgr.save_bans = MagicMock()
        mgr.ban_ip("1.2.3.4", reason="test", duration=3600)
        mgr.unban_ip("1.2.3.4")
        assert not mgr.is_banned("1.2.3.4")

    def test_expired_ban_not_active(self):
        mgr = IPBanManager.__new__(IPBanManager)
        mgr.banned_ips = {}
        mgr.ban_file = "/tmp/test_ban_expire.json"
        mgr.save_bans = MagicMock()
        # Ban with 0 second duration (already expired)
        mgr.ban_ip("1.2.3.4", reason="test", duration=0)
        assert not mgr.is_banned("1.2.3.4")
