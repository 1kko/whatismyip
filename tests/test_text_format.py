"""Shell-sized answers: `?format=text` and `?fields=` on the lookup routes.

`curl ip.1kko.com` used to wait on WHOIS, reverse DNS, the DNS sweep and the map
projection just to print one address, and there was no way to ask for a single
value. `/?format=text` is now the address and a newline with no lookup at all,
`/{target}?format=text` a short `key: value` block, and `?fields=` runs only the
legs the named fields need.

Every outbound leg is mocked; each test asserts which of them ran.
"""

import contextlib
import copy
import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import pytest
from fastapi.testclient import TestClient

import lookup
import main
import managers
import textfmt
from main import app
from managers import _asn1_time

CLIENT_IP = "8.8.8.8"
client = TestClient(app, client=(CLIENT_IP, 41234))

CURL = {"user-agent": "curl/8.7.1"}
CHROME = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}

DOMAIN_IP = "93.184.216.34"
LOCATIONS = {
    DOMAIN_IP: {
        "ip": DOMAIN_IP,
        "country_code": "US",
        "country_name": "United States",
        "city_name": "Los Angeles",
        "cidr": "93.184.216.0/24",
        "asn_name": "Edgecast Inc.",
        "asn_cidr": "93.184.216.0/22",
        "asn_number": 15133,
        "is_private": False,
    },
    CLIENT_IP: {
        "ip": CLIENT_IP,
        "country_code": "US",
        "country_name": "United States",
        "city_name": "Mountain View",
        "cidr": "8.8.8.0/24",
        "asn_name": "Google LLC",
        "asn_cidr": "8.8.8.0/24",
        "asn_number": 15169,
        "is_private": False,
    },
}
REGISTRATIONS = {
    "example.com": {
        "source": "rdap",
        "name": "example.com",
        "registrar": "Example Registrar",
        "registrant": "Example Org",
        "expires": datetime.datetime(2027, 7, 31, 14, 55, tzinfo=datetime.UTC),
    },
    CLIENT_IP: {"source": "rdap", "name": "GOGL", "registrant": "Google LLC"},
}
CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("organizationName", "Let's Encrypt"),),),
    "notAfter": "Nov  9 23:22:58 2099 GMT",
    "protocol": "TLSv1.3",
}

DOMAIN_KEYS = [
    "target",
    "ip",
    "country_code",
    "country_name",
    "city",
    "asn_number",
    "asn_name",
    "cidr",
    "registrar",
    "registrant",
    "domain_expires",
    "domain_age_days",
    "cert_issuer",
    "cert_expires",
    "cert_days_remaining",
    "cert_age_days",
]
IP_KEYS = [
    "target",
    "ip",
    "reverse_dns",
    "country_code",
    "country_name",
    "city",
    "asn_number",
    "asn_name",
    "cidr",
    "registrant",
]


@contextlib.contextmanager
def _legs(a_record=DOMAIN_IP):
    """Patch every leg a lookup can reach, on both the gather() path and the
    self-lookup path in main, and hand back the mocks.

    The WHOIS and GeoIP entry points are AsyncMocks shared between lookup and
    main, so creating the task at all counts as a call wherever it happens.
    GeoIP is patched at lookup_location rather than the database: the security
    middleware's geo-blocking check reads the database on every request, and
    that is the middleware's, not the lookup's.
    """
    resolver = MagicMock()
    resolver.resolve.return_value = [a_record]
    mocks = {
        "whois": AsyncMock(side_effect=lambda t: copy.deepcopy(REGISTRATIONS[t])),
        "geo": AsyncMock(side_effect=lambda ip: copy.deepcopy(LOCATIONS[ip])),
        "resolver": MagicMock(return_value=resolver),
        "records": MagicMock(return_value={}),
        "reverse": MagicMock(return_value="dns.google"),
        "ssl": MagicMock(return_value=copy.deepcopy(CERT)),
        "subdomains": AsyncMock(return_value={"names": [], "count": 0}),
    }
    with (
        patch("lookup.lookup_whois", mocks["whois"]),
        patch("main.lookup_whois", mocks["whois"]),
        patch("lookup.lookup_location", mocks["geo"]),
        patch("main.lookup_location", mocks["geo"]),
        patch("lookup._recursive_resolver", mocks["resolver"]),
        patch.object(lookup.domain_manager, "get_records", mocks["records"]),
        patch.object(lookup.domain_manager, "perform_reverse_lookup", mocks["reverse"]),
        patch("managers.SSLManager.get_ssl_info", mocks["ssl"]),
        patch("main.get_subdomains", mocks["subdomains"]),
    ):
        yield mocks


OUTBOUND = ("whois", "geo", "resolver", "records", "reverse", "ssl")


def _ran(mocks):
    """The legs that were called, by name."""
    return {name for name in OUTBOUND if mocks[name].called}


def _is_text(response):
    return response.headers["content-type"].startswith("text/plain")


def _block(response):
    """A `key: value` body as an ordered list of pairs."""
    assert response.text.endswith("\n")
    return [line.split(": ", 1) for line in response.text.splitlines()]


# --- GET / ----------------------------------------------------------------------


class TestSelfText:
    def test_format_text_is_the_address_and_a_newline_with_no_lookup(self):
        with _legs() as mocks:
            response = client.get("/?format=text", headers=CURL)
        assert response.status_code == 200
        assert _is_text(response)
        assert response.text == "8.8.8.8\n"
        assert _ran(mocks) == set()

    def test_accept_text_plain_is_the_same(self):
        with _legs() as mocks:
            response = client.get("/", headers={**CHROME, "accept": "text/plain"})
        assert response.status_code == 200
        assert _is_text(response)
        assert response.text == "8.8.8.8\n"
        assert _ran(mocks) == set()

    def test_a_proxied_client_gets_its_own_address(self):
        proxied = TestClient(app, client=("127.0.0.1", 41234))
        with _legs():
            response = proxied.get(
                "/?format=text", headers={**CURL, "x-real-ip": "1.1.1.1"}
            )
        assert response.text == "1.1.1.1\n"

    def test_it_is_still_rate_limited_like_any_lookup(self):
        """Settled policy: the lookup surface is rate limited whatever it costs,
        and ?format= is a query parameter the middleware never reads."""
        with _legs():
            client.get("/?format=text", headers=CURL)
        assert len(main.rate_limiter.request_history[CLIENT_IP]) == 1

    def test_the_cache_headers_still_apply(self):
        with _legs():
            response = client.get("/?format=text", headers=CURL)
        vary = {t.strip().lower() for t in response.headers["vary"].split(",")}
        assert {"accept", "user-agent"} <= vary
        assert response.headers["cache-control"] == "no-store"


# --- GET /{target}?format=text ---------------------------------------------------


class TestTargetText:
    def test_a_domain_answers_the_domain_block(self):
        with _legs():
            response = client.get("/example.com?format=text", headers=CURL)
        assert response.status_code == 200
        assert _is_text(response)
        block = _block(response)
        assert [key for key, _ in block] == DOMAIN_KEYS
        values = dict(block)
        assert values == {
            **values,
            "target": "example.com",
            "ip": DOMAIN_IP,
            "country_code": "US",
            "country_name": "United States",
            "city": "Los Angeles",
            "asn_number": "15133",
            "asn_name": "Edgecast Inc.",
            "cidr": "93.184.216.0/22",
            "registrar": "Example Registrar",
            "registrant": "Example Org",
            "domain_expires": "2027-07-31",
            "cert_issuer": "Let's Encrypt",
            "cert_expires": "2099-11-09",
        }
        assert int(values["cert_days_remaining"]) > 0

    def test_an_ip_answers_the_ip_block(self):
        with _legs():
            response = client.get("/8.8.8.8?format=text", headers=CURL)
        assert response.status_code == 200
        block = _block(response)
        assert [key for key, _ in block] == IP_KEYS
        assert dict(block)["reverse_dns"] == "dns.google"
        assert dict(block)["registrant"] == "Google LLC"

    def test_the_block_skips_the_record_sweep_and_crt_sh(self):
        """Nothing in the block comes from the MX/NS/TXT sweep or from CT logs,
        so neither is paid for -- ?subdomains=include included."""
        with _legs() as mocks:
            client.get("/example.com?format=text&subdomains=include", headers=CURL)
            client.get("/8.8.8.8?format=text", headers=CURL)
        mocks["records"].assert_not_called()
        mocks["subdomains"].assert_not_called()

    def test_a_missing_value_is_a_dash(self):
        with _legs() as mocks:
            mocks["ssl"].return_value = None
            mocks["geo"].side_effect = lambda ip: {"ip": ip, "city_name": ""}
            response = client.get("/example.com?format=text", headers=CURL)
        values = dict(_block(response))
        assert values["city"] == "-"
        assert values["asn_number"] == "-"
        assert values["cert_issuer"] == "-"
        assert values["cert_days_remaining"] == "-"

    def test_a_failed_registration_lookup_is_a_question_mark_not_a_dash(self):
        """`-` says there is nothing there; a timeout says nothing of the kind."""
        with _legs() as mocks:
            mocks["whois"].side_effect = lambda t: {"error": "WHOIS lookup timed out"}
            failed = dict(_block(client.get("/example.com?format=text", headers=CURL)))
            mocks["whois"].side_effect = lambda t: {"error": "not registered"}
            unregistered = dict(
                _block(client.get("/example.com?format=text", headers=CURL))
            )
        assert failed["registrar"] == "?"
        assert failed["domain_expires"] == "?"
        assert unregistered["registrar"] == "-"
        assert unregistered["domain_expires"] == "-"

    def test_a_thin_whois_record_is_a_dash_not_a_question_mark(self):
        with _legs() as mocks:
            mocks["whois"].side_effect = lambda target: {
                "source": "whois",
                "name": target,
                "thin": True,
            }
            text = dict(_block(client.get("/nic.ch?format=text", headers=CURL)))
            path = "/nic.ch?fields=registrar,domain_expires"
            fields = client.get(path, headers=CURL)
        assert text["registrar"] == "-"
        assert text["domain_expires"] == "-"
        assert fields.json() == {"registrar": None, "domain_expires": None}

    def test_a_value_cannot_break_the_line_structure(self):
        """Registration data is whatever a registry sent. A newline in it would
        forge another key, and an escape sequence would reach the terminal."""
        hostile = {"source": "whois", "registrant": "Evil\nip: 6.6.6.6\x1b[2J Corp"}
        with _legs() as mocks:
            mocks["whois"].side_effect = lambda t: hostile
            response = client.get("/example.com?format=text", headers=CURL)
        block = _block(response)
        assert [key for key, _ in block] == DOMAIN_KEYS
        assert dict(block)["registrant"] == "Evil ip: 6.6.6.6 [2J Corp"
        assert "\x1b" not in response.text

    @pytest.mark.parametrize(
        ("path", "line"),
        [
            ("/localhost", "error: not a domain name or IP address\n"),
            (
                "/user@example.com",
                "error: looks like an email address; enter the domain after the @\n",
            ),
            (
                "/10.0.0.1",
                "error: 10.0.0.1 is in 10.0.0.0/8, private-use network (RFC 1918), "
                "not a public address\n",
            ),
            (
                "/::1",
                "error: ::1 is in ::1/128, loopback (RFC 4291), not a public address\n",
            ),
        ],
    )
    def test_errors_are_one_line_of_text_with_the_same_status(self, path, line):
        with _legs() as mocks:
            response = client.get(f"{path}?format=text", headers=CURL)
        assert response.status_code == 400
        assert _is_text(response)
        assert response.text == line
        assert _ran(mocks) == set()

    def test_a_bad_subdomains_value_answers_text_too(self):
        with _legs():
            response = client.get("/example.com?format=text&subdomains=1", headers=CURL)
        assert response.status_code == 400
        assert response.text.startswith("error: subdomains must be one of")

    def test_json_errors_keep_detail_and_name_the_block(self):
        with _legs():
            invalid = client.get("/localhost", headers=CURL)
            private = client.get("/10.0.0.1", headers=CURL)
        assert invalid.json() == {
            "error": "not a domain name or IP address",
            "code": "invalid_target",
        }
        assert private.json() == {
            "detail": "Private or reserved IP addresses are not allowed",
            "error": (
                "10.0.0.1 is in 10.0.0.0/8, private-use network (RFC 1918), "
                "not a public address"
            ),
            "code": "private",
        }

    def test_fields_on_a_refused_address_carries_the_block_too(self):
        """?fields= goes through _target_fields, a different except block from
        get_ip_info's; the answer must be the same 400."""
        with _legs() as mocks:
            response = client.get("/100.64.0.1?fields=ip,asn_number", headers=CURL)
        assert response.status_code == 400
        body = response.json()
        assert body["detail"] == "Private or reserved IP addresses are not allowed"
        assert body["code"] == "cgnat"
        assert "RFC 6598" in body["error"]
        assert _ran(mocks) == set()


# --- ?fields= --------------------------------------------------------------------


class TestFieldsValidation:
    @pytest.mark.parametrize("path", ["/", "/example.com"])
    def test_an_unknown_field_is_a_400_invalid_field(self, path):
        with _legs() as mocks:
            response = client.get(f"{path}?fields=ip,bogus", headers=CURL)
        assert response.status_code == 400
        body = response.json()
        assert body["code"] == "invalid_field"
        assert "bogus" in body["error"]
        # The answer names what is valid, so the fix is in the error itself.
        assert "country_code" in body["error"]
        assert _ran(mocks) == set()

    @pytest.mark.parametrize("path", ["/", "/example.com"])
    def test_a_text_client_gets_the_error_as_text(self, path):
        with _legs() as mocks:
            response = client.get(f"{path}?fields=bogus&format=text", headers=CURL)
        assert response.status_code == 400
        assert _is_text(response)
        assert response.text.startswith("error: unknown field: bogus")
        assert response.text.count("\n") == 1
        assert _ran(mocks) == set()

    @pytest.mark.parametrize("query", ["fields=", "fields=,", "fields=%20"])
    def test_asking_for_no_field_is_a_400(self, query):
        with _legs():
            response = client.get(f"/example.com?{query}", headers=CURL)
        assert response.status_code == 400
        assert response.json()["code"] == "invalid_field"

    def test_an_invalid_field_is_refused_before_the_target_is(self):
        """One request, two problems: the field is the one the caller can fix
        without knowing anything about the target."""
        with _legs():
            response = client.get("/localhost?fields=bogus", headers=CURL)
        assert response.json()["code"] == "invalid_field"

    def test_names_ignore_case_and_surrounding_space(self):
        with _legs():
            response = client.get(
                "/example.com?fields=IP,%20Country_Code", headers=CURL
            )
        assert response.json() == {"ip": DOMAIN_IP, "country_code": "US"}


class TestFieldsOutput:
    def test_json_is_a_flat_object_of_just_those_fields(self):
        with _legs():
            response = client.get(
                "/example.com?fields=ip,country_code,asn_number", headers=CURL
            )
        assert response.status_code == 200
        assert response.json() == {
            "ip": DOMAIN_IP,
            "country_code": "US",
            "asn_number": 15133,
        }

    def test_text_is_one_value_per_line_in_the_order_asked(self):
        with _legs():
            response = client.get(
                "/example.com?fields=asn_number,ip&format=text", headers=CURL
            )
        assert _is_text(response)
        assert response.text == f"15133\n{DOMAIN_IP}\n"

    def test_one_field_is_one_line(self):
        with _legs():
            response = client.get("/?fields=country_code&format=text", headers=CURL)
        assert response.text == "US\n"

    def test_a_browser_gets_json_not_the_page(self):
        with _legs():
            response = client.get("/example.com?fields=ip", headers=CHROME)
        assert response.headers["content-type"].startswith("application/json")
        assert response.json() == {"ip": DOMAIN_IP}

    def test_a_failed_lookup_is_null_with_the_reason_alongside(self):
        with _legs() as mocks:
            mocks["whois"].side_effect = lambda t: {"error": "WHOIS lookup timed out"}
            response = client.get("/example.com?fields=ip,registrar", headers=CURL)
        assert response.json() == {
            "ip": DOMAIN_IP,
            "registrar": None,
            "errors": {"registrar": "WHOIS lookup timed out"},
        }

    def test_a_missing_value_is_null_with_no_errors_key(self):
        with _legs() as mocks:
            mocks["ssl"].return_value = None
            response = client.get("/example.com?fields=cert_expires", headers=CURL)
        assert response.json() == {"cert_expires": None}

    def test_a_field_that_does_not_apply_to_the_target_is_a_dash(self):
        """An IP has no registrar or certificate in this service's lookup, and a
        domain's own PTR is not asked for; with ?fields= the line stays, so
        positions still line up."""
        with _legs():
            ip = client.get(
                "/8.8.8.8?fields=registrar,cert_expires,asn_number&format=text",
                headers=CURL,
            )
            domain = client.get(
                "/example.com?fields=reverse_dns,ip&format=text", headers=CURL
            )
        assert ip.text == "-\n-\n15169\n"
        assert domain.text == f"-\n{DOMAIN_IP}\n"

    def test_a_failed_lookup_does_not_turn_an_inapplicable_field_into_a_question(
        self,
    ):
        """An IP's registrar is "-" because an IP has none, not because the
        lookup that would have found it broke."""
        with _legs() as mocks:
            mocks["whois"].side_effect = lambda t: {"error": "WHOIS lookup failed"}
            response = client.get(
                "/8.8.8.8?fields=registrar,registrant&format=text", headers=CURL
            )
        assert response.text == "-\n?\n"

    def test_an_echoed_field_name_cannot_reach_the_terminal_raw(self):
        with _legs():
            response = client.get("/?fields=%1b[2J&format=text", headers=CURL)
        assert response.status_code == 400
        assert "\x1b" not in response.text
        assert response.text.count("\n") == 1


TIMEOUT = dns.resolver.LifetimeTimeout(timeout=3.0, errors=[])


class TestAFailedAQueryIsAQuestionMark:
    """`-` says the name has no address; a resolver that never answered says
    nothing of the kind, and neither does anything read from that address."""

    def test_the_block_marks_every_field_read_from_the_address(self):
        with _legs() as mocks:
            mocks["resolver"].return_value.resolve.side_effect = TIMEOUT
            # What SSLManager.get_ssl_info answers with no verified address.
            mocks["ssl"].return_value = None
            response = client.get("/example.com?format=text", headers=CURL)
        assert response.status_code == 200
        block = _block(response)
        assert [key for key, _ in block] == DOMAIN_KEYS
        values = dict(block)
        assert values["target"] == "example.com"
        assert values["ip"] == "?"
        for name in (
            "country_code",
            "country_name",
            "city",
            "asn_number",
            "asn_name",
            "cidr",
        ):
            assert values[name] == "?", name
        for name in ("cert_issuer", "cert_expires", "cert_days_remaining"):
            assert values[name] == "?", name
        # The registry is asked about the name, not the address.
        assert values["registrar"] == "Example Registrar"
        assert values["registrant"] == "Example Org"
        assert values["domain_expires"] == "2027-07-31"
        mocks["ssl"].assert_called_once_with("example.com", None)

    @pytest.mark.parametrize(
        ("status", "exc"),
        [
            ("timeout", TIMEOUT),
            ("servfail", dns.resolver.NoNameservers()),
            ("error", OSError("network is unreachable")),
        ],
    )
    def test_json_is_null_with_the_status_as_the_reason(self, status, exc):
        with _legs() as mocks:
            mocks["resolver"].return_value.resolve.side_effect = exc
            mocks["ssl"].return_value = None
            response = client.get(
                "/example.com?fields=ip,cert_days_remaining", headers=CURL
            )
        assert response.json() == {
            "ip": None,
            "cert_days_remaining": None,
            "errors": {"ip": status, "cert_days_remaining": status},
        }

    def test_the_registration_is_untouched(self):
        with _legs() as mocks:
            mocks["resolver"].return_value.resolve.side_effect = TIMEOUT
            response = client.get("/example.com?fields=registrar,ip", headers=CURL)
        assert response.json() == {
            "registrar": "Example Registrar",
            "ip": None,
            "errors": {"ip": "timeout"},
        }

    @pytest.mark.parametrize("answer", [dns.resolver.NXDOMAIN, dns.resolver.NoAnswer])
    def test_a_name_with_no_address_is_still_a_dash(self, answer):
        """The reverse of "a failure is not an empty list": an answer must not
        be dressed up as a failure."""
        with _legs() as mocks:
            mocks["resolver"].return_value.resolve.side_effect = answer
            mocks["ssl"].return_value = None
            text = client.get("/example.com?format=text", headers=CURL)
            body = client.get(
                "/example.com?fields=ip,country_code,cert_issuer", headers=CURL
            ).json()
        values = dict(_block(text))
        assert values["ip"] == "-"
        assert values["country_code"] == "-"
        assert values["cert_issuer"] == "-"
        assert body == {"ip": None, "country_code": None, "cert_issuer": None}

    def test_a_timed_out_aaaa_fallback_is_a_failure_too(self):
        """A said "no record", which sends gather() to AAAA; AAAA never
        answered, so the address is unknown, not absent."""
        with _legs() as mocks:
            mocks["resolver"].return_value.resolve.side_effect = [
                dns.resolver.NoAnswer(),
                TIMEOUT,
            ]
            mocks["ssl"].return_value = None
            response = client.get("/example.com?fields=ip", headers=CURL)
        assert response.json() == {"ip": None, "errors": {"ip": "timeout"}}

    def test_an_ip_target_and_the_self_route_are_never_marked(self):
        """An IP's resolution is "literal", and / has none."""
        with _legs():
            by_ip = client.get("/8.8.8.8?fields=ip,country_code", headers=CURL)
            own = client.get("/?fields=ip,country_code", headers=CURL)
        assert by_ip.json() == {"ip": "8.8.8.8", "country_code": "US"}
        assert own.json() == {"ip": CLIENT_IP, "country_code": "US"}

    def test_a_field_from_the_record_sweep_keeps_its_own_answer(self, monkeypatch):
        """The record sweep asks about the name, not the address, and each
        record type carries its own status: a failed A query leaves a field
        read from the sweep to that status. No such field exists yet, so a
        stand-in entry holds the rule for the first one."""
        monkeypatch.setitem(
            textfmt.FIELDS, "sweep_only", (frozenset({"dns"}), frozenset({"domain"}))
        )
        _, errors = textfmt.field_values(
            {"address": "example.com", "resolution": "timeout"}, "domain"
        )
        assert errors["ip"] == "timeout"
        assert "sweep_only" not in errors


UNREACHABLE = {"error": "port 443 unreachable", "reason": "connection refused"}
# What mcp_server._tls_failure makes of managers.TLS_SKIPPED_IPV6.
V6_SKIPPED = "TLS not checked (IPv6-only host; this server has no IPv6 connectivity)"


class TestAFailedTlsLegIsAQuestionMark:
    """A port that never answered is not a host serving no certificate."""

    def test_the_block_marks_the_certificate_fields_only(self):
        with _legs() as mocks:
            mocks["ssl"].return_value = dict(UNREACHABLE)
            response = client.get("/example.com?format=text", headers=CURL)
        values = dict(_block(response))
        assert values["ip"] == DOMAIN_IP
        assert values["country_code"] == "US"
        assert values["registrar"] == "Example Registrar"
        assert values["cert_issuer"] == "?"
        assert values["cert_expires"] == "?"
        assert values["cert_days_remaining"] == "?"

    @pytest.mark.parametrize(
        ("ssl", "reason"),
        [
            (UNREACHABLE, "port 443 unreachable (connection refused)"),
            (
                {"error": "TLS handshake failed", "reason": "timed out"},
                "TLS handshake failed (timed out)",
            ),
            # Not attempted rather than failed, but the certificate is just as
            # unknown: the contract's "?".
            (managers.TLS_SKIPPED_IPV6, V6_SKIPPED),
            # get_ssl_info's catch-all carries no reason, so no parentheses.
            ({"error": "TLS lookup failed"}, "TLS lookup failed"),
        ],
    )
    def test_json_carries_the_mcp_tools_wording(self, ssl, reason):
        """The same words as the MCP ssl_certificate tool's error."""
        with _legs() as mocks:
            mocks["ssl"].return_value = dict(ssl)
            response = client.get(
                "/example.com?fields=ip,cert_issuer,cert_days_remaining", headers=CURL
            )
        assert response.json() == {
            "ip": DOMAIN_IP,
            "cert_issuer": None,
            "cert_days_remaining": None,
            "errors": {"cert_issuer": reason, "cert_days_remaining": reason},
        }

    def test_an_untrusted_certificate_is_still_an_answer(self):
        """A certificate that failed verification was read: its issuer and
        expiry are values, not "?". Whether it is trusted is for the full JSON
        and the MCP tool to say."""
        untrusted = {
            **copy.deepcopy(CERT),
            "trusted": False,
            "verify_error": {
                "code": 20,
                "message": "unable to get local issuer certificate",
                "reason": "chain_incomplete",
            },
            "hostname_match": True,
        }
        with _legs() as mocks:
            mocks["ssl"].return_value = untrusted
            response = client.get(
                "/example.com?fields=cert_issuer,cert_expires", headers=CURL
            )
        assert response.json() == {
            "cert_issuer": "Let's Encrypt",
            "cert_expires": "2099-11-09",
        }

    def test_no_handshake_attempted_is_still_a_dash(self):
        """None from get_ssl_info: there was no address to connect to. On /,
        cert_* does not apply at all."""
        with _legs() as mocks:
            mocks["ssl"].return_value = None
            domain = client.get(
                "/example.com?fields=cert_issuer,cert_expires", headers=CURL
            )
            own = client.get("/?fields=cert_issuer&format=text", headers=CURL)
        assert domain.json() == {"cert_issuer": None, "cert_expires": None}
        assert own.text == "-\n"
        assert _ran(mocks) == {"resolver", "ssl"}


class TestResolutionField:
    """`?fields=resolution`: why `ip` is "?" (or "-"), by name only."""

    def test_it_says_how_the_a_query_ended(self):
        with _legs() as mocks:
            response = client.get("/example.com?fields=ip,resolution", headers=CURL)
        assert response.json() == {"ip": DOMAIN_IP, "resolution": "ok"}
        assert _ran(mocks) == {"resolver"}

    def test_it_is_the_reason_behind_a_question_mark_not_one_itself(self):
        with _legs() as mocks:
            mocks["resolver"].return_value.resolve.side_effect = TIMEOUT
            body = client.get("/example.com?fields=ip,resolution", headers=CURL).json()
            text = client.get(
                "/example.com?fields=ip,resolution&format=text", headers=CURL
            ).text
        assert body == {
            "ip": None,
            "resolution": "timeout",
            "errors": {"ip": "timeout"},
        }
        assert text == "?\ntimeout\n"

    def test_a_name_with_no_address_says_so_without_an_error(self):
        with _legs() as mocks:
            mocks["resolver"].return_value.resolve.side_effect = dns.resolver.NXDOMAIN
            response = client.get("/example.com?fields=ip,resolution", headers=CURL)
        assert response.json() == {"ip": None, "resolution": "nxdomain"}

    def test_it_is_not_in_the_text_block(self):
        with _legs():
            response = client.get("/example.com?format=text", headers=CURL)
        assert [key for key, _ in _block(response)] == DOMAIN_KEYS
        assert textfmt.block_fields("domain") == DOMAIN_KEYS

    def test_an_ip_and_the_self_route_answer_a_dash_for_nothing(self):
        """An IP's "literal" is not shown: the field is a domain's, and a
        field that does not apply to the target is "-" whatever gather()
        left in the dict."""
        with _legs() as mocks:
            by_ip = client.get("/8.8.8.8?fields=resolution&format=text", headers=CURL)
            own = client.get("/?fields=resolution&format=text", headers=CURL)
        assert by_ip.text == "-\n"
        assert own.text == "-\n"
        assert _ran(mocks) == set()

    def test_it_is_named_among_the_valid_fields(self):
        with _legs():
            response = client.get("/example.com?fields=bogus", headers=CURL)
        assert "resolution" in response.json()["error"]


class TestFieldsRunOnlyTheirLegs:
    def test_network_fields_skip_whois_dns_and_tls(self):
        with _legs() as mocks:
            response = client.get(
                "/example.com?fields=ip,country_code,asn_number", headers=CURL
            )
        assert response.status_code == 200
        assert _ran(mocks) == {"resolver", "geo"}

    def test_ip_alone_is_the_a_query_alone(self):
        with _legs() as mocks:
            client.get("/example.com?fields=ip", headers=CURL)
        assert _ran(mocks) == {"resolver"}

    def test_registrar_is_whois_alone(self):
        """WHOIS asks the registry about the name; nothing connects to the
        target, so not even the A query runs."""
        with _legs() as mocks:
            response = client.get("/example.com?fields=registrar", headers=CURL)
        assert response.json() == {"registrar": "Example Registrar"}
        assert _ran(mocks) == {"whois"}

    def test_cert_fields_are_resolution_and_tls(self):
        with _legs() as mocks:
            client.get("/example.com?fields=cert_expires,cert_issuer", headers=CURL)
        assert _ran(mocks) == {"resolver", "ssl"}

    def test_reverse_dns_of_an_ip_is_the_ptr_alone(self):
        with _legs() as mocks:
            response = client.get("/8.8.8.8?fields=reverse_dns", headers=CURL)
        assert response.json() == {"reverse_dns": "dns.google"}
        assert _ran(mocks) == {"reverse"}

    def test_a_field_that_does_not_apply_costs_nothing(self):
        with _legs() as mocks:
            client.get("/8.8.8.8?fields=registrar,cert_expires", headers=CURL)
            client.get("/example.com?fields=reverse_dns", headers=CURL)
        assert _ran(mocks) == set()

    def test_target_alone_costs_nothing(self):
        with _legs() as mocks:
            response = client.get("/EXAMPLE.com?fields=target", headers=CURL)
            idn = client.get("/straße.de.?fields=target", headers=CURL)
        assert response.json() == {"target": "example.com"}
        assert idn.json() == {"target": "xn--strae-oqa.de"}
        assert _ran(mocks) == set()

    def test_a_domain_resolving_to_a_private_address_is_still_refused(self):
        """Narrowing the legs must not narrow the SSRF gate: an address leg
        still resolves first and refuses a private answer before any TLS
        handshake is attempted."""
        with _legs(a_record="10.0.0.5") as mocks:
            response = client.get(
                "/internal.example.com?fields=cert_expires", headers=CURL
            )
        assert response.status_code == 400
        assert _ran(mocks) == {"resolver"}

    def test_self_fields_run_only_their_legs(self):
        with _legs() as mocks:
            response = client.get("/?fields=country_code", headers=CURL)
        assert response.json() == {"country_code": "US"}
        assert _ran(mocks) == {"geo"}

    def test_self_ip_field_costs_nothing(self):
        with _legs() as mocks:
            response = client.get("/?fields=ip", headers=CURL)
        assert response.json() == {"ip": CLIENT_IP}
        assert _ran(mocks) == set()

    def test_self_registration_and_ptr(self):
        with _legs() as mocks:
            response = client.get(
                "/?fields=registrant,reverse_dns&format=text", headers=CURL
            )
        assert response.text == "Google LLC\ndns.google\n"
        assert _ran(mocks) == {"whois", "reverse"}

    def test_a_private_client_is_never_sent_to_a_registry(self):
        """Same rule as the full self lookup: a private address has no public
        registration or PTR, so neither is asked for."""
        private = TestClient(app, client=("192.168.1.10", 41234))
        with _legs() as mocks:
            response = private.get(
                "/?fields=ip,registrant,reverse_dns&format=text", headers=CURL
            )
        assert response.text == "192.168.1.10\n-\n-\n"
        assert _ran(mocks) == set()


def _ptr_sweep(a=("8.8.4.4", "8.8.8.8"), a_status="ok"):
    """The sweep of 8.8.8.8's PTR name, as DomainManager.get_records() returns
    it: {"ip", "ttl"} dicts, and each type's dns_status() under "status"."""
    return {
        "queried_name": "dns.google",
        "a": [{"ip": ip, "ttl": 300} for ip in a],
        "aaaa": [],
        "status": {"a": a_status, "aaaa": "noanswer"},
    }


class TestReverseDnsConfirmed:
    """?fields=reverse_dns_confirmed: whether an IP's PTR name resolves back to
    it, read off the PTR and the sweep of that name, with no query of its own."""

    def test_it_runs_the_ptr_and_the_sweep_of_its_name_alone(self):
        with _legs() as mocks:
            mocks["records"].return_value = _ptr_sweep()
            response = client.get("/8.8.8.8?fields=reverse_dns_confirmed", headers=CURL)
        assert response.json() == {"reverse_dns_confirmed": "confirmed"}
        assert _ran(mocks) == {"reverse", "records"}
        mocks["records"].assert_called_once_with("dns.google", ip="8.8.8.8")

    def test_a_ptr_name_that_points_elsewhere_is_unconfirmed(self):
        with _legs() as mocks:
            mocks["records"].return_value = _ptr_sweep(a=["216.239.32.10"])
            response = client.get(
                "/8.8.8.8?fields=reverse_dns,reverse_dns_confirmed&format=text",
                headers=CURL,
            )
        assert response.text == "dns.google\nunconfirmed\n"

    def test_a_failed_forward_query_is_a_question_mark_not_unconfirmed(self):
        with _legs() as mocks:
            mocks["records"].return_value = _ptr_sweep(a=[], a_status="timeout")
            text = client.get(
                "/8.8.8.8?fields=reverse_dns_confirmed&format=text", headers=CURL
            )
            body = client.get("/8.8.8.8?fields=reverse_dns_confirmed", headers=CURL)
        assert text.text == "?\n"
        assert body.json() == {
            "reverse_dns_confirmed": None,
            "errors": {"reverse_dns_confirmed": "the PTR name's A/AAAA query failed"},
        }

    def test_no_ptr_is_a_dash_and_sweeps_nothing(self):
        with _legs() as mocks:
            mocks["reverse"].return_value = None
            response = client.get(
                "/8.8.8.8?fields=reverse_dns_confirmed&format=text", headers=CURL
            )
        assert response.text == "-\n"
        mocks["records"].assert_not_called()

    def test_a_domain_gets_a_dash_and_costs_nothing(self):
        with _legs() as mocks:
            response = client.get(
                "/example.com?fields=reverse_dns_confirmed&format=text", headers=CURL
            )
        assert response.text == "-\n"
        assert _ran(mocks) == set()

    def test_it_stays_out_of_the_text_block(self):
        """In the block it would add the PTR name's sweep to every IP lookup."""
        with _legs() as mocks:
            mocks["records"].return_value = _ptr_sweep()
            response = client.get("/8.8.8.8?format=text", headers=CURL)
        assert [key for key, _ in _block(response)] == IP_KEYS
        mocks["records"].assert_not_called()

    def test_on_the_self_route_it_is_a_dash_and_sweeps_nothing(self):
        """_self_fields sweeps no PTR name, so `/` answers "-" (the README says
        so); the self page, which does sweep it, shows the verdict."""
        with _legs() as mocks:
            mocks["records"].return_value = _ptr_sweep()
            text = client.get(
                "/?fields=reverse_dns_confirmed&format=text", headers=CURL
            )
            body = client.get("/?fields=reverse_dns_confirmed", headers=CURL)
        assert text.text == "-\n"
        assert body.json() == {"reverse_dns_confirmed": None}
        mocks["records"].assert_not_called()


@contextlib.contextmanager
def _aged_legs(registered_days_ago=25, issued_days_ago=10):
    """_legs(), with example.com registered and its certificate issued that
    many days ago."""
    now = datetime.datetime.now(datetime.UTC)
    registration = {
        **REGISTRATIONS["example.com"],
        "created": now - datetime.timedelta(days=registered_days_ago),
    }
    cert = {
        **CERT,
        "notBefore": _asn1_time(now - datetime.timedelta(days=issued_days_ago)),
    }
    with _legs() as mocks:
        mocks["whois"].side_effect = lambda t: copy.deepcopy(registration)
        mocks["ssl"].return_value = copy.deepcopy(cert)
        yield mocks


class TestAgeFields:
    """domain_age_days and cert_age_days: whole days since the registration's
    created date and since the certificate's notBefore, the arithmetic a
    script would otherwise do on the dates."""

    def test_both_are_in_the_domain_block(self):
        with _aged_legs() as mocks:
            values = dict(_block(client.get("/example.com?format=text", headers=CURL)))
        assert values["domain_age_days"] == "25"
        assert values["cert_age_days"] == "10"
        # Read off the record and the certificate the block already fetches:
        # the same legs as without the two lines, so no new outbound call.
        assert _ran(mocks) == {"whois", "geo", "resolver", "ssl"}

    def test_fields_answer_one_integer_per_line(self):
        with _aged_legs():
            response = client.get(
                "/example.com?fields=domain_age_days,cert_age_days&format=text",
                headers=CURL,
            )
        assert response.text == "25\n10\n"

    def test_json_carries_integers(self):
        with _aged_legs():
            response = client.get(
                "/example.com?fields=domain_age_days,cert_age_days", headers=CURL
            )
        assert response.json() == {"domain_age_days": 25, "cert_age_days": 10}

    def test_each_runs_only_its_own_leg(self):
        with _aged_legs() as mocks:
            client.get("/example.com?fields=domain_age_days", headers=CURL)
        assert _ran(mocks) == {"whois"}
        with _aged_legs() as mocks:
            client.get("/example.com?fields=cert_age_days", headers=CURL)
        assert _ran(mocks) == {"resolver", "ssl"}

    def test_a_failed_registration_lookup_is_a_question_mark(self):
        with _legs() as mocks:
            mocks["whois"].side_effect = lambda t: {"error": "WHOIS lookup timed out"}
            text = client.get(
                "/example.com?fields=domain_age_days&format=text", headers=CURL
            )
            json_ = client.get("/example.com?fields=domain_age_days", headers=CURL)
        assert text.text == "?\n"
        assert json_.json() == {
            "domain_age_days": None,
            "errors": {"domain_age_days": "WHOIS lookup timed out"},
        }

    def test_not_registered_or_an_unreadable_date_is_a_dash(self):
        """Python-whois can hand back a date it could not parse as a string,
        and a date days ahead is bad data: neither is an age, and neither is
        an error."""
        path = "/example.com?fields=domain_age_days&format=text"
        ahead = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=2)
        with _legs() as mocks:
            mocks["whois"].side_effect = lambda t: {"error": "not registered"}
            unregistered = client.get(path, headers=CURL)
            mocks["whois"].side_effect = lambda t: {
                **REGISTRATIONS["example.com"],
                "created": "before Aug-1996",
            }
            unreadable = client.get(path, headers=CURL)
            mocks["whois"].side_effect = lambda t: {
                **REGISTRATIONS["example.com"],
                "created": ahead,
            }
            future = client.get(path, headers=CURL)
        assert unregistered.text == "-\n"
        assert unreadable.text == "-\n"
        assert future.text == "-\n"

    def test_a_name_registered_today_is_zero_not_a_dash(self):
        """0 is an age, not a missing one: a name registered hours ago, and one
        whose registry's naive local time reads a few hours ahead of UTC."""
        path = "/example.com?fields=domain_age_days&format=text"
        ahead = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=9)
        with _aged_legs(registered_days_ago=2 / 24) as mocks:
            today = client.get(path, headers=CURL)
            as_json = client.get("/example.com?fields=domain_age_days", headers=CURL)
            mocks["whois"].side_effect = lambda t: {
                **REGISTRATIONS["example.com"],
                "created": ahead.replace(tzinfo=None),
            }
            ahead_of_utc = client.get(path, headers=CURL)
        assert today.text == "0\n"
        assert as_json.json() == {"domain_age_days": 0}
        assert ahead_of_utc.text == "0\n"

    def test_a_failed_handshake_leaves_cert_age_with_the_other_cert_fields(self):
        """No `?` rule of its own: cert_age_days rides the tls leg, so it reads
        what cert_days_remaining reads, "?", never a number."""
        with _aged_legs() as mocks:
            mocks["ssl"].return_value = {
                "error": "port 443 unreachable",
                "reason": "connection refused",
            }
            values = dict(_block(client.get("/example.com?format=text", headers=CURL)))
        assert values["cert_age_days"] == values["cert_days_remaining"]
        assert values["cert_age_days"] == "?"
        assert values["domain_age_days"] == "25"

    def test_a_timed_out_a_query_leaves_cert_age_with_the_other_cert_fields(self):
        timeout = dns.resolver.LifetimeTimeout(timeout=3.0, errors=[])
        with _aged_legs() as mocks:
            mocks["resolver"].return_value.resolve.side_effect = timeout
            # What SSLManager.get_ssl_info answers with no address to connect to.
            mocks["ssl"].return_value = None
            values = dict(_block(client.get("/example.com?format=text", headers=CURL)))
        assert values["cert_age_days"] == values["cert_days_remaining"]
        assert values["cert_age_days"] == "?"
        # The registration is asked of the registry, not of the address.
        assert values["domain_age_days"] == "25"

    def test_an_ip_has_no_domain_age_even_when_its_registration_ran(self):
        """registrant runs the whois leg for an IP too, and the network's
        record has a created date: that is the block's age, not a domain's."""
        created = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=25)
        with _legs() as mocks:
            mocks["whois"].side_effect = lambda t: {
                **REGISTRATIONS[CLIENT_IP],
                "rir": "arin",
                "created": created,
            }
            response = client.get(
                "/8.8.8.8?fields=registrant,domain_age_days,cert_age_days&format=text",
                headers=CURL,
            )
        assert response.text == "Google LLC\n-\n-\n"

    def test_an_ip_or_your_own_address_asks_nothing_for_them(self):
        """Both are domain-only, so neither costs a lookup, and the visitor's
        own address gets no outbound query from them."""
        with _legs() as mocks:
            ip = client.get(
                "/8.8.8.8?fields=domain_age_days,cert_age_days&format=text",
                headers=CURL,
            )
            own = client.get(
                "/?fields=domain_age_days,cert_age_days&format=text", headers=CURL
            )
        assert ip.text == "-\n-\n"
        assert own.text == "-\n-\n"
        assert _ran(mocks) == set()


# --- dmarc_policy -----------------------------------------------------------------

DMARC_RECORD = {
    "text": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
    "ttl": 300,
    "queried_name": "_dmarc.example.com",
}


def _swept(dmarc, status):
    """What the record sweep hands back for example.com, cut to DMARC."""
    return {"queried_name": "example.com", "dmarc": dmarc, "status": status}


class TestDmarcPolicyField:
    def test_it_is_the_record_sweep_alone(self):
        """No WHOIS, GeoIP or TLS: the A query that gates every address leg,
        then the sweep, which asks for the DMARC record."""
        with _legs() as mocks:
            mocks["records"].return_value = _swept([DMARC_RECORD], {"dmarc": "ok"})
            response = client.get("/example.com?fields=dmarc_policy", headers=CURL)
        assert response.json() == {"dmarc_policy": "reject"}
        assert _ran(mocks) == {"resolver", "records"}
        assert mocks["records"].call_args.kwargs["dmarc"] is True

    def test_it_stays_out_of_the_text_block(self):
        """The block skips the sweep, so a field that needs it is asked for by
        name only (test_the_block_skips_the_record_sweep_and_crt_sh)."""
        with _legs():
            response = client.get("/example.com?format=text", headers=CURL)
        assert "dmarc_policy" not in dict(_block(response))

    def test_an_inherited_policy_is_the_one_for_subdomains(self):
        inherited = {**DMARC_RECORD, "text": "v=DMARC1; p=reject; sp=quarantine"}
        with _legs() as mocks:
            mocks["records"].return_value = {
                "queried_name": "www.example.com",
                "dmarc": [inherited],
                "status": {"dmarc": "ok"},
            }
            response = client.get(
                "/www.example.com?fields=dmarc_policy&format=text", headers=CURL
            )
        assert response.text == "quarantine\n"

    @pytest.mark.parametrize("status", ["nxdomain", "noanswer"])
    def test_no_record_is_a_dash(self, status):
        with _legs() as mocks:
            mocks["records"].return_value = _swept([], {"dmarc": status})
            text = client.get(
                "/example.com?fields=dmarc_policy&format=text", headers=CURL
            )
            body = client.get("/example.com?fields=dmarc_policy", headers=CURL)
        assert text.text == "-\n"
        assert body.json() == {"dmarc_policy": None}

    def test_two_records_are_a_dash(self):
        """RFC 7489 ends policy discovery at two records: no policy applies."""
        second = {**DMARC_RECORD, "text": "v=DMARC1; p=none"}
        with _legs() as mocks:
            mocks["records"].return_value = _swept(
                [DMARC_RECORD, second], {"dmarc": "ok"}
            )
            response = client.get("/example.com?fields=dmarc_policy", headers=CURL)
        assert response.json() == {"dmarc_policy": None}

    @pytest.mark.parametrize("status", ["timeout", "servfail", "error"])
    def test_a_failed_dmarc_query_is_a_question_mark(self, status):
        """The A query answered; the _dmarc TXT query did not."""
        with _legs() as mocks:
            mocks["records"].return_value = _swept([], {"dmarc": status})
            text = client.get(
                "/example.com?fields=ip,dmarc_policy&format=text", headers=CURL
            )
            body = client.get("/example.com?fields=dmarc_policy", headers=CURL)
        assert text.text == f"{DOMAIN_IP}\n?\n"
        assert body.json() == {"dmarc_policy": None, "errors": {"dmarc_policy": status}}

    def test_resolvers_that_answer_nothing_are_a_question_mark(self):
        """The gating A query and the _dmarc query both time out: the policy
        is unknown, whatever the A query's own failure does to `ip`."""
        timeout = dns.resolver.LifetimeTimeout(timeout=3.0, errors=[])
        with _legs() as mocks:
            mocks["resolver"].return_value.resolve.side_effect = timeout
            mocks["records"].return_value = _swept([], {"dmarc": "timeout"})
            text = client.get(
                "/example.com?fields=dmarc_policy&format=text", headers=CURL
            )
            body = client.get("/example.com?fields=dmarc_policy", headers=CURL)
        assert text.text == "?\n"
        assert body.json() == {
            "dmarc_policy": None,
            "errors": {"dmarc_policy": "timeout"},
        }

    def test_an_answered_policy_stands_when_the_a_query_failed(self):
        """The gating A query timed out, the _dmarc query answered. The policy
        does not hang on the address, so it stands, as on the page's Mail row
        and in MCP dns_records: the A query's failure marks the fields that
        read the address (ip here), and _NAME_LEGS leaves a field of the
        record sweep to its own status."""
        timeout = dns.resolver.LifetimeTimeout(timeout=3.0, errors=[])
        with _legs() as mocks:
            mocks["resolver"].return_value.resolve.side_effect = timeout
            mocks["records"].return_value = _swept([DMARC_RECORD], {"dmarc": "ok"})
            text = client.get(
                "/example.com?fields=ip,dmarc_policy&format=text", headers=CURL
            )
            body = client.get("/example.com?fields=ip,dmarc_policy", headers=CURL)
        assert text.text == "?\nreject\n"
        assert body.json() == {
            "ip": None,
            "dmarc_policy": "reject",
            "errors": {"ip": "timeout"},
        }

    def test_an_ip_has_none_and_costs_nothing(self):
        with _legs() as mocks:
            ip = client.get("/8.8.8.8?fields=dmarc_policy&format=text", headers=CURL)
            self_ = client.get("/?fields=dmarc_policy&format=text", headers=CURL)
        assert ip.text == "-\n"
        assert self_.text == "-\n"
        assert _ran(mocks) == set()


# --- lookup.gather(legs=) -----------------------------------------------------------


class TestGatherLegs:
    async def test_the_default_still_runs_every_leg(self):
        """The page, the full JSON and the MCP `lookup` tool call gather()
        bare; dns_records and ssl_certificate narrow it (see TestMcp in
        tests/test_concurrency_gate.py)."""
        with _legs() as mocks:
            data = await lookup.gather("example.com")
        assert _ran(mocks) == {"whois", "geo", "resolver", "records", "ssl"}
        assert data["whois"]["registrar"] == "Example Registrar"

    async def test_the_default_for_an_ip_still_runs_every_leg(self):
        with _legs() as mocks:
            await lookup.gather("8.8.8.8")
        assert _ran(mocks) == {"whois", "geo", "reverse", "records"}

    async def test_an_unrun_leg_comes_back_empty(self):
        with _legs():
            data = await lookup.gather("example.com", legs={"geo"})
        assert data["whois"] is None
        assert data["ssl"] is None
        assert data["domain"] is None
        assert data["location"]["country_code"] == "US"

    async def test_an_unknown_leg_is_refused(self):
        with _legs() as mocks:
            with pytest.raises(ValueError, match="cert"):
                await lookup.gather("example.com", legs={"geo", "cert"})
        assert _ran(mocks) == set()


# --- HEAD ---------------------------------------------------------------------------


class TestHead:
    @pytest.mark.parametrize("path", ["/", "/example.com"])
    def test_text_is_advertised_as_text_plain(self, path):
        with _legs() as mocks:
            by_param = client.head(f"{path}?format=text", headers=CHROME)
            by_accept = client.head(path, headers={**CURL, "accept": "text/plain"})
        for response in (by_param, by_accept):
            assert response.status_code == 200
            assert _is_text(response)
        assert _ran(mocks) == set()

    @pytest.mark.parametrize("path", ["/", "/example.com"])
    def test_fields_are_advertised_as_json_even_to_a_browser(self, path):
        with _legs():
            response = client.head(f"{path}?fields=ip", headers=CHROME)
        assert response.headers["content-type"].startswith("application/json")

    def test_an_unknown_field_is_the_same_400_as_get(self):
        with _legs():
            response = client.head("/example.com?fields=bogus", headers=CURL)
        assert response.status_code == 400


# --- the security middleware --------------------------------------------------------


class TestSecurityClassification:
    """?format= and ?fields= are query parameters, and the security middleware
    classifies a request by its path alone."""

    def test_a_probe_shaped_field_is_a_400_not_a_ban(self):
        with _legs():
            response = client.get("/example.com?fields=.env,config.json", headers=CURL)
        assert response.status_code == 400
        assert not main.ip_ban_manager.is_banned(CLIENT_IP)

    def test_a_format_suffix_in_the_path_is_still_a_probe(self):
        """What the README warns about: put in the path, the suffix is what
        the detector's `\\.json$` rule reads, and the target behind it has no
        public suffix to excuse it."""
        with _legs() as mocks:
            response = client.get("/example.com.json", headers=CURL)
        assert response.status_code == 403
        assert main.ip_ban_manager.is_banned(CLIENT_IP)
        assert _ran(mocks) == set()
