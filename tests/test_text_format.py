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

import pytest
from fastapi.testclient import TestClient

import lookup
import main
from main import app

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
    "cert_issuer",
    "cert_expires",
    "cert_days_remaining",
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
            ("/2001:4860:4860::8888", "error: IPv6 addresses are not supported yet\n"),
            ("/10.0.0.1", "error: Private or reserved IP addresses are not allowed\n"),
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

    def test_json_errors_are_unchanged(self):
        with _legs():
            invalid = client.get("/localhost", headers=CURL)
            private = client.get("/10.0.0.1", headers=CURL)
        assert invalid.json() == {
            "error": "not a domain name or IP address",
            "code": "invalid_target",
        }
        assert private.json() == {
            "detail": "Private or reserved IP addresses are not allowed"
        }


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
        assert response.json() == {"target": "EXAMPLE.com"}
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


# --- lookup.gather(legs=) -----------------------------------------------------------


class TestGatherLegs:
    async def test_the_default_still_runs_every_leg(self):
        """The page, the full JSON and every MCP tool call gather() bare."""
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
