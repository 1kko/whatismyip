"""SSRF: only globally reachable unicast may become a connection target.

is_safe_ip used to be a denylist (private, loopback, link-local, reserved), so
every range it did not name passed: CGNAT 100.64.0.0/10 -- where Tailscale's
MagicDNS answers at 100.100.100.100 -- and multicast. A domain whose A record
pointed there got a TLS handshake from the server on port 443.
"""

import ipaddress
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import lookup
import managers
from main import app

client = TestClient(app, raise_server_exceptions=False)

# Not globally reachable, yet in none of the ranges the old denylist named.
UNNAMED_NON_GLOBAL = ["100.64.0.1", "100.100.100.100", "224.0.0.1"]


@pytest.mark.parametrize(
    "ip",
    [
        *UNNAMED_NON_GLOBAL,
        "100.127.255.254",  # top of CGNAT
        "239.255.255.250",  # SSDP multicast
        "ff02::1",  # link-scope multicast
        "ff0e::1",  # global-scope multicast: is_global says True
        "fec0::1",  # deprecated site-local: is_global says True
    ],
)
def test_rejects_ranges_the_denylist_never_named(ip):
    assert lookup.is_safe_ip(ip) is False


@pytest.mark.parametrize(
    "ip",
    [
        "4000::1",  # unassigned IPv6: is_global says True
        "64:ff9b::a00:1",  # NAT64 prefix embedding 10.0.0.1
    ],
)
def test_reserved_space_stays_rejected(ip):
    # is_global alone would let these through; the old denylist refused them
    # via is_reserved, and moving to an allowlist must not reopen them.
    assert lookup.is_safe_ip(ip) is False


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",
        "1.1.1.1",
        "168.126.63.1",
        "93.184.216.34",
        "2001:4860:4860::8888",
        "192.0.0.9",  # IANA's exceptions inside 192.0.0.0/24: public anycast
        "192.0.0.10",
    ],
)
def test_public_unicast_still_passes(ip):
    assert lookup.is_safe_ip(ip) is True


def _no_outbound():
    """Patch every leg gather() could reach, so a test can assert none ran."""
    return (
        patch("lookup.lookup_whois", new=AsyncMock(return_value={})),
        patch("lookup.geo_ip_manager.fetch_location", return_value={}),
        patch("lookup.domain_manager.perform_reverse_lookup"),
        patch("lookup.domain_manager.get_records"),
        patch("managers.SSLManager.get_ssl_info"),
    )


@pytest.mark.parametrize("ip", UNNAMED_NON_GLOBAL)
def test_direct_target_is_refused_before_any_lookup(ip):
    whois, geo, reverse, records, ssl_info = _no_outbound()
    with (
        whois,
        geo,
        reverse as reverse_mock,
        records as records_mock,
        ssl_info as ssl_mock,
    ):
        response = client.get(f"/{ip}")
    assert response.status_code == 400
    reverse_mock.assert_not_called()
    records_mock.assert_not_called()
    ssl_mock.assert_not_called()


@pytest.mark.parametrize("ip", UNNAMED_NON_GLOBAL)
def test_domain_resolving_there_is_refused_without_tls(ip):
    whois, geo, reverse, records, ssl_info = _no_outbound()
    with (
        whois,
        geo,
        reverse,
        records as records_mock,
        ssl_info as ssl_mock,
        patch("lookup.domain_manager.is_valid_domain", return_value=True),
        # gather() reads str(answer[0]) from the public resolver's answer.
        patch("lookup._recursive_resolver") as resolver,
    ):
        resolver.return_value.resolve.return_value = [ip]
        response = client.get("/internal.example.com")
    assert response.status_code == 400
    records_mock.assert_not_called()
    ssl_mock.assert_not_called()


@pytest.mark.parametrize("ip", UNNAMED_NON_GLOBAL)
async def test_gather_opens_no_socket_for_a_domain_resolving_there(ip, monkeypatch):
    # One level down from the route, with the real SSLManager: the MCP tools
    # share gather(), so this is the check that covers them too.
    monkeypatch.setattr(lookup, "lookup_whois", AsyncMock(return_value={}))
    monkeypatch.setattr(lookup.domain_manager, "is_valid_domain", lambda d: True)
    monkeypatch.setattr(lookup.domain_manager, "get_records", MagicMock())
    resolver = MagicMock()
    resolver.resolve.return_value = [ip]
    monkeypatch.setattr(lookup, "_recursive_resolver", lambda: resolver)
    sock = MagicMock(side_effect=AssertionError("socket opened"))
    with patch.object(managers.socket, "socket", sock):
        with pytest.raises(lookup.PrivateAddressError):
            await lookup.gather("internal.example.com")
    sock.assert_not_called()


# --- The block table only labels what is_safe_ip refused -----------------------


@pytest.mark.parametrize(
    "network, code",
    [(str(network), code) for network, code, _, _ in lookup._SPECIAL_PURPOSE],
)
def test_every_row_of_the_block_table_is_refused_end_to_end(network, code):
    """special_purpose() names the block an address fell in after is_safe_ip
    refused it. Were a row to cover an address is_safe_ip lets through, the
    table would have become a second opinion on the SSRF boundary."""
    block = ipaddress.ip_network(network)
    assert lookup.is_safe_ip(str(block[0])) is False, (network, code)
    assert lookup.is_safe_ip(str(block[-1])) is False, (network, code)


@pytest.mark.parametrize("ip", ["192.0.0.9", "192.0.0.10"])
async def test_the_registry_exceptions_never_reach_the_table(ip):
    """192.0.0.9 and 192.0.0.10 sit inside the table's 192.0.0.0/24 row, but
    is_safe_ip passes them (public anycast) and gather() takes them on: the
    table is read only after is_safe_ip refused an address, so a row can
    never refuse one by itself. An IP's "resolve" leg is the literal itself,
    so nothing is asked of anyone."""
    assert ipaddress.ip_address(ip) in ipaddress.ip_network("192.0.0.0/24")
    assert lookup.is_safe_ip(ip) is True
    data = await lookup.gather(ip, legs={"resolve"})
    assert data["resolved_ip"] == ip
    assert data["resolution"] == "literal"


@pytest.mark.parametrize("ip", UNNAMED_NON_GLOBAL)
async def test_gather_names_the_block_a_domain_resolved_to(ip, monkeypatch):
    """_run_legs raises for the address a domain resolved to, naming that
    address and its block; the target in str(exc) stays the domain."""
    monkeypatch.setattr(lookup, "lookup_whois", AsyncMock(return_value={}))
    monkeypatch.setattr(lookup.domain_manager, "is_valid_domain", lambda d: True)
    monkeypatch.setattr(lookup.domain_manager, "get_records", MagicMock())
    resolver = MagicMock()
    resolver.resolve.return_value = [ip]
    monkeypatch.setattr(lookup, "_recursive_resolver", lambda: resolver)
    with pytest.raises(lookup.PrivateAddressError) as info:
        await lookup.gather("internal.example.com")
    assert str(info.value) == "internal.example.com"
    assert info.value.code == ("multicast" if ip == "224.0.0.1" else "cgnat")
    assert info.value.message.startswith(f"internal.example.com resolves to {ip}, in ")
