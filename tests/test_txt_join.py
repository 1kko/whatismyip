"""TXT records longer than 255 bytes.

A TXT record is a list of character-strings of at most 255 bytes each, so a
long SPF policy arrives split into chunks wherever byte 255 happens to fall.
RFC 7208 §3.3 says to concatenate them with no separator. Joining with a space
broke github.com's policy mid-address — 'ip4:62.253.2 27.114' — on the page,
the API and MCP alike.

The fixture is github.com's real answer (8.8.8.8, 2026-10-08): the first chunk
is exactly 255 bytes and the boundary lands inside 62.253.227.114. No network —
the resolver and gather() are faked.
"""

from unittest.mock import AsyncMock, patch

import dns.resolver
import dns.rrset
from fastapi.testclient import TestClient

import managers
from main import _record_value, app

SPF_HEAD = (
    "v=spf1 ip4:192.30.252.0/22 include:spf.protection.outlook.com"
    " include:_netblocks.google.com include:_netblocks2.google.com"
    " include:mail.zendesk.com include:_spf.salesforce.com"
    " include:servers.mcsv.net include:mktomail.com include:sendgrid.net"
    " ip4:62.253.2"
)
SPF_TAIL = "27.114 ip4:166.78.69.169 ip4:166.78.69.170 ip4:166.78.71.131 ~all"
SPF_CHUNKS = [SPF_HEAD, SPF_TAIL]
SPF_JOINED = SPF_HEAD + SPF_TAIL


def test_fixture_splits_inside_an_address_at_byte_255():
    assert len(SPF_HEAD.encode()) == 255
    assert "ip4:62.253.227.114 " in SPF_JOINED


class _Answer:
    """Just what get_records() reads off a dns.resolver.Answer."""

    def __init__(self, rrset):
        self.rrset = rrset

    def __iter__(self):
        return iter(self.rrset)


class _Resolver:
    def resolve(self, name, rdtype):
        if rdtype == "TXT" and str(name).rstrip(".") == "github.com":
            return _Answer(
                dns.rrset.from_text(
                    "github.com.",
                    3600,
                    "IN",
                    "TXT",
                    " ".join(f'"{chunk}"' for chunk in SPF_CHUNKS),
                    '"MS=ms44452932"',
                )
            )
        raise dns.resolver.NXDOMAIN()


def _records(monkeypatch):
    monkeypatch.setattr(managers, "_recursive_resolver", _Resolver)
    return managers.DomainManager().get_records("github.com")


class TestSpf:
    def test_chunks_are_concatenated_without_a_separator(self, monkeypatch):
        spf = _records(monkeypatch)["spf"]
        assert spf == [{"text": SPF_JOINED, "ttl": 3600}]
        assert "ip4:62.253.227.114" in spf[0]["text"]
        assert "62.253.2 27.114" not in spf[0]["text"]

    def test_raw_txt_list_keeps_its_chunks(self, monkeypatch):
        # The JSON and MCP `txt` list is the wire form: one string per
        # character-string. Only the joined views change.
        txt = _records(monkeypatch)["txt"]
        assert {"text": SPF_CHUNKS, "ttl": 3600} in txt
        assert {"text": ["MS=ms44452932"], "ttl": 3600} in txt


GATHERED = {
    "address": "github.com",
    "domain": {
        "a": [{"ip": "140.82.112.3", "ttl": 60}],
        "mx": [],
        "ns": [],
        "txt": [{"text": SPF_CHUNKS, "ttl": 3600}],
        "spf": [{"text": SPF_JOINED, "ttl": 3600}],
    },
    "location": {"country_code": "US", "country_name": "United States"},
    "whois": {"registrar": "Example Registrar"},
    "ssl": None,
    "resolved_ip": "140.82.112.3",
    "reverse_dns": None,
}

BROWSER_UA = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}
JSON_UA = {"user-agent": "curl/8.0"}

client = TestClient(app, client=("118.235.14.201", 41234))


class TestDnsTable:
    def test_record_value_joins_txt_chunks_without_a_separator(self):
        value = _record_value("TXT", {"text": SPF_CHUNKS, "ttl": 3600})
        assert value == SPF_JOINED

    def test_html_dns_table_renders_the_joined_record(self):
        with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
            html = client.get("/github.com", headers=BROWSER_UA).text
        table = html.split('class="records records--dns"')[1].split("</table>")[0]
        assert f"<td>{SPF_JOINED}</td>" in table
        assert "62.253.2 27.114" not in table

    def test_json_txt_list_is_still_chunked(self):
        with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
            body = client.get("/github.com", headers=JSON_UA).json()
        assert body["domain"]["txt"] == [{"text": SPF_CHUNKS, "ttl": 3600}]
