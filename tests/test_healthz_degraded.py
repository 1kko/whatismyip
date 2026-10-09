"""The two logging.exception calls in gather() that ran outside any except
block and so logged "NoneType: None" instead of the real error."""

import asyncio
import logging

import lookup


class FakeResolver:
    def resolve(self, name, rdtype):
        return ["93.184.216.34"]


def test_gather_logs_the_real_dns_and_tls_exceptions(monkeypatch, caplog):
    """Both legs run under asyncio.gather(return_exceptions=True), so their
    errors come back as values and are logged after the fact, outside any
    except block. logging.exception there logged "NoneType: None"."""
    dns_error = RuntimeError("dns sweep exploded")
    tls_error = RuntimeError("tls handshake exploded")

    def broken_records(*args, **kwargs):
        raise dns_error

    def broken_tls(*args, **kwargs):
        raise tls_error

    monkeypatch.setattr(lookup.domain_manager, "is_valid_domain", lambda d: True)
    monkeypatch.setattr(lookup, "_recursive_resolver", FakeResolver)
    monkeypatch.setattr(lookup.domain_manager, "get_records", broken_records)
    monkeypatch.setattr(lookup.SSLManager, "get_ssl_info", broken_tls)

    with caplog.at_level(logging.ERROR):
        result = asyncio.run(lookup.gather("example.com", legs={"dns", "tls"}))

    assert result["domain"] is None and result["ssl"] is None
    logged = {
        record.getMessage(): record.exc_info
        for record in caplog.records
        if record.levelno == logging.ERROR
    }
    assert logged["Error getting DNS records for example.com"][1] is dns_error
    assert logged["Error getting SSL info for example.com"][1] is tls_error
