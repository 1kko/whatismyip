"""Four small follow-ups that earlier items left open.

1. gather()'s gating A query logged every miss at WARNING, an IPv6-only name's
   NoAnswer included, though the AAAA fallback then resolved it.

Every outbound lookup is faked; nothing here touches the network.
"""

import logging

import dns.resolver
import pytest

import lookup

# --- 1. The gating A query's misses are logged by what they mean -------------------

NAME = "v6only.example.com"
V6 = "2001:4860:4860::8888"


def _timeout():
    return dns.resolver.LifetimeTimeout(timeout=3.0, errors=[])


class _Resolver:
    """Answers each record type from `answers`: a list of addresses, or the
    exception dnspython would raise. A type it was not given has no record."""

    def __init__(self):
        self.answers = {}

    def resolve(self, qname, rdtype="A", *args, **kwargs):
        outcome = self.answers.get(rdtype) or dns.resolver.NoAnswer()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


@pytest.fixture
def resolver(monkeypatch, caplog):
    fake = _Resolver()
    monkeypatch.setattr(lookup, "_recursive_resolver", lambda: fake)
    caplog.set_level(logging.DEBUG)
    return fake


def _logged(caplog, level):
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == level and NAME in r.getMessage()
    ]


class TestGatingAQueryLogLevel:
    async def test_an_ipv6_only_name_is_not_a_warning(self, resolver, caplog):
        """The name has no A record and resolves through AAAA: nothing failed,
        so the A miss is a debug line, not one in the warning stream."""
        resolver.answers = {"A": dns.resolver.NoAnswer(), "AAAA": [V6]}
        data = await lookup.gather(NAME, legs={"resolve"})
        assert data["resolved_ip"] == V6
        assert data["resolution"] == "ok"
        assert _logged(caplog, logging.WARNING) == []
        assert any("No A record" in line for line in _logged(caplog, logging.DEBUG))

    @pytest.mark.parametrize(
        "answers, resolution",
        [
            ({"A": dns.resolver.NXDOMAIN()}, "nxdomain"),
            ({"A": dns.resolver.NoAnswer()}, "noanswer"),
            ({"A": dns.resolver.NoAnswer(), "AAAA": dns.resolver.NXDOMAIN()}, None),
        ],
        ids=["nxdomain", "no-address-records", "aaaa-nxdomain"],
    )
    async def test_a_name_with_no_address_is_an_answer_not_a_warning(
        self, resolver, caplog, answers, resolution
    ):
        """A name that does not exist, or has no address records, is what DNS
        said. Like a missing PTR record (#14), it stays out of the warnings."""
        resolver.answers = answers
        data = await lookup.gather(NAME, legs={"resolve"})
        assert data["resolved_ip"] is None
        if resolution:
            assert data["resolution"] == resolution
        assert _logged(caplog, logging.WARNING) == []
        assert _logged(caplog, logging.DEBUG)

    @pytest.mark.parametrize(
        "answers, status",
        [
            ({"A": _timeout()}, "timeout"),
            ({"A": dns.resolver.NoNameservers()}, "servfail"),
            ({"A": RuntimeError("resolver bug")}, "error"),
            ({"A": dns.resolver.NoAnswer(), "AAAA": _timeout()}, None),
            (
                {"A": dns.resolver.NoAnswer(), "AAAA": dns.resolver.NoNameservers()},
                None,
            ),
        ],
        ids=["a-timeout", "a-servfail", "a-error", "aaaa-timeout", "aaaa-servfail"],
    )
    async def test_a_name_that_could_not_be_resolved_still_warns(
        self, resolver, caplog, answers, status
    ):
        """Neither query answered: the resolver failed, so whether the name has
        an address is unknown. That stays visible, once."""
        resolver.answers = answers
        data = await lookup.gather(NAME, legs={"resolve"})
        assert data["resolved_ip"] is None
        if status:
            assert data["resolution"] == status
        assert len(_logged(caplog, logging.WARNING)) == 1
