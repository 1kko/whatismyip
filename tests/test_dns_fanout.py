"""NS/MX host resolution is capped, however many records the zone publishes.

Anyone can publish hundreds of MX records in a zone they control (thousands
over TCP). get_records() used to resolve every one of those hosts on a thread
pool sized to the answer, so one HTTP request became that many threads and
outbound A queries. These pin the cap on both — and that every record is still
returned, so the cap costs addresses, never rows.

The resolver is a fake: no network. Each host A query sleeps briefly so that an
unbounded pool shows up as real concurrency rather than finishing too fast to
overlap.
"""

import threading
import time
from types import SimpleNamespace

import dns.name
import dns.resolver
import pytest

import managers

LIMIT = 10
WORKERS = 4
TTL = 300


class _Answer:
    """Just enough of dns.resolver.Answer: iterable rdatas plus rrset.ttl."""

    def __init__(self, rdatas):
        self._rdatas = rdatas
        self.rrset = SimpleNamespace(ttl=TTL)

    def __iter__(self):
        return iter(self._rdatas)

    def __getitem__(self, index):
        return self._rdatas[index]


class _FakeResolver:
    """Answers NS and MX with a configurable number of hosts, and records every
    host A query: how many were sent and how many ran at once, per group."""

    def __init__(self, ns_count: int, mx_count: int):
        self.ns_hosts = [f"ns{i}.dns.example.org." for i in range(ns_count)]
        self.mx_hosts = [f"mx{i}.mail.example.net." for i in range(mx_count)]
        self.lock = threading.Lock()
        self.queries = {"ns": 0, "mx": 0}
        self.running = {"ns": 0, "mx": 0}
        self.peak = {"ns": 0, "mx": 0}

    def resolver(self):
        # Stands in for managers._recursive_resolver, which builds a fresh
        # resolver per query; every one shares this object's counters.
        return self

    def resolve(self, name, rdtype):
        name = str(name)
        if rdtype == "NS":
            return _Answer(
                [SimpleNamespace(target=dns.name.from_text(h)) for h in self.ns_hosts]
            )
        if rdtype == "MX":
            return _Answer(
                [
                    SimpleNamespace(preference=10 + i, exchange=dns.name.from_text(h))
                    for i, h in enumerate(self.mx_hosts)
                ]
            )
        if rdtype == "A":
            group = (
                "ns"
                if name.endswith(".dns.example.org.")
                else "mx"
                if name.endswith(".mail.example.net.")
                else None
            )
            if group is None:
                raise dns.resolver.NoAnswer()  # the target's own A: not counted
            with self.lock:
                self.queries[group] += 1
                self.running[group] += 1
                self.peak[group] = max(self.peak[group], self.running[group])
            try:
                time.sleep(0.02)
            finally:
                with self.lock:
                    self.running[group] -= 1
            return ["192.0.2.1"]
        raise dns.resolver.NoAnswer()


@pytest.fixture
def fake_dns(monkeypatch):
    monkeypatch.setattr(managers, "DNS_HOST_RESOLVE_LIMIT", LIMIT)
    monkeypatch.setattr(managers, "DNS_HOST_RESOLVE_WORKERS", WORKERS)

    def install(ns_count: int, mx_count: int) -> _FakeResolver:
        fake = _FakeResolver(ns_count, mx_count)
        monkeypatch.setattr(managers, "_recursive_resolver", fake.resolver)
        return fake

    return install


def test_hundreds_of_mx_and_ns_hosts_are_capped(fake_dns):
    fake = fake_dns(ns_count=60, mx_count=300)

    records = managers.DomainManager().get_records("example.com", ip="192.0.2.10")

    # Outbound host A queries and the threads running them are both bounded,
    # per record type, by config rather than by the zone.
    assert fake.queries == {"ns": LIMIT, "mx": LIMIT}
    assert fake.peak["ns"] <= WORKERS
    assert fake.peak["mx"] <= WORKERS

    # Every record still comes back, in answer order.
    assert [r["hostname"] for r in records["mx"]] == fake.mx_hosts
    assert [r["hostname"] for r in records["ns"]] == fake.ns_hosts
    assert [r["preference"] for r in records["mx"]] == list(range(10, 310))


@pytest.mark.parametrize("kind", ["ns", "mx"])
def test_hosts_past_the_cap_are_listed_without_an_address(fake_dns, kind):
    fake_dns(ns_count=25, mx_count=25)

    rows = managers.DomainManager().get_records("example.com", ip="192.0.2.10")[kind]

    resolved, skipped = rows[:LIMIT], rows[LIMIT:]
    assert all(r["ip"] == "192.0.2.1" for r in resolved)
    assert not any("ip_skipped" in r for r in resolved)
    # A skipped host must not read as one that has no address: the flag says
    # the question was never asked.
    assert all(r["ip"] is None and r["ip_skipped"] is True for r in skipped)
    assert all(r["ttl"] == TTL for r in rows)


def test_small_answers_keep_their_exact_shape(fake_dns):
    fake = fake_dns(ns_count=4, mx_count=2)

    records = managers.DomainManager().get_records("example.com", ip="192.0.2.10")

    assert fake.queries == {"ns": 4, "mx": 2}
    assert records["ns"] == [
        {"hostname": h, "ttl": TTL, "ip": "192.0.2.1"} for h in fake.ns_hosts
    ]
    assert records["mx"] == [
        {"preference": 10 + i, "hostname": h, "ttl": TTL, "ip": "192.0.2.1"}
        for i, h in enumerate(fake.mx_hosts)
    ]


def test_a_zero_limit_lists_every_host_and_resolves_none(fake_dns, monkeypatch):
    monkeypatch.setattr(managers, "DNS_HOST_RESOLVE_LIMIT", 0)
    fake = fake_dns(ns_count=3, mx_count=3)

    records = managers.DomainManager().get_records("example.com", ip="192.0.2.10")

    assert fake.queries == {"ns": 0, "mx": 0}
    assert len(records["ns"]) == 3 and len(records["mx"]) == 3
    assert all(r["ip_skipped"] for r in records["ns"] + records["mx"])
