"""Normalization and source-adapter tests.

The fixture below mirrors the *shapes* seen in live crt.sh output — wildcards,
the apex, unrelated SANs sharing a certificate, underscore labels, and
rfc822Name email entries. The email addresses are synthetic on purpose:
committing a real one would be the same privacy failure the code prevents.
"""

import json
import time
from unittest.mock import patch

import pytest

import subdomains

CRTSH_ROWS = [
    {"name_value": "*.example.com\nexample.com", "common_name": "example.com"},
    {"name_value": "api.example.com", "common_name": "api.example.com"},
    {"name_value": "API.Example.COM.", "common_name": "api.example.com"},
    {"name_value": "_dmarc.example.com", "common_name": "_dmarc.example.com"},
    {"name_value": "deep.nested.example.com", "common_name": None},
    {"name_value": "someone@example.com", "common_name": "someone@example.com"},
    {"name_value": "first.last@mail.example.com", "common_name": None},
    {"name_value": "unrelated.example.org", "common_name": "unrelated.example.org"},
    {"name_value": "notexample.com", "common_name": "notexample.com"},
]


def _names():
    return subdomains.extract_names(CRTSH_ROWS)


def test_email_addresses_are_discarded():
    """The load-bearing privacy rule. crt.sh's name_value carries rfc822Name
    entries from S/MIME certificates; 551 appear for nasa.gov alone."""
    names, _ = subdomains.normalize_names(_names(), "example.com", cap=100)
    assert not any("@" in n for n in names)
    # must not survive by stripping the local part
    assert "mail.example.com" not in names


def test_wildcards_fold_onto_the_apex_and_the_apex_is_dropped():
    names, _ = subdomains.normalize_names(_names(), "example.com", cap=100)
    assert "example.com" not in names
    assert not any(n.startswith("*") for n in names)


def test_unrelated_sans_on_a_shared_certificate_are_dropped():
    names, _ = subdomains.normalize_names(_names(), "example.com", cap=100)
    assert "unrelated.example.org" not in names


def test_a_suffix_match_is_not_a_substring_match():
    """ "notexample.com" ends with "example.com" but is a different domain."""
    names, _ = subdomains.normalize_names(_names(), "example.com", cap=100)
    assert "notexample.com" not in names


def test_underscore_labels_survive():
    """_dmarc and _acme-challenge are legitimate DNS labels."""
    names, _ = subdomains.normalize_names(_names(), "example.com", cap=100)
    assert "_dmarc.example.com" in names


def test_names_are_lowercased_deduplicated_and_sorted():
    names, total = subdomains.normalize_names(_names(), "example.com", cap=100)
    assert names == sorted(set(names))
    assert names.count("api.example.com") == 1
    assert total == len(names)


def test_capping_reports_the_true_total():
    names, total = subdomains.normalize_names(_names(), "example.com", cap=2)
    assert len(names) == 2
    assert total > 2


def test_an_internationalised_domain_survives_normalization():
    """Review Focus 5. Punycode is plain ASCII and must not be filtered out."""
    rows = [{"name_value": "www.xn--3e0b707e.kr", "common_name": None}]
    names, _ = subdomains.normalize_names(
        subdomains.extract_names(rows), "xn--3e0b707e.kr", cap=100
    )
    assert names == ["www.xn--3e0b707e.kr"]


def test_extract_names_tolerates_a_non_list_payload():
    """Review Focus 1. crt.sh answers {"error": ...} under load; iterating that
    dict yields strings, and .get on a string raises AttributeError."""
    assert subdomains.extract_names({"error": "rate limited"}) == []
    assert subdomains.extract_names(None) == []
    assert subdomains.extract_names("garbage") == []


def test_extract_names_skips_malformed_rows():
    assert subdomains.extract_names([{"no_name_value": 1}, None, "x"]) == []


class TestFetchFromSource:
    @pytest.mark.asyncio
    async def test_a_successful_fetch_returns_normalized_names(self):
        with patch.object(subdomains, "_fetch_sync", return_value=CRTSH_ROWS):
            names, total = await subdomains.fetch_from_source("example.com")
        assert "api.example.com" in names
        assert total == len(names)

    @pytest.mark.asyncio
    async def test_a_timeout_raises_rather_than_returning_empty(self):
        with patch.object(subdomains, "_fetch_sync", side_effect=TimeoutError):
            with pytest.raises(subdomains.SubdomainError):
                await subdomains.fetch_from_source("example.com")

    @pytest.mark.asyncio
    async def test_malformed_json_raises_rather_than_returning_empty(self):
        with patch.object(
            subdomains, "_fetch_sync", side_effect=json.JSONDecodeError("x", "y", 0)
        ):
            with pytest.raises(subdomains.SubdomainError):
                await subdomains.fetch_from_source("example.com")

    @pytest.mark.asyncio
    async def test_an_error_object_payload_yields_no_names_without_raising(self):
        """Review Focus 1. A 200 carrying {"error": ...} is a successful HTTP
        exchange with nothing in it — not an exception, and not a crash."""
        with patch.object(
            subdomains, "_fetch_sync", return_value={"error": "rate limited"}
        ):
            names, total = await subdomains.fetch_from_source("example.com")
        assert names == []
        assert total == 0


class TestGetSubdomains:
    @pytest.fixture(autouse=True)
    def isolated(self, tmp_path):
        subdomains.reset_state(store_path=str(tmp_path / "s.sqlite3"))
        yield
        subdomains.reset_state()

    @pytest.mark.asyncio
    async def test_a_miss_fetches_and_stores(self):
        with patch.object(subdomains, "_fetch_sync", return_value=CRTSH_ROWS) as f:
            first = await subdomains.get_subdomains("example.com")
            second = await subdomains.get_subdomains("example.com")
        assert f.call_count == 1  # second call served from the store
        assert first["names"] == second["names"]
        assert first["stale"] is False
        assert first["error"] is None

    @pytest.mark.asyncio
    async def test_a_stale_entry_is_served_immediately_and_refreshed_behind(self):
        with patch.object(subdomains, "_fetch_sync", return_value=CRTSH_ROWS):
            await subdomains.get_subdomains("example.com")
        with patch.object(subdomains, "SUBDOMAIN_CACHE_TTL", -1):
            with patch.object(subdomains, "_fetch_sync", return_value=CRTSH_ROWS) as f:
                result = await subdomains.get_subdomains("example.com")
                assert result["stale"] is True
                assert result["names"]  # served without waiting
                await subdomains.drain_background()
                assert f.call_count == 1

    @pytest.mark.asyncio
    async def test_a_failed_refresh_leaves_the_stale_entry_intact(self):
        with patch.object(subdomains, "_fetch_sync", return_value=CRTSH_ROWS):
            good = await subdomains.get_subdomains("example.com")
        with patch.object(subdomains, "SUBDOMAIN_CACHE_TTL", -1):
            with patch.object(subdomains, "_fetch_sync", side_effect=TimeoutError):
                await subdomains.get_subdomains("example.com")
                await subdomains.drain_background()
        with patch.object(subdomains, "_fetch_sync", side_effect=AssertionError):
            after = await subdomains.get_subdomains("example.com")
        assert after["names"] == good["names"]

    @pytest.mark.asyncio
    async def test_a_failure_on_a_cold_domain_reports_error_not_empty(self):
        """A model or a page reading names=[] would state as fact that the
        domain has no subdomains. Failure must be distinguishable."""
        with patch.object(subdomains, "_fetch_sync", side_effect=TimeoutError):
            result = await subdomains.get_subdomains("cold.example")
        assert result["error"]
        assert result["names"] == []
        assert result["count"] == 0

    @pytest.mark.asyncio
    async def test_a_failure_is_not_written_to_the_durable_store(self):
        with patch.object(subdomains, "_fetch_sync", side_effect=TimeoutError):
            await subdomains.get_subdomains("cold.example")
        assert subdomains._store.get("cold.example") is None

    @pytest.mark.asyncio
    async def test_concurrent_cold_requests_make_one_outbound_fetch(self):
        """Review Focus 4. Single-flight is keyed on the domain, not on the
        surface, so a page request and an MCP call coalesce with each other.

        `_fetch_sync` runs via asyncio.to_thread, so it can block on a plain
        threading.Event without stalling the loop the tasks live on.
        """
        import asyncio as aio
        import threading

        gate = threading.Event()
        calls = []

        def slow(domain):
            calls.append(domain)
            gate.wait(timeout=5)
            return CRTSH_ROWS

        with patch.object(subdomains, "_fetch_sync", side_effect=slow):
            tasks = [
                aio.create_task(subdomains.get_subdomains("example.com"))
                for _ in range(5)
            ]
            await aio.sleep(0.1)  # let every task reach the single-flight map
            # Proves coalescing while it still matters: after the gate opens
            # and every task completes, _inflight is empty either way, so
            # only checking after gather() would pass even without
            # single-flight.
            assert len(subdomains._inflight) == 1
            gate.set()
            results = await aio.gather(*tasks)

        assert len(calls) == 1
        assert all(r["names"] == results[0]["names"] for r in results)

    @pytest.mark.asyncio
    async def test_the_outbound_budget_refuses_a_cold_fetch_once_exhausted(self):
        with patch.object(subdomains, "_budget", subdomains._MinuteBudget(0)):
            with patch.object(subdomains, "_fetch_sync", side_effect=AssertionError):
                result = await subdomains.get_subdomains("cold.example")
        assert result["error"]
        assert result["names"] == []

    @pytest.mark.asyncio
    async def test_budget_exhaustion_does_not_poison_the_failure_cache(self):
        """Review I1. A budget refusal is our own back-pressure, not a source
        failure. Recording it into _failures would durably blacklist a cold
        domain for SUBDOMAIN_ERROR_TTL (five minutes) even though the shared
        budget refills within a minute and a fetch was never attempted --
        one client stays under the lookup rate limit while blacking out the
        feature for every other cold domain it names.
        """
        with patch.object(subdomains, "_budget", subdomains._MinuteBudget(0)):
            with patch.object(subdomains, "_fetch_sync", side_effect=AssertionError):
                exhausted = await subdomains.get_subdomains("exhausted.example")
        assert exhausted["error"]
        assert "exhausted.example" not in subdomains._failures

        # The budget has refilled (the patch above is out of scope, so the
        # real _budget from the `isolated` fixture is back in effect). A
        # DIFFERENT cold domain must be genuinely fetched, not answered
        # "lookup failed recently" from a negative-cache entry that was
        # never a real source failure.
        with patch.object(subdomains, "_fetch_sync", return_value=CRTSH_ROWS) as f:
            result = await subdomains.get_subdomains("different.example")
        assert f.call_count == 1
        assert result["error"] is None

    @pytest.mark.asyncio
    async def test_the_budget_does_not_block_a_cached_answer(self):
        with patch.object(subdomains, "_fetch_sync", return_value=CRTSH_ROWS):
            await subdomains.get_subdomains("example.com")
        with patch.object(subdomains, "_budget", subdomains._MinuteBudget(0)):
            result = await subdomains.get_subdomains("example.com")
        assert result["names"]
        assert result["error"] is None

    @pytest.mark.asyncio
    async def test_a_waiters_cancellation_does_not_poison_the_shared_future(self):
        """Review Critical 1. A waiter task uses the shared future as its
        _fut_waiter while suspended on it: Task.cancel() cancels whatever
        future a task is currently suspended on, so an unshielded
        `await existing` lets Task.cancel() on ONE waiter cancel the future
        the owner and every OTHER waiter depend on — a second, uninvolved
        waiter would be cancelled too, even though it never asked to be.
        _fetch_and_store must shield the waiter path so only the cancelled
        waiter's own task is affected.
        """
        import asyncio as aio
        import threading

        gate = threading.Event()

        def slow(domain):
            gate.wait(timeout=5)
            return CRTSH_ROWS

        with patch.object(subdomains, "_fetch_sync", side_effect=slow):
            owner = aio.create_task(subdomains._fetch_and_store("example.com"))
            await aio.sleep(0.05)  # owner claims _inflight, blocks in the thread
            assert "example.com" in subdomains._inflight

            waiter_to_cancel = aio.create_task(
                subdomains._fetch_and_store("example.com")
            )
            survivor = aio.create_task(subdomains._fetch_and_store("example.com"))
            await aio.sleep(0.05)  # both attach to the shared future

            waiter_to_cancel.cancel()
            with pytest.raises(aio.CancelledError):
                await waiter_to_cancel

            gate.set()
            owner_names, _ = await owner
            survivor_names, _ = await survivor  # must NOT be cancelled too

        assert owner_names
        assert survivor_names == owner_names

    @pytest.mark.asyncio
    async def test_the_owners_cancellation_gives_waiters_an_error_not_a_cancellation(
        self,
    ):
        """Review Critical 2. A cancelled owner must not publish
        CancelledError onto the shared future — every waiter riding it would
        then surface as a cancelled task rather than a normal error result,
        turning one abandoned request into N failed ones. The owner itself
        must still end up correctly cancelled.
        """
        import asyncio as aio
        import threading

        gate = threading.Event()

        def slow(domain):
            gate.wait(timeout=5)
            return CRTSH_ROWS

        try:
            with patch.object(subdomains, "_fetch_sync", side_effect=slow):
                owner = aio.create_task(subdomains._fetch_and_store("example.com"))
                await aio.sleep(0.05)
                assert "example.com" in subdomains._inflight

                waiter = aio.create_task(subdomains._fetch_and_store("example.com"))
                await aio.sleep(0.05)

                owner.cancel()
                with pytest.raises(aio.CancelledError):
                    await owner

                with pytest.raises(subdomains.SubdomainError):
                    await waiter
        finally:
            gate.set()  # release the blocked thread so it doesn't outlive the test

    @pytest.mark.asyncio
    async def test_a_failing_refresh_does_not_retry_on_every_stale_read(self):
        """Review Important. With the source failing, a stale domain must
        not schedule an unbounded series of background refreshes — each one
        spends a slot from the global per-minute budget, so one broken
        popular domain would otherwise starve every other domain's cold
        lookups. The stale entry keeps being served regardless.
        """
        with patch.object(subdomains, "_fetch_sync", return_value=CRTSH_ROWS):
            await subdomains.get_subdomains("example.com")
        with patch.object(subdomains, "SUBDOMAIN_CACHE_TTL", -1):
            with patch.object(subdomains, "_fetch_sync", side_effect=TimeoutError) as f:
                first = await subdomains.get_subdomains("example.com")
                await subdomains.drain_background()
                assert f.call_count == 1

                second = await subdomains.get_subdomains("example.com")
                await subdomains.drain_background()
                assert f.call_count == 1  # no second refresh while the
                # recorded failure is still fresh

        assert first["stale"] is True
        assert second["stale"] is True
        assert second["names"]  # still served despite the failing source

    @pytest.mark.asyncio
    async def test_a_stale_failure_entry_is_evicted_opportunistically(self):
        """Review Important (promoted). Nothing but reset_state() — test only
        — ever removed a _failures entry, so in production every domain that
        ever failed left a permanent dict entry for the life of the process.
        Recording a new failure must sweep out old ones instead.
        """
        with patch.object(subdomains, "_fetch_sync", side_effect=TimeoutError):
            await subdomains.get_subdomains("old.example")
        assert "old.example" in subdomains._failures
        # Backdate it past the error TTL, as if it had sat there for a while.
        subdomains._failures["old.example"] = (
            time.time() - subdomains.SUBDOMAIN_ERROR_TTL - 1
        )

        with patch.object(subdomains, "_fetch_sync", side_effect=TimeoutError):
            await subdomains.get_subdomains("new.example")

        assert "old.example" not in subdomains._failures
        assert "new.example" in subdomains._failures
