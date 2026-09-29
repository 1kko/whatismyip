"""Store tests. No mocks and no network: the store knows nothing about crt.sh."""

import time

import pytest

from subdomain_store import SubdomainStore


@pytest.fixture
def store(tmp_path):
    s = SubdomainStore(path=str(tmp_path / "t.sqlite3"), max_rows=5)
    yield s
    s.close()


def test_put_then_get_round_trips(store):
    store.put("example.com", ["a.example.com", "b.example.com"], 2, False, "crt.sh")
    entry = store.get("example.com")
    assert entry.names == ["a.example.com", "b.example.com"]
    assert entry.count == 2
    assert entry.truncated is False
    assert entry.source == "crt.sh"
    assert entry.age() < 5


def test_get_returns_none_for_an_unknown_domain(store):
    assert store.get("nope.example") is None


def test_put_replaces_an_existing_row(store):
    store.put("example.com", ["old.example.com"], 1, False, "crt.sh")
    store.put("example.com", ["new.example.com"], 1, False, "crt.sh")
    assert store.get("example.com").names == ["new.example.com"]


def test_count_is_the_true_total_not_the_stored_length(store):
    """`names` is capped; `count` must still report what the source held, or a
    caller cannot tell a short list from a truncated one."""
    store.put("big.example", ["a.big.example"], 9000, True, "crt.sh")
    entry = store.get("big.example")
    assert len(entry.names) == 1
    assert entry.count == 9000
    assert entry.truncated is True


def test_prune_evicts_oldest_first(store):
    for i in range(8):
        store.put(f"d{i}.example", [f"a.d{i}.example"], 1, False, "crt.sh")
        time.sleep(0.01)  # distinct fetched_at values
    store.prune()
    assert store.get("d0.example") is None
    assert store.get("d7.example") is not None


def test_a_domain_containing_path_characters_is_stored_as_data(store):
    """The key is attacker-influenced. It is a bound parameter, never a path."""
    nasty = "../../etc/passwd"
    store.put(nasty, ["x.example.com"], 1, False, "crt.sh")
    assert store.get(nasty).names == ["x.example.com"]


def test_an_unwritable_store_degrades_instead_of_raising(tmp_path):
    """Review Focus 2. Persistence is a cache. A read-only volume or a full disk
    must cost us the cache, not the request.

    A merely *missing* parent directory would not test this: _open() calls
    os.makedirs(exist_ok=True) and would simply create it. Putting a regular
    file where the directory would go is what makes makedirs fail.
    """
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    s = SubdomainStore(path=str(blocker / "t.sqlite3"), max_rows=5)
    s.put("example.com", ["a.example.com"], 1, False, "crt.sh")
    assert s.get("example.com") is None
    s.close()


def test_a_corrupt_database_degrades_instead_of_raising(tmp_path):
    """Review Focus 2, the other half: a truncated file already on the volume."""
    path = tmp_path / "corrupt.sqlite3"
    path.write_bytes(b"this is not a database")
    s = SubdomainStore(path=str(path), max_rows=5)
    s.put("example.com", ["a.example.com"], 1, False, "crt.sh")
    assert s.get("example.com") is None
    s.close()
