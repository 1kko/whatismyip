"""Every test starts from the state the process started in, and no run starts
from another run's.

The ban list and the geo rules are files the security managers load when main
is imported. They lived at fixed /tmp paths every pytest run on the machine
shared, so the RU blocklist test_security.py PUTs through /admin/geo/rules was
the next run's starting point, and five test files pinned geo-blocking open to
get around it.
"""

import json
import tempfile
from pathlib import Path

import main

pytest_plugins = ["pytester"]

TESTS = Path(__file__).parent


def test_the_state_files_live_in_a_directory_of_this_runs_own():
    state_dir = Path(main.ip_ban_manager.ban_file).parent
    assert state_dir.name.startswith("whatismyip-test-")
    assert state_dir.parent == Path(tempfile.gettempdir())
    assert Path(main.geo_block_manager.config_file).parent == state_dir
    assert Path(main.ip_rule_manager.rules_file).parent == state_dir


# Run twice under a copy of the real conftest, in a fresh interpreter each time:
# records what the run's managers loaded, then leaves behind what
# test_security.py's tests do, a ban and a geo blocklist. The managers are
# built here exactly as main builds them at import.
ONE_RUN = """
import json
import os
from pathlib import Path

import config
from security import GeoBlockManager, IPBanManager


def test_a_run():
    bans = IPBanManager()
    geo = GeoBlockManager(None)
    Path(os.environ["STATE_RECORD"]).write_text(json.dumps({
        "files": [config.BANNED_IPS_FILE, config.GEO_RULES_FILE],
        "bans": bans.banned_ips,
        "geo": geo.config,
    }))
    bans.ban_ip("203.0.113.60", reason="suspicious_request", duration=86400)
    geo.config.update(mode="blocklist", blocked_countries=["RU"])
    geo.save_config()
"""


def test_a_run_starts_from_nothing_another_run_left(pytester, monkeypatch):
    pytester.makeconftest((TESTS / "conftest.py").read_text(encoding="utf-8"))
    pytester.makepyfile(test_one_run=ONE_RUN)
    # The fresh interpreter imports config and security from the repository.
    monkeypatch.setenv("PYTHONPATH", str(TESTS.parent))
    # A developer's .env may switch geo-blocking on. load_dotenv() writes it
    # into os.environ, so the inner runs inherit it from here as they would
    # from a .env, and must start with geo-blocking off all the same.
    monkeypatch.setenv("GEO_MODE", "blocklist")
    monkeypatch.setenv("GEO_BLOCKED_COUNTRIES", "CN,RU,KP")
    monkeypatch.setenv("GEO_ALLOWED_COUNTRIES", "KR")
    monkeypatch.setenv("GEO_BLOCK_UNKNOWN", "true")
    records = []
    for n in (1, 2):
        record = pytester.path / f"run{n}.json"
        monkeypatch.setenv("STATE_RECORD", str(record))
        result = pytester.runpytest_subprocess("-p", "no:cacheprovider")
        result.assert_outcomes(passed=1)
        records.append(json.loads(record.read_text()))

    first, second = records
    # The second run loaded none of the first run's bans or geo rules.
    assert second["bans"] == {}
    for record in records:
        # Whatever the environment said, and whatever the first run saved,
        # each run starts with geo-blocking off and no country listed.
        geo = record["geo"]
        assert (geo["mode"], geo["blocked_countries"]) == ("disabled", [])
        assert (geo["allowed_countries"], geo["block_unknown"]) == ([], False)
        state_dirs = {Path(f).parent for f in record["files"]}
        assert len(state_dirs) == 1
        (state_dir,) = state_dirs
        # Not /tmp/test_*.json: a directory of the run's own, gone with it.
        assert state_dir.name.startswith("whatismyip-test-")
        assert not state_dir.exists()
    assert first["files"] != second["files"]
