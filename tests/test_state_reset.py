"""Every test starts from the state the process started in, and no run starts
from another run's.

The ban list and the geo rules are files the security managers load when main
is imported. They lived at fixed /tmp paths every pytest run on the machine
shared, so the RU blocklist test_security.py PUTs through /admin/geo/rules was
the next run's starting point, and five test files pinned geo-blocking open to
get around it. In-process, conftest's reset_security_state cleared the lookup
rate limiter and the ban list alone; the MCP bucket, the WHOIS cache, the RDAP
breaker, the self page's lookups in flight and the refresh failure count were
cleared, or not, file by file.
"""

import json
import re
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import lookup
import main
import rdap

pytest_plugins = ["pytester"]

TESTS = Path(__file__).parent

client = TestClient(main.app)
ADMIN = {"api-key": "test-secret-key"}


def test_geo_rules_a_test_puts_are_gone_for_the_next(reset_state):
    rules = {"mode": "blocklist", "blocked_countries": ["RU"]}
    assert client.put("/admin/geo/rules", json=rules, headers=ADMIN).status_code == 200
    assert main.geo_block_manager.config["blocked_countries"] == ["RU"]

    reset_state()

    config = main.geo_block_manager.config
    assert config["mode"] == "disabled"
    assert config["blocked_countries"] == []
    on_disk = json.loads(Path(main.geo_block_manager.config_file).read_text())
    assert on_disk == config


def test_every_piece_of_module_state_is_put_back(reset_state):
    ip = "203.0.113.60"
    main.rate_limiter.allow_request(ip)
    main.mcp_rate_limiter.allow_request(ip)
    main.ip_ban_manager.ban_ip(ip, reason="manual", duration=3600)
    lookup._whois_cache.set(ip, {"source": "rdap"}, ttl=600)
    main._self_whois_tasks[ip] = object()
    main._refresh_failures["GeoLite2-City"] = 2
    for _ in range(rdap.rdap_breaker.threshold):
        rdap.rdap_breaker.record_failure("rdap.example.net")
    assert main.rdap_breaker.open_hosts() == ["rdap.example.net"]

    reset_state()

    assert not main.rate_limiter.request_history
    assert not main.mcp_rate_limiter.request_history
    assert main.ip_ban_manager.banned_ips == {}
    assert lookup._whois_cache.get(ip) is None
    assert main._self_whois_tasks == {}
    assert main._refresh_failures == {}
    # One breaker under both names: lookup_rdap records into rdap's,
    # health_reasons reads main's.
    assert main.rdap_breaker is rdap.rdap_breaker
    assert main.rdap_breaker.open_hosts() == []


@pytest.mark.parametrize(
    "route, key",
    [
        ("/admin/geo/block/country/RU", "blocked_countries"),
        ("/admin/geo/allow/country/KR", "allowed_countries"),
    ],
)
def test_a_country_added_through_the_admin_api_is_gone_for_the_next(
    reset_state, route, key
):
    """These routes append to the list in place. Were it the environment's own
    default list, load_config() would hand the country straight back."""
    assert client.post(route, headers=ADMIN).status_code == 200
    assert main.geo_block_manager.config[key] != []

    reset_state()

    assert main.geo_block_manager.config[key] == []


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


# What conftest's reset covers, done again by hand. Search whole files so a
# normally formatted multiline patch cannot hide a geo-access bypass.
RESET_BY_HAND = re.compile(
    r"banned_ips\.clear\(\)"
    r"|ip_ban_manager\.save_bans\(\)"
    r"|request_history\.clear\(\)"
    r"|_whois_cache(?:\._data)?\.clear\(\)"
    r"|[\"']_whois_cache[\"']\s*,\s*lookup\.TTLCache\(\)"
    r"|(?:_self_whois_tasks|TASKS)\.clear\(\)"
    r"|_refresh_failures\.clear\(\)"
    r"|geo_block_manager\.load_config\(\)"
    r"|check_access[\"']\s*,\s*return_value\s*=\s*allowed",
    re.S,
)


def test_no_test_file_resets_what_conftest_resets():
    """A mid-test clean slate lifts only what the preceding step changed."""
    found = []
    for path in sorted(TESTS.glob("test_*.py")):
        if path == Path(__file__):
            continue
        source = path.read_text()
        for match in RESET_BY_HAND.finditer(source):
            number = source.count("\n", 0, match.start()) + 1
            excerpt = " ".join(match.group(0).split())
            found.append(f"{path.name}:{number}: {excerpt}")
    assert found == [], "reset by hand outside conftest:\n" + "\n".join(found)


def test_reset_guard_sees_a_multiline_geo_bypass():
    source = """patch(
        "main.geo_block_manager.check_access",
        return_value=allowed,
    )"""
    assert RESET_BY_HAND.search(source)
