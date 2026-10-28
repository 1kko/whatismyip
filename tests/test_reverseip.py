"""reverseip.py's source table, licence lines and refresh, and the saved copy
of OpenINTEL's terms. No network: the one real child process reads a bucket
served on loopback."""

import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import config
import reverseip
from main import app
from reverseip import ReverseIpManager, parse_sources
from reverseip_fixtures import (
    DAY,
    NOW,
    ROWS,
    Row,
    build_manager,
    bucket_with,
    key,
    serve,
)

ROOT = Path(__file__).resolve().parent.parent
TERMS = ROOT / "static" / "licenses" / "openintel-terms.html"
DEFAULT_SOURCES = "tranco,umbrella,radar,majestic,crux:global,crux:kr"

client = TestClient(app)
# Every build here runs on SQLite as Linux has it (conftest's stock_sqlite).
pytestmark = pytest.mark.usefixtures("stock_sqlite")


def _text(html: str) -> str:
    return " ".join(re.sub(r"<[^>]+>", " ", html).split())


class TestTermsCopy:
    def test_the_copy_carries_the_attribution_the_code_shows(self):
        assert config.OPENINTEL_ATTRIBUTION in _text(TERMS.read_text(encoding="utf-8"))

    def test_the_copy_is_the_2024_12_11_document(self):
        text = _text(TERMS.read_text(encoding="utf-8"))
        assert "Document last updated: Wednesday, December 11, 2024." in text
        assert "By clicking the button below" not in text  # the document only

    def test_it_is_served(self):
        response = client.get("/static/licenses/openintel-terms.html")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")


class TestSources:
    def test_the_default_six(self):
        sources = reverseip.parse_sources(DEFAULT_SOURCES)
        assert [s.id for s in sources] == [
            "tranco",
            "umbrella",
            "radar",
            "majestic",
            "crux:global",
            "crux:kr",
        ]
        assert sources[1].label == "Cisco Umbrella"
        assert sources[5].label == "Chrome UX Report (KR)"
        assert sources[5].path == "source=crux/country-code=kr"
        # the bucket keeps global CrUX under a country code of its own
        assert sources[4].label == "Chrome UX Report (global)"
        assert sources[4].path == "source=crux/country-code=global"
        assert sources[0].path == "source=tranco"

    def test_an_unknown_source_is_refused(self):
        with pytest.raises(ValueError, match="alexa"):
            reverseip.parse_sources("tranco,alexa")

    def test_a_repeated_id_is_kept_once_and_logged(self, caplog):
        caplog.set_level(logging.WARNING, logger="reverseip")
        sources = reverseip.parse_sources("tranco,crux:kr, tranco,crux:kr,umbrella")
        assert [s.id for s in sources] == ["tranco", "crux:kr", "umbrella"]
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 2
        assert "tranco" in warnings[0].getMessage()
        assert "crux:kr" in warnings[1].getMessage()

    def test_a_repeated_id_builds(self, tmp_path):
        manager = build_manager(tmp_path, sources="tranco,tranco")
        assert manager.for_address("93.184.215.14")["total"] == 4

    def test_the_coverage_sentence(self):
        sources = reverseip.parse_sources(DEFAULT_SOURCES)
        assert reverseip.coverage_sentence(sources) == (
            "Names on the Tranco, Cisco Umbrella, Cloudflare Radar, Majestic "
            "Million and Chrome UX Report (global, KR) top lists only."
        )

    def test_one_source_reads_as_a_sentence(self):
        assert reverseip.coverage_sentence(reverseip.parse_sources("tranco")) == (
            "Names on the Tranco top list only."
        )

    def test_the_file_stem(self):
        assert reverseip.file_stem("crux:kr") == "crux-kr"


class TestLicenceLines:
    def test_the_five_keys_come_from_config(self):
        lines = reverseip.licence_lines()
        assert set(lines) == {
            "coverage",
            "license",
            "license_url",
            "terms_url",
            "attribution",
        }
        assert lines["license"] == config.OPENINTEL_LICENSE == "CC BY-NC-SA 4.0"
        assert lines["license_url"] == config.OPENINTEL_LICENSE_URL
        assert lines["terms_url"] == config.REVERSEIP_TERMS_URL
        assert lines["attribution"] == config.OPENINTEL_ATTRIBUTION
        assert lines["coverage"] == reverseip.coverage_sentence(
            reverseip.parse_sources(config.REVERSEIP_SOURCES)
        )

    def test_coverage_names_the_sources_given(self):
        lines = reverseip.licence_lines(reverseip.parse_sources("tranco"))
        assert lines["coverage"] == "Names on the Tranco top list only."


def _summary(**states):
    sources = {
        source_id: {"state": state, "date": "2026-10-20", "error": None}
        for source_id, state in states.items()
    }
    return json.dumps({"built": True, "sources": sources}) + "\n"


def _answering(calls, returncode=0, stdout="", stderr=""):
    """A runner that records each call and answers as the child would."""

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)

    return runner


class TestRefresh:
    def test_refresh_runs_the_child_without_pythonpath(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PYTHONPATH", "/otel/sitecustomize")
        calls = []

        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(
                args,
                0,
                stdout='{"built": true, "sources": '
                '{"tranco": {"state": "downloaded"}}}\n',
                stderr="",
            )

        manager = ReverseIpManager(
            str(tmp_path), parse_sources("tranco"), enabled=True, runner=runner
        )
        assert manager.refresh() is True and manager.build_attempted
        args, kwargs = calls[0]
        assert args[0] == sys.executable
        assert args[1:3] == ["-m", "reverseip_build"]
        assert json.loads(args[3]) == {
            "directory": str(tmp_path),
            "sources": "tranco",
            "base_url": config.REVERSEIP_BASE_URL,
        }
        assert "PYTHONPATH" not in kwargs["env"]
        assert kwargs["env"]["PATH"] == os.environ["PATH"]
        assert kwargs["cwd"] == os.path.dirname(os.path.abspath(reverseip.__file__))
        assert kwargs["capture_output"] is True and kwargs["text"] is True
        assert kwargs["timeout"] == config.REVERSEIP_BUILD_TIMEOUT_SECONDS

    def test_the_child_gets_an_absolute_directory_and_every_source(
        self, tmp_path, monkeypatch
    ):
        # the child runs in reverseip.py's directory, not the parent's
        monkeypatch.chdir(tmp_path)
        calls = []
        manager = ReverseIpManager(
            os.path.join("data", "reverseip"),
            parse_sources("crux:kr,tranco"),
            enabled=True,
            runner=_answering(calls, stdout=_summary(tranco="current")),
        )
        manager.refresh()
        settings = json.loads(calls[0][0][3])
        assert settings["directory"] == os.path.join(os.getcwd(), "data", "reverseip")
        assert settings["sources"] == "crux:kr,tranco"

    def test_the_child_logs_through_the_parent(self, tmp_path, caplog):
        caplog.set_level(logging.INFO, logger="reverseip")
        manager = ReverseIpManager(
            str(tmp_path),
            parse_sources("tranco"),
            enabled=True,
            runner=_answering(
                [],
                stdout=_summary(tranco="downloaded"),
                stderr="INFO reverse IP: tranco 2026-10-20\nINFO built\n",
            ),
        )
        assert manager.refresh() is True
        assert [
            (r.levelno, r.getMessage()) for r in caplog.records if r.name == "reverseip"
        ] == [
            (logging.INFO, "reverseip_build: INFO reverse IP: tranco 2026-10-20"),
            (logging.INFO, "reverseip_build: INFO built"),
        ]

    @pytest.mark.parametrize(
        ("state", "current"),
        [
            ("current", True),
            ("downloaded", True),
            ("waiting", False),
            ("failed", False),
        ],
    )
    def test_true_only_when_every_source_is_current(self, tmp_path, state, current):
        manager = ReverseIpManager(
            str(tmp_path),
            parse_sources("tranco,umbrella"),
            enabled=True,
            runner=_answering([], stdout=_summary(tranco="current", umbrella=state)),
        )
        assert manager.refresh() is current

    def test_a_failed_child_is_false_and_logged(self, tmp_path, caplog):
        caplog.set_level(logging.INFO, logger="reverseip")
        manager = ReverseIpManager(
            str(tmp_path),
            parse_sources("tranco"),
            enabled=True,
            runner=_answering(
                [],
                returncode=1,
                stderr="Traceback (most recent call last):\nRuntimeError: boom\n",
            ),
        )
        assert manager.refresh() is False
        assert manager.build_attempted
        messages = [(r.levelno, r.getMessage()) for r in caplog.records]
        assert (logging.INFO, "reverseip_build: RuntimeError: boom") in messages
        errors = [m for level, m in messages if level == logging.ERROR]
        assert len(errors) == 1 and "exit" in errors[0] and "1" in errors[0]

    @pytest.mark.parametrize("stdout", ["", "not json\n", '{"built": true}\n'])
    def test_unreadable_output_is_false_and_logged(self, tmp_path, caplog, stdout):
        manager = ReverseIpManager(
            str(tmp_path),
            parse_sources("tranco"),
            enabled=True,
            runner=_answering([], stdout=stdout),
        )
        assert manager.refresh() is False
        assert manager.build_attempted
        assert [r for r in caplog.records if r.levelno == logging.ERROR]

    def test_a_timed_out_child_is_false(self, tmp_path, caplog):
        caplog.set_level(logging.INFO, logger="reverseip")

        def runner(args, **kwargs):
            # run() kills the child; what it wrote comes as bytes
            raise subprocess.TimeoutExpired(
                args, kwargs["timeout"], output=b"", stderr=b"INFO listing tranco\n"
            )

        manager = ReverseIpManager(
            str(tmp_path), parse_sources("tranco"), enabled=True, runner=runner
        )
        assert manager.refresh() is False
        assert manager.build_attempted
        messages = [(r.levelno, r.getMessage()) for r in caplog.records]
        assert (logging.INFO, "reverseip_build: INFO listing tranco") in messages
        assert any(level == logging.ERROR for level, _ in messages)

    def test_disabled_runs_nothing(self, tmp_path):
        calls = []
        manager = ReverseIpManager(
            str(tmp_path),
            parse_sources("tranco"),
            enabled=False,
            runner=_answering(calls, stdout=_summary(tranco="current")),
        )
        assert manager.refresh() is True
        assert calls == []
        assert manager.build_attempted is False
        assert os.listdir(tmp_path) == []

    def test_the_defaults(self):
        manager = ReverseIpManager(enabled=True)
        assert manager._runner is subprocess.run
        assert manager.directory == config.REVERSEIP_DIR
        assert manager.path == os.path.join(config.REVERSEIP_DIR, "reverseip.sqlite3")
        assert manager.sources == parse_sources(config.REVERSEIP_SOURCES)
        assert manager.build_attempted is False

    def test_the_sources_are_read_only_when_enabled(self, monkeypatch):
        # a bad id must not stop the service starting while the feature is off
        monkeypatch.setattr(config, "REVERSEIP_SOURCES", "tranco,alexa")
        assert ReverseIpManager(enabled=False).sources == ()
        with pytest.raises(ValueError, match="alexa"):
            ReverseIpManager(enabled=True)

    def test_lookup_imports_with_a_bad_id_while_off(self):
        env = {
            **os.environ,
            "REVERSEIP_ENABLED": "false",
            "REVERSEIP_SOURCES": "tranco,alexa",
        }
        done = subprocess.run(
            [
                sys.executable,
                "-c",
                "import lookup; print(lookup.reverse_ip_manager.sources)",
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == "()"

    @pytest.mark.parametrize(
        ("given", "used"),
        [
            (
                "https://mirror.test/openintel-public",
                "https://mirror.test/openintel-public/",
            ),
            (
                "https://mirror.test/openintel-public/",
                "https://mirror.test/openintel-public/",
            ),
            (
                "https://mirror.test/openintel-public//",
                "https://mirror.test/openintel-public/",
            ),
        ],
    )
    def test_the_base_url_ends_with_one_slash(self, given, used):
        done = subprocess.run(
            [sys.executable, "-c", "import config; print(config.REVERSEIP_BASE_URL)"],
            cwd=ROOT,
            env={**os.environ, "REVERSEIP_BASE_URL": given},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == used

    def test_the_real_child_builds_over_loopback(self, tmp_path):
        """python -m reverseip_build against FakeBucket served on 127.0.0.1.
        The child lists the real month and ages its copy by the real clock, so
        the partition is dated today, UTC."""
        today = datetime.now(timezone.utc).date().isoformat()
        bucket = bucket_with(today)
        with serve(bucket) as base_url:
            manager = ReverseIpManager(
                str(tmp_path), parse_sources("tranco"), enabled=True, clock=lambda: NOW
            )
            with patch.object(reverseip, "REVERSEIP_BASE_URL", base_url):
                assert manager.refresh() is True
        assert (tmp_path / "reverseip.sqlite3").exists()
        # over real HTTP, the object's URL is the base URL and its key
        assert [url for url, wanted in bucket.requests if wanted] == [
            base_url + key("tranco", today)
        ]
        con = sqlite3.connect(str(tmp_path / "reverseip.sqlite3"))
        try:
            date, pairs, error = con.execute(
                "SELECT date, pairs, error FROM source_meta WHERE id = 'tranco'"
            ).fetchone()
        finally:
            con.close()
        assert (date, error) == (today, None) and pairs > 0


def test_an_address_with_names(tmp_path):
    answer = build_manager(tmp_path).for_address("93.184.215.14")
    assert answer["total"] == 4
    assert answer["names"][:2] == ["example.com", "shop.example.org"]
    assert answer["truncated"] is False
    assert answer["block"] == {"prefix": "93.184.215.0/24", "addresses": 4, "names": 7}
    assert answer["as_of"] == DAY
    assert answer["sources"] == [{"id": "tranco", "label": "Tranco", "date": DAY}]
    assert answer["unavailable"] == []
    assert answer["license"] == "CC BY-NC-SA 4.0"
    assert answer["attribution"] == config.OPENINTEL_ATTRIBUTION
    assert answer["terms_url"] == config.REVERSEIP_TERMS_URL
    assert answer["coverage"] == "Names on the Tranco top list only."
    assert list(answer) == [
        "total",
        "names",
        "truncated",
        "block",
        "as_of",
        "sources",
        "unavailable",
        "coverage",
        "license",
        "license_url",
        "terms_url",
        "attribution",
    ]


def test_the_limit_truncates(tmp_path):
    answer = build_manager(tmp_path).for_address("93.184.215.14", limit=2)
    assert answer["names"] == ["example.com", "shop.example.org"]
    assert answer["total"] == 4 and answer["truncated"] is True


def test_no_listed_name_is_zero_not_null(tmp_path):
    answer = build_manager(tmp_path).for_address("175.214.27.215")
    assert (answer["total"], answer["names"], answer["truncated"]) == (0, [], False)
    assert answer["block"] == {"prefix": "175.214.27.0/24", "addresses": 0, "names": 0}


def test_a_mapped_address_reads_as_ipv4(tmp_path):
    answer = build_manager(tmp_path).for_address("::ffff:93.184.215.15")
    assert answer["names"] == ["mapped.example.org"]
    assert answer["block"]["prefix"] == "93.184.215.0/24"


def test_an_ipv6_block_is_a_48(tmp_path):
    answer = build_manager(tmp_path).for_address("2606:2800:21f:1::1")
    assert answer["total"] == 0
    assert answer["block"] == {
        "prefix": "2606:2800:21f::/48",
        "addresses": 1,
        "names": 1,
    }


def test_no_database_is_unknown(tmp_path):
    manager = ReverseIpManager(
        str(tmp_path), parse_sources("tranco"), enabled=True, clock=lambda: NOW
    )
    answer = manager.for_address("93.184.215.14")
    assert answer["total"] is None and answer["names"] is None
    assert answer["block"] is None and answer["as_of"] is None
    assert answer["truncated"] is None and answer["sources"] == []
    assert answer["unavailable"] == [
        {"source": "tranco", "label": "Tranco", "reason": "not downloaded yet"}
    ]
    assert answer["license"] == "CC BY-NC-SA 4.0"
    manager.build_attempted = True
    assert manager.for_address("1.1.1.1")["unavailable"][0]["reason"] == (
        "the database has not been built"
    )


def test_an_unreadable_file_is_unknown_and_logged_once(tmp_path, caplog):
    (tmp_path / reverseip.DATABASE_NAME).write_bytes(b"not a database" * 100)
    manager = ReverseIpManager(
        str(tmp_path), parse_sources("tranco"), enabled=True, clock=lambda: NOW
    )
    with caplog.at_level(logging.ERROR):
        first = manager.for_address("1.1.1.1")
        manager.for_address("1.1.1.1")
    assert first["total"] is None
    assert first["unavailable"][0]["reason"] == "the database could not be read"
    assert len([r for r in caplog.records if r.levelno == logging.ERROR]) == 1


def test_a_database_from_another_release_is_unknown(tmp_path):
    manager = build_manager(tmp_path)
    con = sqlite3.connect(manager.path)
    con.execute("PRAGMA user_version = 99")
    con.close()
    reason = manager.for_address("1.1.1.1")["unavailable"][0]["reason"]
    assert reason == "the database is from another release"


def test_every_source_stale_is_unknown(tmp_path):
    manager = build_manager(tmp_path, now=NOW)
    manager._clock = lambda: NOW + 5 * 86400
    answer = manager.for_address("93.184.215.14")
    assert answer["total"] is None
    assert (
        answer["unavailable"][0]["reason"]
        == f"last measured {DAY}, older than 96 hours"
    )


def test_the_build_age_error_reads_with_its_date(tmp_path):
    manager = build_manager(tmp_path, now=NOW + 5 * 86400)
    manager._clock = lambda: NOW + 5 * 86400
    answer = manager.for_address("93.184.215.14")
    assert (
        answer["unavailable"][0]["reason"]
        == f"last measured {DAY}, older than 96 hours"
    )


def test_a_build_error_is_the_reason(tmp_path):
    manager = build_manager(tmp_path)
    con = sqlite3.connect(manager.path)
    con.execute("UPDATE source_meta SET error = 'no copy', date = NULL")
    con.commit()
    con.close()
    assert manager.for_address("1.1.1.1")["unavailable"][0]["reason"] == "no copy"


def test_a_partial_set_still_answers(tmp_path):
    build_manager(tmp_path, sources="tranco")
    manager = ReverseIpManager(
        str(tmp_path),
        parse_sources("tranco,umbrella"),
        enabled=True,
        clock=lambda: NOW,
    )
    answer = manager.for_address("93.184.215.14")
    assert answer["total"] == 4
    assert answer["unavailable"] == [
        {
            "source": "umbrella",
            "label": "Cisco Umbrella",
            "reason": "not in the database",
        }
    ]
    assert "Umbrella" in answer["coverage"]


def test_disabled_answers_none(tmp_path):
    manager = ReverseIpManager(str(tmp_path), (), enabled=False)
    assert manager.for_address("1.1.1.1") is None
    assert manager.names_under("example.com") is None
    assert manager.status() == {"enabled": False}


def test_names_under_a_domain(tmp_path):
    answer = build_manager(tmp_path).names_under("example.com")
    assert answer["names"] == ["a.b.example.com", "norank.example.com"]
    assert answer["count"] == 2 and answer["truncated"] is False
    assert answer["as_of"] == DAY and answer["unavailable"] == []
    assert answer["attribution"] == config.OPENINTEL_ATTRIBUTION


def test_names_under_matches_on_a_label_boundary(tmp_path):
    rows = ROWS + [
        Row("notexample.com.", "A", "A", "ans", "93.184.215.20", None, "50"),
        Row("x.notexample.com.", "A", "A", "ans", "93.184.215.20", None, "50"),
    ]
    answer = build_manager(tmp_path, rows).names_under("example.com")
    assert answer["names"] == ["a.b.example.com", "norank.example.com"]


def test_names_under_a_deeper_target_and_any_spelling(tmp_path):
    answer = build_manager(tmp_path).names_under("B.Example.COM.")
    assert answer["names"] == ["a.b.example.com"]


def test_names_under_caps_and_counts(tmp_path):
    answer = build_manager(tmp_path).names_under("example.com", cap=1)
    assert answer["names"] == ["a.b.example.com"]
    assert answer["count"] == 2 and answer["truncated"] is True


def test_none_under_is_zero(tmp_path):
    answer = build_manager(tmp_path).names_under("1kko.com")
    assert (answer["names"], answer["count"]) == ([], 0)


def test_names_under_without_a_database_is_unknown(tmp_path):
    manager = ReverseIpManager(
        str(tmp_path), parse_sources("tranco"), enabled=True, clock=lambda: NOW
    )
    answer = manager.names_under("example.com")
    assert answer["names"] is None and answer["count"] is None
    assert answer["unavailable"][0]["reason"] == "not downloaded yet"


def test_status_and_stale_sources(tmp_path):
    manager = build_manager(tmp_path)
    assert manager.status() == {
        "enabled": True,
        "database": True,
        "sources": {
            "tranco": {
                "label": "Tranco",
                "date": DAY,
                "age_hours": 36.0,
                "pairs": manager.status()["sources"]["tranco"]["pairs"],
                "stale": False,
            }
        },
    }
    assert manager.status()["sources"]["tranco"]["pairs"] > 0
    assert manager.stale_sources() == []
    manager._clock = lambda: NOW + 5 * 86400
    assert manager.status()["sources"]["tranco"]["stale"] is True
    assert manager.stale_sources() == [
        f"the Tranco list is unavailable to lookups: last measured {DAY}, "
        "older than 96 hours"
    ]


def test_status_and_stale_sources_without_a_database(tmp_path):
    manager = ReverseIpManager(
        str(tmp_path), parse_sources("tranco"), enabled=True, clock=lambda: NOW
    )
    assert manager.status() == {"enabled": True, "database": False, "sources": {}}
    assert manager.stale_sources() == []


def test_hosts():
    assert ReverseIpManager("x", (), enabled=False).hosts() == ["object.openintel.nl"]


def test_a_swapped_file_is_read_afresh(tmp_path):
    manager = build_manager(tmp_path)
    assert manager.for_address("93.184.215.14")["total"] == 4
    other = tmp_path / "other"
    other.mkdir()
    build_manager(other, rows=ROWS[:1])
    os.replace(other / reverseip.DATABASE_NAME, manager.path)
    assert manager.for_address("93.184.215.14")["names"] == ["example.com"]


def test_names_under_reads_no_more_than_the_cap(tmp_path):
    rows = [
        Row(f"h{i}.big.example.", "A", "A", "ans", "93.184.215.30", None, "5")
        for i in range(30)
    ]
    manager = build_manager(tmp_path, rows)
    answer = manager.names_under("big.example", cap=5)
    assert len(answer["names"]) == 5
    assert answer["count"] == 30 and answer["truncated"] is True
    assert answer["names"] == sorted(answer["names"])
    traced = []
    manager._database()[0].set_trace_callback(traced.append)
    manager.names_under("big.example", cap=5)
    assert any("LIMIT ?" in sql or "LIMIT 5" in sql for sql in traced)
