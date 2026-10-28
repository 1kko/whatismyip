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
from reverseip_fixtures import NOW, bucket_with, key, serve

ROOT = Path(__file__).resolve().parent.parent
TERMS = ROOT / "static" / "licenses" / "openintel-terms.html"
DEFAULT_SOURCES = "tranco,umbrella,radar,majestic,crux:global,crux:kr"

client = TestClient(app)


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
        assert sources[0].path == "source=tranco"

    def test_an_unknown_source_is_refused(self):
        with pytest.raises(ValueError, match="alexa"):
            reverseip.parse_sources("tranco,alexa")

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
        manager = ReverseIpManager(enabled=False)
        assert manager._runner is subprocess.run
        assert manager.directory == config.REVERSEIP_DIR
        assert manager.path == os.path.join(config.REVERSEIP_DIR, "reverseip.sqlite3")
        assert manager.sources == parse_sources(config.REVERSEIP_SOURCES)
        assert manager.build_attempted is False

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
