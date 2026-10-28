"""reverseip.py's source table and licence lines, and the saved copy of
OpenINTEL's terms. No network."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import config
import reverseip
from main import app

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
