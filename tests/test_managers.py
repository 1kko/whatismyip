"""GeoIP databases and the public suffix list.

GeoLite2-City answers country, city and coordinates and GeoLite2-ASN the
carrier, both memory-mapped. The tests open MaxMind's small synthetic test
databases under tests/fixtures, never the repo's data/ files, and need no
network. The country-only snapshot bundled with geoip2fast stands in only
while the City database is missing, so a fresh volume still has a country for
geo-blocking.
"""

import base64
import gzip
import io
import json
import os
import tarfile

import pytest
from tld import conf as tld_conf
from tld.utils import reset_tld_names

import managers
import security

# MaxMind's synthetic test databases; see fixtures/LICENSE-MaxMind-DB.txt.
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
CITY_TEST_DB = os.path.join(FIXTURES, "GeoLite2-City-Test.mmdb")
ASN_TEST_DB = os.path.join(FIXTURES, "GeoLite2-ASN-Test.mmdb")


def _manager(tmp_path, monkeypatch, city=None, asn=None):
    """A GeoIpManager over the given mmdb files, or none at all, so a test never
    reads (or, through a refresh, writes) the repo's real data files."""
    monkeypatch.setattr(
        managers, "GEOIP_CITY_DB_FILE", city or str(tmp_path / "absent-city.mmdb")
    )
    monkeypatch.setattr(
        managers, "GEOIP_ASN_DB_FILE", asn or str(tmp_path / "absent-asn.mmdb")
    )
    return managers.GeoIpManager()


class _FakeCityReader:
    """One canned GeoLite2-City record for every address."""

    def __init__(self, record, prefix_len=24):
        self.record, self.prefix_len = record, prefix_len

    def get_with_prefix_len(self, ip):
        return self.record, self.prefix_len


class _RecordingReader:
    """A reader that notes every query and finds nothing. It records rather
    than raises because the lookup swallows reader errors."""

    def __init__(self):
        self.queried = []

    def get_with_prefix_len(self, ip):
        self.queried.append(ip)
        return None, 0


def _blocklist(tmp_path, *countries):
    rules = tmp_path / "geo_rules.json"
    rules.write_text(
        json.dumps(
            {
                "mode": "blocklist",
                "blocked_countries": list(countries),
                "blocked_regions": [],
                "allowed_countries": [],
                "allowed_regions": [],
                "block_unknown": False,
                "bypass_ips": [],
            }
        )
    )
    return str(rules)


class TestGeoLite2Lookup:
    """GeoLite2-City is the primary source: country, city, coordinates and the
    matched block, with the carrier from GeoLite2-ASN."""

    def test_city_and_asn_fill_one_record(self, tmp_path, monkeypatch):
        manager = _manager(tmp_path, monkeypatch, CITY_TEST_DB, ASN_TEST_DB)
        assert manager.fetch_location("89.160.20.112") == {
            "ip": "89.160.20.112",
            "country_code": "SE",
            "country_name": "Sweden",
            "city_name": "Linköping",
            "subdivision_name": "Östergötland County",
            "subdivision_code": "E",
            "lat": 58.4167,
            "lon": 15.6167,
            "accuracy_km": 76,
            "time_zone": "Europe/Stockholm",
            "cidr": "89.160.20.112/28",  # ip/prefix -> the City block
            "asn_name": "Bredband2 AB",
            "asn_cidr": "89.160.0.0/17",
            "asn_number": 29518,
            "is_private": False,
            "hostname": "",
        }

    def test_ipv6_addresses_resolve(self, tmp_path, monkeypatch):
        manager = _manager(tmp_path, monkeypatch, CITY_TEST_DB, ASN_TEST_DB)
        location = manager.fetch_location("2001:218::1")
        assert location["country_code"] == "JP"
        assert location["cidr"] == "2001:218::/32"

    def test_the_city_country_is_what_geo_blocking_judges(self, tmp_path, monkeypatch):
        """The bundled geoip2fast snapshot puts 67.43.156.0/24 in the US; the
        City database, in Bhutan. With the City database loaded, Bhutan is the
        country both the page and geo-blocking see."""
        manager = _manager(tmp_path, monkeypatch, CITY_TEST_DB)
        location = manager.fetch_location("67.43.156.1")
        assert (location["country_code"], location["country_name"]) == (
            "BT",
            "Bhutan",
        )

        geo_block = security.GeoBlockManager(
            manager, config_file=_blocklist(tmp_path, "BT")
        )
        verdict = geo_block.check_access("67.43.156.1")
        assert verdict["country"] == "BT"
        assert verdict["allowed"] is False

    def test_registered_country_stands_in_for_a_missing_one(
        self, tmp_path, monkeypatch
    ):
        """Some City records carry only the country the block is registered
        in. geoip2fast's own builder makes the same substitution, so dropping
        it would turn those addresses country-less."""
        manager = _manager(tmp_path, monkeypatch)
        manager.city_reader = _FakeCityReader(
            {"registered_country": {"iso_code": "RO", "names": {"en": "Romania"}}}
        )
        location = manager.fetch_location("8.8.8.8")
        assert location["country_code"] == "RO"
        assert location["country_name"] == "Romania"

    def test_an_unlisted_address_has_no_country_but_keeps_its_carrier(
        self, tmp_path, monkeypatch
    ):
        """An address no database lists keeps "--", the country code the JSON
        API and geo-blocking have always seen for it."""
        manager = _manager(tmp_path, monkeypatch, CITY_TEST_DB, ASN_TEST_DB)
        location = manager.fetch_location("1.128.0.1")  # absent from the City DB
        assert location["country_code"] == "--"
        assert location["country_name"] is None
        assert location["cidr"] is None
        assert location["asn_name"] == "Telstra Pty Ltd"
        assert location["asn_cidr"] == "1.128.0.0/11"

    @pytest.mark.parametrize(
        "ip",
        ["192.168.0.1", "10.1.2.3", "127.0.0.1", "100.64.0.1", "224.0.0.1", "::1"]
        + ["fe80::1", "fd00::1"],
    )
    def test_private_addresses_query_no_database(self, tmp_path, monkeypatch, ip):
        manager = _manager(tmp_path, monkeypatch, CITY_TEST_DB)
        manager.city_reader = manager.asn_reader = reader = _RecordingReader()
        location = manager.fetch_location(ip)
        assert location["is_private"] is True
        assert location["country_code"] == "--"
        assert reader.queried == []

    def test_a_non_address_does_not_raise(self, tmp_path, monkeypatch):
        # TestClient's peer is the string "testclient".
        manager = _manager(tmp_path, monkeypatch, CITY_TEST_DB, ASN_TEST_DB)
        location = manager.fetch_location("testclient")
        assert location["country_code"] == "--"
        assert location["is_private"] is False

    def test_the_fallback_is_never_loaded_while_the_city_db_serves(
        self, tmp_path, monkeypatch
    ):
        """The whole point: geoip2fast unpickles its database onto the Python
        heap (about 900 MB for the city build this replaced), where the mmdb
        readers only map their files."""
        manager = _manager(tmp_path, monkeypatch, CITY_TEST_DB, ASN_TEST_DB)
        for ip in ("89.160.20.112", "1.128.0.1", "2001:218::1", "8.8.8.8"):
            manager.fetch_location(ip)
        assert manager.fallback is None


class TestCountryFallback:
    """Until the first GeoLite2-City download lands, or while a corrupt one
    will not open, the country-only snapshot bundled with geoip2fast answers,
    so geo-blocking always has a country to judge."""

    def test_a_missing_city_db_falls_back_to_the_bundled_snapshot(
        self, tmp_path, monkeypatch
    ):
        manager = _manager(tmp_path, monkeypatch)
        assert manager.fetch_location("8.8.8.8")["country_code"] == "US"
        # The bundled file covers IPv6 too, not just the package's IPv4 default.
        assert manager.fetch_location("2001:4860:4860::8888")["country_code"] == "US"

    def test_a_corrupt_city_db_falls_back(self, tmp_path, monkeypatch):
        bad = tmp_path / "GeoLite2-City.mmdb"
        bad.write_bytes(b"not a valid mmdb")  # a truncated download
        manager = _manager(tmp_path, monkeypatch, str(bad))  # must not raise
        assert manager.city_reader is None
        assert manager.fetch_location("8.8.8.8")["country_code"] == "US"

    def test_the_fallback_answers_country_alone(self, tmp_path, monkeypatch):
        manager = _manager(tmp_path, monkeypatch, asn=ASN_TEST_DB)
        location = manager.fetch_location("89.160.20.112")
        assert location["country_code"] == "SE"
        assert location["city_name"] == ""
        assert location["lat"] is None
        assert location["asn_name"] == "Bredband2 AB"  # the ASN DB still answers

    def test_a_city_download_takes_over_from_the_fallback(self, tmp_path, monkeypatch):
        manager = _manager(tmp_path, monkeypatch)
        assert manager.fetch_location("67.43.156.1")["country_code"] == "US"
        assert manager.database_status()["geoip2fast"]["source"] == "bundled"

        with open(CITY_TEST_DB, "rb") as handle:
            city_bytes = handle.read()
        monkeypatch.setattr(managers, "_fetch_mmdb", lambda edition, url: city_bytes)
        assert manager.update_city_database() is True

        assert manager.fetch_location("67.43.156.1")["country_code"] == "BT"
        assert manager.database_status()["geoip2fast"]["source"] == "unused"


def _make_city_targz(mmdb_bytes, name="GeoLite2-City_20260718/GeoLite2-City.mmdb"):
    """A MaxMind-shaped .tar.gz: the .mmdb plus the COPYRIGHT/LICENSE text files
    that ride along in the real release, so extraction has to pick the right
    member rather than the first file."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for extra in (
            "GeoLite2-City_20260718/COPYRIGHT.txt",
            "GeoLite2-City_20260718/LICENSE.txt",
        ):
            info = tarfile.TarInfo(name=extra)
            info.size = 3
            tar.addfile(info, io.BytesIO(b"txt"))
        info = tarfile.TarInfo(name=name)
        info.size = len(mmdb_bytes)
        tar.addfile(info, io.BytesIO(mmdb_bytes))
    return buf.getvalue()


class TestCityDatabaseSource:
    """The GeoLite2-City overlay is fetched from MaxMind's licensed endpoint when
    credentials are configured (a .tar.gz over Basic auth), otherwise the free
    jsdelivr mirror (a plain gzip), with MaxMind failures falling back to the
    mirror. No network — urllib is stubbed."""

    def test_maxmind_request_carries_basic_auth(self, monkeypatch):
        monkeypatch.setattr(managers, "MAXMIND_ACCOUNT_ID", "123456")
        monkeypatch.setattr(managers, "MAXMIND_LICENSE_KEY", "secret_key")

        request = managers._maxmind_mmdb_request("GeoLite2-City")

        assert request is not None
        assert "GeoLite2-City/download" in request.full_url
        assert "suffix=tar.gz" in request.full_url
        expected = base64.b64encode(b"123456:secret_key").decode()
        assert request.get_header("Authorization") == f"Basic {expected}"

    def test_maxmind_request_takes_the_edition(self, monkeypatch):
        monkeypatch.setattr(managers, "MAXMIND_ACCOUNT_ID", "123456")
        monkeypatch.setattr(managers, "MAXMIND_LICENSE_KEY", "secret_key")
        request = managers._maxmind_mmdb_request("GeoLite2-ASN")
        assert "GeoLite2-ASN/download" in request.full_url

    def test_no_request_unless_both_credentials_are_set(self, monkeypatch):
        monkeypatch.setattr(managers, "MAXMIND_ACCOUNT_ID", None)
        monkeypatch.setattr(managers, "MAXMIND_LICENSE_KEY", "secret_key")
        assert managers._maxmind_mmdb_request("GeoLite2-City") is None

        monkeypatch.setattr(managers, "MAXMIND_ACCOUNT_ID", "123456")
        monkeypatch.setattr(managers, "MAXMIND_LICENSE_KEY", None)
        assert managers._maxmind_mmdb_request("GeoLite2-City") is None

    def test_redirect_handler_drops_authorization(self):
        # MaxMind 302-redirects to a presigned URL that rejects the auth header;
        # the handler must not carry Authorization across the redirect.
        import email.message

        handler = managers._AuthDroppingRedirectHandler()
        req = managers.urllib.request.Request("https://download.example/x")
        req.add_header("Authorization", "Basic abc123")
        new = handler.redirect_request(
            req, None, 302, "Found", email.message.Message(), "https://cdn.example/y"
        )
        assert new is not None
        assert new.get_header("Authorization") is None

    def test_extract_mmdb_picks_the_member_out_of_the_tarball(self):
        mmdb = b"\x00fake-mmdb-bytes\x00"
        assert managers._extract_mmdb(_make_city_targz(mmdb)) == mmdb

    def test_extract_mmdb_raises_when_no_member(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="README.txt")
            info.size = 2
            tar.addfile(info, io.BytesIO(b"hi"))
        try:
            managers._extract_mmdb(buf.getvalue())
            raise AssertionError("expected ValueError")
        except ValueError:
            pass

    def test_fetch_prefers_maxmind_when_configured(self, monkeypatch):
        mmdb = b"maxmind-city-db"
        monkeypatch.setattr(managers, "MAXMIND_ACCOUNT_ID", "123456")
        monkeypatch.setattr(managers, "MAXMIND_LICENSE_KEY", "secret_key")

        def fake_download(target, timeout=120):
            # MaxMind is fetched with an authenticated Request, not a bare URL.
            assert isinstance(target, managers.urllib.request.Request)
            return _make_city_targz(mmdb)

        monkeypatch.setattr(managers, "_download_bytes", fake_download)
        assert managers._fetch_mmdb("GeoLite2-City", managers.GEOIP_CITY_DB_URL) == mmdb

    def test_fetch_falls_back_to_mirror_on_maxmind_failure(self, monkeypatch):
        mirror_mmdb = b"mirror-city-db"
        monkeypatch.setattr(managers, "MAXMIND_ACCOUNT_ID", "123456")
        monkeypatch.setattr(managers, "MAXMIND_LICENSE_KEY", "bad_key")

        def fake_download(target, timeout=120):
            if isinstance(target, managers.urllib.request.Request):
                raise RuntimeError("401 Unauthorized")  # a bad MaxMind key
            assert target == managers.GEOIP_CITY_DB_URL
            return gzip.compress(mirror_mmdb)  # the mirror is a plain gzip

        monkeypatch.setattr(managers, "_download_bytes", fake_download)
        assert (
            managers._fetch_mmdb("GeoLite2-City", managers.GEOIP_CITY_DB_URL)
            == mirror_mmdb
        )

    def test_fetch_uses_mirror_without_credentials(self, monkeypatch):
        mirror_mmdb = b"mirror-only"
        monkeypatch.setattr(managers, "MAXMIND_ACCOUNT_ID", None)
        monkeypatch.setattr(managers, "MAXMIND_LICENSE_KEY", None)

        def fake_download(target, timeout=120):
            assert target == managers.GEOIP_ASN_DB_URL  # never an auth request
            return gzip.compress(mirror_mmdb)

        monkeypatch.setattr(managers, "_download_bytes", fake_download)
        assert (
            managers._fetch_mmdb("GeoLite2-ASN", managers.GEOIP_ASN_DB_URL)
            == mirror_mmdb
        )

    def test_update_city_database_swallows_fetch_failure(self, tmp_path, monkeypatch):
        target = tmp_path / "GeoLite2-City.mmdb"
        target.write_bytes(b"existing-good-db")
        monkeypatch.setattr(managers, "GEOIP_CITY_DB_FILE", str(target))

        manager = managers.GeoIpManager()
        before = manager.city_reader  # None (the fake file is not a real mmdb)

        def boom(edition, mirror_url):
            raise RuntimeError("both sources down")

        monkeypatch.setattr(managers, "_fetch_mmdb", boom)
        assert manager.update_city_database() is False  # must not raise

        assert manager.city_reader is before  # reader untouched
        assert target.read_bytes() == b"existing-good-db"  # live file untouched
        assert not (tmp_path / "GeoLite2-City.mmdb.tmp").exists()

    def test_update_asn_database_swallows_fetch_failure(self, tmp_path, monkeypatch):
        target = tmp_path / "GeoLite2-ASN.mmdb"
        monkeypatch.setattr(managers, "GEOIP_ASN_DB_FILE", str(target))

        manager = managers.GeoIpManager()

        def boom(edition, mirror_url):
            raise RuntimeError("both sources down")

        monkeypatch.setattr(managers, "_fetch_mmdb", boom)
        assert manager.update_asn_database() is False  # must not raise
        assert manager.asn_reader is None
        assert not target.exists()


class TestAsnOverlay:
    """Carrier data comes from GeoLite2-ASN alone; the country-only fallback
    has none to offer."""

    class _FakeReader:
        def __init__(self, record, prefix_len=0):
            self.record, self.prefix_len = record, prefix_len

        def get_with_prefix_len(self, ip):
            return self.record, self.prefix_len

    def test_the_announced_block_comes_from_the_prefix(self, tmp_path, monkeypatch):
        manager = _manager(tmp_path, monkeypatch, CITY_TEST_DB)
        manager.asn_reader = self._FakeReader(
            {
                "autonomous_system_organization": "Fake Telecom",
                "autonomous_system_number": 65000,
            },
            prefix_len=20,
        )
        location = manager.fetch_location("168.126.63.1")
        assert location["asn_name"] == "Fake Telecom"
        assert location["asn_number"] == 65000
        assert location["asn_cidr"] == "168.126.48.0/20"  # ip/prefix -> network

    def test_no_record_leaves_the_carrier_empty(self, tmp_path, monkeypatch):
        manager = _manager(tmp_path, monkeypatch, CITY_TEST_DB, ASN_TEST_DB)
        location = manager.fetch_location("8.8.8.8")  # absent from the ASN DB
        assert location["asn_name"] is None
        assert location["asn_cidr"] is None
        assert location["asn_number"] is None


class TestDatabaseStatus:
    """database_status() feeds /healthz: a silent fallback to the bundled DB
    (the failure mode that dropped carrier data in production) must be visible.
    The `geoip2fast` block keeps its key and its meaning: `source` reads
    "bundled" exactly when the bundled snapshot is answering."""

    def test_bundled_fallback_is_visible(self, tmp_path, monkeypatch):
        status = _manager(tmp_path, monkeypatch).database_status()
        assert status["geoip2fast"]["source"] == "bundled"
        assert status["geoip2fast"]["content"] == "Country with IPv4 and IPv6"
        assert "GeoLite2-Country" in status["geoip2fast"]["build"]
        assert status["city_overlay"] == {"loaded": False, "build": None}
        assert status["asn_overlay"] == {"loaded": False, "build": None}

    def test_the_city_db_retires_the_fallback(self, tmp_path, monkeypatch):
        manager = _manager(tmp_path, monkeypatch, CITY_TEST_DB, ASN_TEST_DB)
        status = manager.database_status()
        assert status["geoip2fast"] == {
            "source": "unused",
            "content": None,
            "build": None,
        }
        assert status["city_overlay"] == {"loaded": True, "build": "2026-02-04"}
        assert status["asn_overlay"] == {"loaded": True, "build": "2026-02-04"}


# ---------------------------------------------------------------------------
# Public suffix list
# ---------------------------------------------------------------------------
def _fake_urlopen(body: str):
    """Stand in for urllib.request.urlopen as a context manager returning body."""

    class _Response:
        def read(self):
            return body.encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def urlopen(*args, **kwargs):
        return _Response()

    return urlopen


@pytest.fixture
def tld_dir(tmp_path):
    """A TldNamesManager on a throwaway directory.

    NAMES_LOCAL_PATH_PARENT is a process-wide setting inside the `tld` package,
    so constructing a manager repoints domain validation for every other module
    too. Put it back afterwards or the rest of the suite reads a deleted
    tmp_path and every domain stops validating.
    """
    original = tld_conf.get_setting("NAMES_LOCAL_PATH_PARENT")
    yield managers.TldNamesManager(directory=str(tmp_path))
    tld_conf.set_setting("NAMES_LOCAL_PATH_PARENT", original)
    reset_tld_names()


class TestTldNamesManager:
    """The list decides whether a single-segment request is a lookup or a probe,
    so a missing, stale or corrupt copy has teeth: it makes the middleware read
    ordinary domains as probes and ban the visitors asking for them. No network
    — every fetch is stubbed.
    """

    def test_seeds_from_the_bundled_snapshot(self, tld_dir):
        assert os.path.exists(tld_dir.path)
        with (
            open(tld_dir.path, "rb") as copied,
            open(tld_dir.bundled_path, "rb") as bundled,
        ):
            assert copied.read() == bundled.read()

    def test_a_seeded_copy_counts_as_stale(self, tld_dir):
        """Otherwise a year-old bundled snapshot hides behind a fresh mtime for
        a full interval and is never replaced on first boot."""
        assert tld_dir.age_days() is None
        assert tld_dir.is_stale()
        assert tld_dir.status()["source"] == "bundled"

    def test_update_writes_the_list_and_clears_stale(self, tld_dir, monkeypatch):
        body = "// ===BEGIN ICANN DOMAINS===\ncom\nexample\n"
        monkeypatch.setattr(managers.urllib.request, "urlopen", _fake_urlopen(body))
        assert tld_dir.update() is True
        with open(tld_dir.path, encoding="utf-8") as handle:
            assert handle.read() == body
        assert not tld_dir.is_stale()
        assert tld_dir.status()["source"] == "downloaded"

    def test_a_bad_response_never_replaces_a_good_list(self, tld_dir, monkeypatch):
        """The failure that matters: a captive portal or half-finished download
        would otherwise install a list matching nothing, and every domain would
        start reading as a probe."""
        with open(tld_dir.path, "rb") as handle:
            before = handle.read()
        monkeypatch.setattr(
            managers.urllib.request,
            "urlopen",
            _fake_urlopen("<html>captive portal</html>"),
        )
        assert tld_dir.update() is False
        with open(tld_dir.path, "rb") as handle:
            assert handle.read() == before
        assert not os.path.exists(tld_dir.path + ".tmp")

    def test_a_fresh_list_is_not_refetched(self, tld_dir, monkeypatch):
        """The job runs daily but the list is only pulled every TLD_MAX_AGE_DAYS,
        so a restart must not re-download."""
        os.utime(tld_dir.path, None)  # pretend it was just downloaded

        def explode(*args, **kwargs):
            raise AssertionError("should not have been fetched")

        monkeypatch.setattr(managers.urllib.request, "urlopen", explode)
        assert tld_dir.update() is True

    def test_force_refetches_a_fresh_list(self, tld_dir, monkeypatch):
        os.utime(tld_dir.path, None)
        body = "// ===BEGIN ICANN DOMAINS===\ncom\n"
        monkeypatch.setattr(managers.urllib.request, "urlopen", _fake_urlopen(body))
        assert tld_dir.update(force=True) is True
        with open(tld_dir.path, encoding="utf-8") as handle:
            assert handle.read() == body


class TestIsValidDomain:
    def test_empty_and_punctuation_targets_do_not_raise(self):
        """get_tld raises TldBadUrl, not TldDomainNotFound, for these. The MCP
        lookup tool hands user input straight in and the security middleware
        asks before banning, so this has to be total."""
        manager = managers.DomainManager()
        for value in ("", "//", ".", "..", " "):
            assert manager.is_valid_domain(value) is False

    def test_real_domains_still_validate(self):
        manager = managers.DomainManager()
        assert manager.is_valid_domain("nasa.gov")
        assert manager.is_valid_domain("foo.dev")
        assert not manager.is_valid_domain("admin.php")
