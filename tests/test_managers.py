"""GeoIP database resilience.

An interrupted download used to leave a truncated .dat.gz that crashed the next
startup. These pin the two guards: a corrupt file degrades to the bundled DB
instead of raising, and a failed refresh never disturbs the live instance or
leaves the live file half-written. No network — the bundled geoip2fast DB is
used as the fallback.
"""

import base64
import gzip
import io
import os
import shutil
import tarfile

import managers


class TestGeoIpResilience:
    def test_corrupt_db_falls_back_to_bundled(self, tmp_path, monkeypatch):
        bad = tmp_path / "geoip.dat.gz"
        bad.write_bytes(b"not a valid gzip database")  # a truncated download
        monkeypatch.setattr(managers, "GEOIP_DATA_FILE", str(bad))

        manager = managers.GeoIpManager()  # must not raise
        # The bundled DB still answers, so a public IP resolves to a country.
        assert manager.fetch_location("8.8.8.8")["country_code"]

    def test_missing_db_uses_bundled(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            managers, "GEOIP_DATA_FILE", str(tmp_path / "absent.dat.gz")
        )
        manager = managers.GeoIpManager()
        assert manager.fetch_location("8.8.8.8")["country_code"]

    def test_update_failure_keeps_the_live_instance_and_file(
        self, tmp_path, monkeypatch
    ):
        live = tmp_path / "geoip.dat.gz"
        live.write_bytes(b"pretend-this-is-the-current-good-db")
        monkeypatch.setattr(managers, "GEOIP_DATA_FILE", str(live))

        manager = managers.GeoIpManager()  # bundled fallback (live file is fake)
        before = manager.instance

        def boom(filename, destination, verbose=False):
            # Simulate a download that dies partway through.
            open(destination, "wb").write(b"half a file")
            raise RuntimeError("connection reset")

        monkeypatch.setattr(manager.instance, "update_file", boom)
        assert manager.update_database() is False  # swallows the error

        assert manager.instance is before  # never swapped in a bad load
        assert live.read_bytes() == b"pretend-this-is-the-current-good-db"  # untouched
        # the partial download is cleaned up, whatever the temp file is named
        assert [p.name for p in tmp_path.iterdir()] == ["geoip.dat.gz"]

    def test_refresh_survives_the_library_extension_check(self, tmp_path, monkeypatch):
        """update_file() rejects any destination filename that does not end with
        .dat.gz — with an {'error': ...} result, not an exception, and nothing
        downloaded. A '<live>.tmp' temp name trips exactly that and silently
        killed every refresh in production, so the fake below enforces the real
        library's contract."""
        live = tmp_path / "geoip2fast.dat.gz"
        live.write_bytes(b"pretend-old-db")
        monkeypatch.setattr(managers, "GEOIP_DATA_FILE", str(live))
        manager = managers.GeoIpManager()  # bundled fallback (live file is fake)
        before = manager.instance
        loadable_db = manager.instance.get_database_info()["database_fullpath"]

        def fake_update_file(filename, destination, verbose=False):
            if not os.path.basename(destination).lower().endswith(".dat.gz"):
                return {"error": "The destination file extension is invalid."}
            shutil.copyfile(loadable_db, destination)  # a real, loadable DB
            return {"error": None}

        monkeypatch.setattr(manager.instance, "update_file", fake_update_file)
        assert manager.update_database() is True

        assert manager.instance is not before  # the refreshed DB was swapped in
        assert live.read_bytes() != b"pretend-old-db"  # live file replaced
        assert manager.db_info["source"] == "volume"  # status reflects the refresh
        assert [p.name for p in tmp_path.iterdir()] == ["geoip2fast.dat.gz"]

    def test_an_error_result_keeps_the_live_instance_and_file(
        self, tmp_path, monkeypatch
    ):
        """update_file() reports failures (bad URL, redirect loops, text
        responses) as an {'error': ...} dict; that must be treated as a failed
        refresh, not followed by a load attempt on a file that was never
        written."""
        live = tmp_path / "geoip2fast.dat.gz"
        live.write_bytes(b"pretend-old-db")
        monkeypatch.setattr(managers, "GEOIP_DATA_FILE", str(live))
        manager = managers.GeoIpManager()
        before = manager.instance

        monkeypatch.setattr(
            manager.instance,
            "update_file",
            lambda *a, **k: {"error": "Exceeded maximum redirects."},
        )
        assert manager.update_database() is False  # swallows the failure

        assert manager.instance is before
        assert live.read_bytes() == b"pretend-old-db"
        assert [p.name for p in tmp_path.iterdir()] == ["geoip2fast.dat.gz"]


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


def _isolated_manager(tmp_path, monkeypatch):
    """A manager on the bundled geoip2fast DB with no mmdb overlays, so tests
    can attach fake readers without touching the repo's real data files."""
    monkeypatch.setattr(managers, "GEOIP_DATA_FILE", str(tmp_path / "absent.dat.gz"))
    monkeypatch.setattr(
        managers, "GEOIP_CITY_DB_FILE", str(tmp_path / "absent-city.mmdb")
    )
    monkeypatch.setattr(
        managers, "GEOIP_ASN_DB_FILE", str(tmp_path / "absent-asn.mmdb")
    )
    return managers.GeoIpManager()


class TestAsnOverlay:
    """fetch_location prefers the GeoLite2-ASN overlay for carrier data and
    falls back to geoip2fast's own ASN fields when the overlay is absent."""

    class _FakeReader:
        def __init__(self, record, prefix_len=0):
            self.record, self.prefix_len = record, prefix_len

        def get_with_prefix_len(self, ip):
            return self.record, self.prefix_len

    def test_overlay_wins_over_geoip2fast(self, tmp_path, monkeypatch):
        manager = _isolated_manager(tmp_path, monkeypatch)
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

    def test_private_ips_skip_the_overlay(self, tmp_path, monkeypatch):
        manager = _isolated_manager(tmp_path, monkeypatch)

        class Exploding:
            def get_with_prefix_len(self, ip):
                raise AssertionError("must not be queried for private IPs")

        manager.asn_reader = Exploding()
        location = manager.fetch_location("192.168.0.1")
        assert location["is_private"] is True
        assert location["asn_number"] is None

    def test_no_record_falls_back_to_geoip2fast(self, tmp_path, monkeypatch):
        manager = _isolated_manager(tmp_path, monkeypatch)
        raw = manager.instance.lookup("8.8.8.8").to_dict()
        manager.asn_reader = self._FakeReader(None)
        location = manager.fetch_location("8.8.8.8")
        assert location["asn_name"] == raw.get("asn_name")
        assert location["asn_cidr"] == raw.get("asn_cidr")
        assert location["asn_number"] is None


class TestDatabaseStatus:
    """database_status() feeds /healthz: a silent fallback to the bundled DB
    (the failure mode that dropped carrier data in production) must be visible."""

    def test_bundled_fallback_is_visible(self, tmp_path, monkeypatch):
        status = _isolated_manager(tmp_path, monkeypatch).database_status()
        assert status["geoip2fast"]["source"] == "bundled"
        assert status["geoip2fast"]["content"]
        assert status["city_overlay"] == {"loaded": False, "build": None}
        assert status["asn_overlay"] == {"loaded": False, "build": None}

    def test_volume_db_reports_source_and_build(self, tmp_path, monkeypatch):
        bundled = managers.GeoIP2Fast().get_database_info()["database_fullpath"]
        live = tmp_path / "geoip2fast.dat.gz"
        shutil.copyfile(bundled, live)
        monkeypatch.setattr(managers, "GEOIP_DATA_FILE", str(live))
        monkeypatch.setattr(
            managers, "GEOIP_CITY_DB_FILE", str(tmp_path / "absent-city.mmdb")
        )
        monkeypatch.setattr(
            managers, "GEOIP_ASN_DB_FILE", str(tmp_path / "absent-asn.mmdb")
        )
        status = managers.GeoIpManager().database_status()
        assert status["geoip2fast"]["source"] == "volume"
        assert status["geoip2fast"]["build"]
