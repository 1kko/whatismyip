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

        def boom(*args, **kwargs):
            # Simulate a download that dies partway through.
            open(str(live) + ".tmp", "wb").write(b"half a file")
            raise RuntimeError("connection reset")

        monkeypatch.setattr(manager.instance, "update_file", boom)
        manager.update_database()  # swallows the error

        assert manager.instance is before  # never swapped in a bad load
        assert live.read_bytes() == b"pretend-this-is-the-current-good-db"  # untouched
        assert not (tmp_path / "geoip.dat.gz.tmp").exists()  # partial file cleaned up


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
        monkeypatch.setattr(managers, "MAXMIND_CITY_EDITION", "GeoLite2-City")

        request = managers._maxmind_city_request()

        assert request is not None
        assert "GeoLite2-City/download" in request.full_url
        assert "suffix=tar.gz" in request.full_url
        expected = base64.b64encode(b"123456:secret_key").decode()
        assert request.get_header("Authorization") == f"Basic {expected}"

    def test_no_request_unless_both_credentials_are_set(self, monkeypatch):
        monkeypatch.setattr(managers, "MAXMIND_ACCOUNT_ID", None)
        monkeypatch.setattr(managers, "MAXMIND_LICENSE_KEY", "secret_key")
        assert managers._maxmind_city_request() is None

        monkeypatch.setattr(managers, "MAXMIND_ACCOUNT_ID", "123456")
        monkeypatch.setattr(managers, "MAXMIND_LICENSE_KEY", None)
        assert managers._maxmind_city_request() is None

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
        assert managers._fetch_city_mmdb() == mmdb

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
        assert managers._fetch_city_mmdb() == mirror_mmdb

    def test_fetch_uses_mirror_without_credentials(self, monkeypatch):
        mirror_mmdb = b"mirror-only"
        monkeypatch.setattr(managers, "MAXMIND_ACCOUNT_ID", None)
        monkeypatch.setattr(managers, "MAXMIND_LICENSE_KEY", None)

        def fake_download(target, timeout=120):
            assert target == managers.GEOIP_CITY_DB_URL  # never an auth request
            return gzip.compress(mirror_mmdb)

        monkeypatch.setattr(managers, "_download_bytes", fake_download)
        assert managers._fetch_city_mmdb() == mirror_mmdb

    def test_update_city_database_swallows_fetch_failure(self, tmp_path, monkeypatch):
        target = tmp_path / "GeoLite2-City.mmdb"
        target.write_bytes(b"existing-good-db")
        monkeypatch.setattr(managers, "GEOIP_CITY_DB_FILE", str(target))

        manager = managers.GeoIpManager()
        before = manager.city_reader  # None (the fake file is not a real mmdb)

        def boom():
            raise RuntimeError("both sources down")

        monkeypatch.setattr(managers, "_fetch_city_mmdb", boom)
        manager.update_city_database()  # must not raise

        assert manager.city_reader is before  # reader untouched
        assert target.read_bytes() == b"existing-good-db"  # live file untouched
        assert not (tmp_path / "GeoLite2-City.mmdb.tmp").exists()
