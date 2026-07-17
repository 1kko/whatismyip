"""GeoIP database resilience.

An interrupted download used to leave a truncated .dat.gz that crashed the next
startup. These pin the two guards: a corrupt file degrades to the bundled DB
instead of raising, and a failed refresh never disturbs the live instance or
leaves the live file half-written. No network — the bundled geoip2fast DB is
used as the fallback.
"""

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
