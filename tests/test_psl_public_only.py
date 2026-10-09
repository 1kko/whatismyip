"""The public-only suffix list that DomainManager.zone_apex reads.

zone_apex floors a zone at the registrable domain under an ICANN suffix, so it
calls get_fld(search_private=False). `tld` serves that from a second file,
res/effective_tld_names_public_only.dat.txt, which TldNamesManager used to
neither seed nor refresh. On a fresh volume the first domain lookup made `tld`
fetch it from publicsuffix.org inside the request, with no timeout; offline the
fetch failed and get_fld raised TypeError even with fail_silently; and nothing
ever refreshed the copy it did get.

Every test here blocks `tld`'s own downloader, so any lookup that would fetch
fails loudly instead of quietly reaching the network.
"""

import os

import pytest
from tld import get_fld
from tld import base as tld_base
from tld import conf as tld_conf
from tld import utils as tld_utils
from tld.utils import reset_tld_names

import managers

PUBLIC_ONLY = tld_utils.MozillaPublicOnlyTLDSourceParser.local_path


@pytest.fixture
def no_tld_download(monkeypatch):
    """`tld` fetches a missing list itself (tld.base, with no timeout) and
    swallows the error when that fails, so record every attempt and fail the
    test afterwards rather than raising where `tld` would catch it."""
    attempts = []

    def refuse(url, *args, **kwargs):
        attempts.append(url)
        raise OSError("network blocked in this test")

    monkeypatch.setattr(tld_base, "urlopen", refuse)
    yield attempts
    assert attempts == [], f"tld tried to download: {attempts}"


@pytest.fixture
def restore_tld():
    """NAMES_LOCAL_PATH_PARENT is process-wide; put it back afterwards (see the
    tld_dir fixture in test_managers.py)."""
    original = tld_conf.get_setting("NAMES_LOCAL_PATH_PARENT")
    reset_tld_names()
    yield
    tld_conf.set_setting("NAMES_LOCAL_PATH_PARENT", original)
    reset_tld_names()


def _fld(name, **kwargs):
    return get_fld(name, fix_protocol=True, fail_silently=True, **kwargs)


def _read(path):
    with open(path, "rb") as handle:
        return handle.read()


class _Response:
    def __init__(self, body):
        self.body = body.encode("utf-8")

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# A list with one ICANN suffix and one private suffix under it, so the two
# parsers give different answers for a name under the private one.
LIST = (
    "// ===BEGIN ICANN DOMAINS===\n"
    "newtld\n"
    "// ===END ICANN DOMAINS===\n"
    "// ===BEGIN PRIVATE DOMAINS===\n"
    "hosted.newtld\n"
    "// ===END PRIVATE DOMAINS===\n"
)


class TestSeeding:
    def test_a_fresh_volume_gets_a_public_only_copy(
        self, tmp_path, restore_tld, no_tld_download
    ):
        manager = managers.TldNamesManager(directory=str(tmp_path))
        assert os.path.exists(manager.public_only_path)
        assert _read(manager.public_only_path) == _read(manager.path)

    def test_the_icann_floor_needs_no_network(
        self, tmp_path, restore_tld, no_tld_download
    ):
        """The failure as it happened: only the full list was on the volume."""
        managers.TldNamesManager(directory=str(tmp_path))
        assert _fld("foo.github.io", search_private=False) == "github.io"
        assert _fld("foo.github.io") == "foo.github.io"
        assert _fld("www.naver.co.kr", search_private=False) == "naver.co.kr"

    def test_a_volume_from_before_is_brought_in_line(
        self, tmp_path, restore_tld, no_tld_download
    ):
        """An existing volume has a downloaded full list and either no
        public-only copy or the one tld fetched once and never refreshed."""
        res = tmp_path / os.path.dirname(managers.TldNamesManager._RELATIVE_PATH)
        res.mkdir(parents=True)
        (tmp_path / managers.TldNamesManager._RELATIVE_PATH).write_text(LIST)
        (tmp_path / PUBLIC_ONLY).write_text("// stale\ncom\n")

        manager = managers.TldNamesManager(directory=str(tmp_path))

        assert _read(manager.public_only_path) == LIST.encode()
        assert _fld("a.b.hosted.newtld", search_private=False) == "hosted.newtld"


class TestUpdate:
    def test_a_refresh_replaces_both_copies(
        self, tmp_path, restore_tld, no_tld_download, monkeypatch
    ):
        manager = managers.TldNamesManager(directory=str(tmp_path))
        # Parse the seeded lists first, so a stale trie would show below.
        assert _fld("x.hosted.newtld") is None
        monkeypatch.setattr(
            managers.urllib.request, "urlopen", lambda *a, **k: _Response(LIST)
        )

        assert manager.update(force=True) is True

        assert _read(manager.path) == LIST.encode()
        assert _read(manager.public_only_path) == LIST.encode()
        assert _fld("x.hosted.newtld") == "x.hosted.newtld"
        assert _fld("x.hosted.newtld", search_private=False) == "hosted.newtld"
        assert not os.path.exists(manager.public_only_path + ".tmp")

    def test_a_missing_copy_is_restored_without_a_download(
        self, tmp_path, restore_tld, no_tld_download, monkeypatch
    ):
        """The daily job skips a fresh list, but a public-only copy that went
        missing (or failed to write last time) should not wait out the
        interval."""
        manager = managers.TldNamesManager(directory=str(tmp_path))
        os.utime(manager.path, None)  # a fresh download
        os.remove(manager.public_only_path)

        def explode(*args, **kwargs):
            raise AssertionError("a fresh list should not be refetched")

        monkeypatch.setattr(managers.urllib.request, "urlopen", explode)
        assert manager.update() is True
        assert _read(manager.public_only_path) == _read(manager.path)


class TestZoneApex:
    def test_the_floor_holds_offline(
        self, tmp_path, restore_tld, no_tld_download, monkeypatch
    ):
        """DNS down and no network for tld either: the floor is the registrable
        domain under the ICANN suffix, without a fetch and without a crash."""
        managers.TldNamesManager(directory=str(tmp_path))

        def no_dns(*args, **kwargs):
            raise managers.dns.exception.Timeout()

        monkeypatch.setattr(managers.dns.resolver, "zone_for_name", no_dns)
        domain_manager = managers.DomainManager()
        assert domain_manager.zone_apex("foo.github.io") == "github.io"
        assert domain_manager.zone_apex("mail.naver.co.kr") == "naver.co.kr"
