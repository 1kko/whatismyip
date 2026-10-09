"""Data-gathering managers: GeoIP (GeoLite2 City/ASN), DNS, SSL, and header hygiene.

Each is a thin wrapper over one external source. They depend only on config, so
main.py can import them without an import cycle.
"""

import base64
import gzip
import io
import ipaddress
import logging
import os
import shutil
import socket
import ssl
import tarfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict

import dns.exception
import dns.resolver
import dns.reversename
import geoip2fast
import maxminddb
from cryptography import x509
from cryptography.x509.oid import NameOID
from geoip2fast import GeoIP2Fast
from tld import exceptions as tld_exceptions
from tld import get_fld, get_tld

from tld import defaults as tld_defaults
from tld.conf import set_setting as set_tld_setting
from tld.utils import (
    MozillaPublicOnlyTLDSourceParser,
    MozillaTLDSourceParser,
    reset_tld_names,
)

from config import (
    DNS_HOST_RESOLVE_LIMIT,
    DNS_HOST_RESOLVE_WORKERS,
    DNS_QUERY_LIFETIME,
    DNS_QUERY_TIMEOUT,
    GEOIP_ASN_DB_FILE,
    GEOIP_ASN_DB_URL,
    GEOIP_CITY_DB_FILE,
    GEOIP_CITY_DB_URL,
    MAXMIND_ACCOUNT_ID,
    MAXMIND_ASN_EDITION,
    MAXMIND_CITY_EDITION,
    MAXMIND_LICENSE_KEY,
    PUBLIC_RESOLVERS,
    TIMEOUT_SECONDS,
    TLD_LIST_URL,
    TLD_MAX_AGE_DAYS,
    TLD_NAMES_DIR,
)

# MaxMind's licensed direct-download endpoint. It returns a .tar.gz (Basic auth
# with account id + license key); the free mirrors in GEOIP_*_DB_URL are plain
# gzips of the bare .mmdb instead.
MAXMIND_DOWNLOAD_URL = (
    "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
)


def _recursive_resolver() -> dns.resolver.Resolver:
    """A resolver pointed at the public recursive DNS servers.

    Public resolvers are heavily cached and close to the datacentre, so they
    answer far faster than a domain's own authoritative nameservers, and they
    actually answer PTR / MX-host A queries (which authoritative NS refuse).
    """
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = list(PUBLIC_RESOLVERS)
    resolver.timeout = DNS_QUERY_TIMEOUT
    resolver.lifetime = DNS_QUERY_LIFETIME
    return resolver


# The statuses that mean "could not find out". The other two a query can end
# in, noanswer and nxdomain, are answers: the name has no such record, or does
# not exist. viewmodel.DNS_FAILURE_TEXT mirrors this set.
DNS_FAILURES = frozenset({"timeout", "servfail", "error"})


def dns_status(exc: BaseException) -> str:
    """How a DNS query that raised `exc` ended: "noanswer", "nxdomain",
    "servfail", "timeout" or "error". A query that returned is "ok".

    NoNameservers is what dnspython raises once it has run out of resolvers to
    ask: each answered SERVFAIL (a broken DNSSEC chain, a dead authoritative
    server) or REFUSED, or could not be reached -- it folds a resolver's socket
    error into this too. Anything else -- a name dnspython will not encode, a
    bug -- is "error", rather than a guess at which server to blame. Both are
    failures all the same: "could not find out", never "none".
    """
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "nxdomain"
    if isinstance(exc, dns.resolver.NoAnswer):
        return "noanswer"
    if isinstance(exc, dns.resolver.NoNameservers):
        return "servfail"
    if isinstance(exc, dns.exception.Timeout):
        return "timeout"
    return "error"


def _with_host_ips(rows: list[dict], rdtype: str = "A") -> list[dict]:
    """Add each row's "ip": the first `rdtype` address its "hostname" has.

    Any record type that names hosts (NS, MX, and whatever comes next) goes
    through here, because its answer is sized by whoever runs the zone. Only the
    first DNS_HOST_RESOLVE_LIMIT rows are resolved, on at most
    DNS_HOST_RESOLVE_WORKERS threads; the rest keep their row with "ip": None
    and "ip_skipped": True, so a host nobody asked about does not read as a
    host with no address.

    The pool is this call's own, never the caller's: get_records() runs this
    from inside its record-type sweep, and a bounded pool whose workers wait on
    tasks queued behind them in that same pool deadlocks.
    """
    head = rows[:DNS_HOST_RESOLVE_LIMIT]

    def first_address(row: dict) -> str | None:
        try:
            return str(_recursive_resolver().resolve(row["hostname"], rdtype)[0])
        except Exception:
            return None

    if head:
        workers = min(len(head), DNS_HOST_RESOLVE_WORKERS)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for row, ip in zip(head, pool.map(first_address, head)):
                row["ip"] = ip
    for row in rows[len(head) :]:
        row["ip"] = None
        row["ip_skipped"] = True
    return rows


class _AuthDroppingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Strip the Authorization header when following a redirect. MaxMind's
    download endpoint 302-redirects to a presigned URL on another host that
    rejects the Basic auth header (HTTP 400); the credentials belong only on the
    first request."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.remove_header("Authorization")
        return new


def _download_bytes(target, timeout: int = 120) -> bytes:
    """Read an HTTP(S) URL or a prepared urllib Request fully into memory. The
    target is operator-set config (a mirror URL or an authenticated MaxMind
    request), not user input, so any scheme is intentional."""
    opener = urllib.request.build_opener(_AuthDroppingRedirectHandler())
    with opener.open(target, timeout=timeout) as resp:  # noqa: S310
        return resp.read()


def _maxmind_mmdb_request(edition: str):
    """An authenticated request for one MaxMind .tar.gz edition, or None when
    the two credentials are not both configured (then the free mirror is used)."""
    if not (MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY):
        return None
    url = MAXMIND_DOWNLOAD_URL.format(edition=edition)
    token = base64.b64encode(
        f"{MAXMIND_ACCOUNT_ID}:{MAXMIND_LICENSE_KEY}".encode()
    ).decode()
    # url is the hardcoded https MaxMind endpoint above, not user input.
    request = urllib.request.Request(url)  # noqa: S310
    request.add_header("Authorization", f"Basic {token}")
    return request


def _extract_mmdb(tar_gz_bytes: bytes) -> bytes:
    """Pull the single .mmdb file out of a MaxMind .tar.gz release, which also
    bundles COPYRIGHT/LICENSE text files alongside the database."""
    with tarfile.open(fileobj=io.BytesIO(tar_gz_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith(".mmdb"):
                extracted = tar.extractfile(member)
                if extracted is not None:
                    return extracted.read()
    raise ValueError("no .mmdb member found in the MaxMind tarball")


def _fetch_mmdb(edition: str, mirror_url: str) -> bytes:
    """Raw mmdb bytes for one MaxMind edition from the best available source.

    MaxMind's licensed endpoint (a .tar.gz, extracted) when credentials are set;
    on any MaxMind error, falls back to the edition's free jsdelivr mirror (a
    plain gzip) so the overlay still refreshes. Without credentials the mirror
    is the only source."""
    request = _maxmind_mmdb_request(edition)
    if request is not None:
        try:
            return _extract_mmdb(_download_bytes(request))
        except Exception:
            logging.exception(
                "MaxMind %s download failed (check MAXMIND_ACCOUNT_ID / "
                "MAXMIND_LICENSE_KEY); falling back to the free mirror",
                edition,
            )
    return gzip.decompress(_download_bytes(mirror_url))


# The country-only (IPv4 + IPv6) snapshot that ships inside the geoip2fast
# package. It answers country only while GeoLite2-City is not loaded (a fresh
# volume before its first download, or a City file that will not open), so
# geo-blocking always has a country to judge. Read by absolute path: given a
# bare file name, GeoIP2Fast looks in the working directory first, and the file
# is a pickle.
GEOIP_FALLBACK_FILE = os.path.join(
    os.path.dirname(geoip2fast.__file__), "geoip2fast-ipv6.dat.gz"
)

# geoip2fast's country code for a private or unlisted address, kept for every
# address no database places, so the JSON API and geo-blocking see the value
# they always have, whichever database answered.
NO_COUNTRY = "--"


def _network(ip: str, prefix_len: int) -> str | None:
    """The block an mmdb lookup matched: the address masked to its prefix."""
    try:
        return str(ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False))
    except ValueError:
        return None


def _english_name(entry: Dict[str, Any] | None) -> str | None:
    return ((entry or {}).get("names") or {}).get("en")


class GeoIpManager:
    """GeoIP from the GeoLite2-City and GeoLite2-ASN mmdb files in the data
    volume, refreshed every three days.

    maxminddb memory-maps both, so they cost page cache the kernel can reclaim
    rather than Python heap. The geoip2fast city+ASN build this replaced held
    the same MaxMind data as unpickled Python objects, about 900 MB of RSS, and
    briefly twice that while a refresh loaded the new copy beside the old."""

    def __init__(self):
        self.city_reader = self._open_mmdb_reader(GEOIP_CITY_DB_FILE)
        self.asn_reader = self._open_mmdb_reader(GEOIP_ASN_DB_FILE)
        # The fallback costs tens of MB of heap, so it is loaded only when no
        # City database opened. A City download that lands later takes over at
        # once but cannot hand that memory back: geoip2fast keeps its data in
        # module globals, which outlive the instance until the next restart.
        # (The same globals are why every GeoIP2Fast instance answers from the
        # file loaded last; loading only this one file keeps that harmless.)
        self.fallback = (
            None
            if self.city_reader
            else GeoIP2Fast(geoip2fast_data_file=GEOIP_FALLBACK_FILE)
        )
        self.fallback_info = self._describe_fallback(self.fallback)
        self._log_db_status()

    @staticmethod
    def _describe_fallback(instance: GeoIP2Fast | None) -> Dict[str, Any]:
        """What the fallback holds, from attributes set at load. Not
        get_database_info(): that decompresses the whole file again just to
        report its size."""
        if instance is None:
            return {"content": None, "build": None}
        ipv6 = "IPv4 and IPv6" if getattr(instance, "ipv6", False) else "IPv4 only"
        return {
            "content": f"Country with {ipv6}",
            "build": getattr(instance, "source_info", None),
        }

    @staticmethod
    def _open_mmdb_reader(path: str):
        if os.path.exists(path):
            try:
                return maxminddb.open_database(path)
            except Exception:
                logging.exception("Could not open mmdb database at %s", path)
        return None

    def _log_db_status(self):
        logging.info(
            "GeoIP DB loaded: country=%s city_overlay=%s asn_overlay=%s",
            "GeoLite2-City" if self.city_reader else "geoip2fast fallback",
            self.city_reader is not None,
            self.asn_reader is not None,
        )
        if self.city_reader is None:
            logging.warning(
                "GeoLite2-City not loaded; country comes from the bundled "
                "geoip2fast snapshot (%s), with no city or coordinates, until a "
                "refresh succeeds",
                self.fallback_info["build"],
            )
        if self.asn_reader is None:
            logging.warning(
                "GeoLite2-ASN not loaded; carrier lookups stay empty until a "
                "refresh succeeds"
            )

    @staticmethod
    def _mmdb_status(reader) -> Dict[str, Any]:
        if reader is None:
            return {"loaded": False, "build": None}
        try:
            epoch = reader.metadata().build_epoch
            build = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")
        except Exception:
            build = None
        return {"loaded": True, "build": build}

    def database_status(self) -> Dict[str, Any]:
        """What each database serving lookups actually is — for the health
        endpoint, so a silent fallback to the bundled country-only DB is
        visible from outside.

        The keys predate GeoLite2-City becoming the primary source and keep
        their meaning: `geoip2fast.source` reads "bundled" exactly when the
        bundled snapshot is answering country, as it always has, and "unused"
        once the City database is (there is no "volume" geoip2fast copy any
        more); `city_overlay` is that City database."""
        return {
            "geoip2fast": {
                "source": "bundled" if self.city_reader is None else "unused",
                **self.fallback_info,
            },
            "city_overlay": self._mmdb_status(self.city_reader),
            "asn_overlay": self._mmdb_status(self.asn_reader),
        }

    def build_ages(self) -> Dict[str, float]:
        """Days since each loaded GeoLite2 database was built, by edition, for
        /healthz. One that is not loaded is left out: that is reported on its
        own, and its age would mean nothing."""
        ages = {}
        for edition, reader in (
            (MAXMIND_CITY_EDITION, self.city_reader),
            (MAXMIND_ASN_EDITION, self.asn_reader),
        ):
            try:
                built = reader.metadata().build_epoch if reader else None
            except Exception:
                built = None
            if built is not None:
                ages[edition] = (time.time() - built) / 86400
        return ages

    def _update_mmdb(
        self, edition: str, mirror_url: str, path: str, reader_attr: str
    ) -> bool:
        """Download one MaxMind mmdb edition, then hot-swap its reader. The
        source is MaxMind's licensed endpoint when MAXMIND_ACCOUNT_ID and
        MAXMIND_LICENSE_KEY are set, otherwise the free mirror; see _fetch_mmdb.
        The write is atomic, so the live file is only ever a complete database."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data = _fetch_mmdb(edition, mirror_url)
            tmp = path + ".tmp"
            with open(tmp, "wb") as handle:
                handle.write(data)
            os.replace(tmp, path)
            old = getattr(self, reader_attr)
            setattr(self, reader_attr, maxminddb.open_database(path))
            if old:
                old.close()
            logging.info("%s database updated (%d bytes)", edition, len(data))
            return True
        except Exception:
            logging.exception("Error updating %s database", edition)
            return False

    def update_city_database(self) -> bool:
        return self._update_mmdb(
            MAXMIND_CITY_EDITION, GEOIP_CITY_DB_URL, GEOIP_CITY_DB_FILE, "city_reader"
        )

    def update_asn_database(self) -> bool:
        return self._update_mmdb(
            MAXMIND_ASN_EDITION, GEOIP_ASN_DB_URL, GEOIP_ASN_DB_FILE, "asn_reader"
        )

    def fetch_location(self, ip: str) -> Dict[str, Any]:
        """A single flat location record for the IP: country, city,
        coordinates, accuracy, time zone and the matched block from
        GeoLite2-City, and the AS org/number/announced block from GeoLite2-ASN.
        While the City database is not loaded, the bundled geoip2fast snapshot
        supplies country and block alone. Callers add reverse_dns; the response
        assembly adds the resolved coordinates, the origin_* fields, and
        distance_km."""
        location: Dict[str, Any] = {
            "ip": ip,
            "country_code": NO_COUNTRY,
            "country_name": None,
            "city_name": "",
            "subdivision_name": "",
            "subdivision_code": "",
            "lat": None,
            "lon": None,
            "accuracy_km": None,
            "time_zone": None,
            "cidr": None,
            "asn_name": None,
            "asn_cidr": None,
            "asn_number": None,
            "is_private": False,
            "hostname": "",
        }
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return location  # not an address at all, e.g. TestClient's peer
        # is_global follows IANA's special-purpose registry but counts
        # multicast as global. No database places any of these.
        if not address.is_global or address.is_multicast:
            location["is_private"] = True
            location["country_name"] = "Private network"
            return location
        # Read once: a refresh may swap the attribute mid-lookup.
        city_reader = self.city_reader
        if city_reader is not None:
            self._apply_city(city_reader, ip, location)
        else:
            self._apply_fallback(ip, location)
        self._apply_asn(ip, location)
        return location

    @staticmethod
    def _apply_city(reader, ip: str, location: Dict[str, Any]) -> None:
        """Country, city, coordinates, time zone and block from GeoLite2-City.

        Geo-blocking judges the country set here. A record without a located
        country falls back to the country its block is registered in, the
        substitution geoip2fast's own builder made, so no address that had a
        country under geoip2fast loses it."""
        try:
            record, prefix_len = reader.get_with_prefix_len(ip)
        except Exception:
            return
        if not record:
            return
        location["cidr"] = _network(ip, prefix_len)
        for key in ("country", "registered_country"):
            country = record.get(key) or {}
            if country.get("iso_code"):
                location["country_code"] = country["iso_code"]
                location["country_name"] = _english_name(country) or country["iso_code"]
                break
        loc = record.get("location") or {}
        if loc.get("latitude") is not None and loc.get("longitude") is not None:
            location["lat"] = loc["latitude"]
            location["lon"] = loc["longitude"]
            location["accuracy_km"] = loc.get("accuracy_radius")
            location["time_zone"] = loc.get("time_zone")
        location["city_name"] = _english_name(record.get("city")) or ""
        subdivisions = record.get("subdivisions") or []
        if subdivisions:
            location["subdivision_name"] = _english_name(subdivisions[0]) or ""
            location["subdivision_code"] = subdivisions[0].get("iso_code") or ""

    def _apply_fallback(self, ip: str, location: Dict[str, Any]) -> None:
        """Country and block from the bundled geoip2fast snapshot, which has
        no city, coordinates or carrier. Its own markers for an unlisted or
        malformed address ("--", "") leave the defaults in place."""
        if self.fallback is None:
            return
        result = self.fallback.lookup(ip)
        if result.country_code and result.country_code != NO_COUNTRY:
            location["country_code"] = result.country_code
            location["country_name"] = result.country_name
            location["cidr"] = result.cidr or None

    def _apply_asn(self, ip: str, location: Dict[str, Any]) -> None:
        """AS org/number/announced block from GeoLite2-ASN, which refreshes
        twice weekly upstream. Left empty when the reader is absent or the DB
        has no record."""
        reader = self.asn_reader
        if reader is None:
            return
        try:
            record, prefix_len = reader.get_with_prefix_len(ip)
        except Exception:
            return
        if not record:
            return
        location["asn_name"] = record.get("autonomous_system_organization")
        location["asn_number"] = record.get("autonomous_system_number")
        location["asn_cidr"] = _network(ip, prefix_len)


class TldNamesManager:
    """Keeps the Public Suffix List that `tld` parses in the writable data
    volume, and keeps it current.

    Two jobs, and both matter for the same reason: `is_valid_domain` is what
    separates a real lookup target from a probe, so a missing or stale list
    turns real domains into probes.

    `_seed` copies the snapshot bundled with the `tld` package into the volume
    the first time. Without it the first `get_tld` call would hit a missing file
    and `tld` would download the list synchronously inside that request, then
    fail writing it to its own package directory — root-owned once the container
    drops to appuser — and repeat that on every later lookup.

    `update` replaces the copy with the current list, atomically, and drops the
    parsed trie so the next lookup reads the new file.
    """

    # tld resolves its data file as NAMES_LOCAL_PATH_PARENT + the parser's own
    # relative path. Read that name off the parser instead of hardcoding it, so
    # a package upgrade that renames the file cannot silently strand us on a
    # copy nothing reads.
    _RELATIVE_PATH = MozillaTLDSourceParser.local_path
    # get_fld(search_private=False), which DomainManager.zone_apex uses for its
    # floor, reads a second file. One list serves both: tld's public-only parser
    # stops reading at "===BEGIN PRIVATE DOMAINS===", so the full list parsed by
    # it is exactly the ICANN-only list. Without a copy here, tld fetches
    # ?publiconly itself inside the first request that needs it, with no
    # timeout, and nothing ever refreshes what it fetched.
    _PUBLIC_ONLY_RELATIVE_PATH = MozillaPublicOnlyTLDSourceParser.local_path

    def __init__(self, directory: str = TLD_NAMES_DIR, url: str = TLD_LIST_URL):
        self.url = url
        self.directory = directory
        self.path = os.path.join(directory, self._RELATIVE_PATH)
        self.public_only_path = os.path.join(directory, self._PUBLIC_ONLY_RELATIVE_PATH)
        self.bundled_path = os.path.join(
            tld_defaults.NAMES_LOCAL_PATH_PARENT, self._RELATIVE_PATH
        )
        # Must happen before anything calls get_tld(); see lookup.py, where this
        # manager is constructed ahead of DomainManager.
        set_tld_setting("NAMES_LOCAL_PATH_PARENT", directory)
        self._seed()
        self._mirror_public_only()

    def _seed(self) -> bool:
        """Put the bundled snapshot in place if the volume has no copy yet."""
        if os.path.exists(self.path):
            return False
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            shutil.copyfile(self.bundled_path, self.path)
            # Stamp the copy as expired. The bundled snapshot is only as fresh
            # as the installed `tld` release, so dating it "now" would hide a
            # year-old list behind a current-looking mtime for a full interval.
            os.utime(self.path, (0, 0))
            logging.info("Seeded the public suffix list from %s", self.bundled_path)
            return True
        except Exception:
            logging.exception(
                "Could not seed the public suffix list from %s", self.bundled_path
            )
            return False

    @staticmethod
    def _replace(path: str, data: bytes) -> None:
        """Write via a temp file and os.replace, so a reader never sees half."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "wb") as handle:
            handle.write(data)
        os.replace(tmp, path)

    def _mirror_public_only(self) -> bool:
        """Make the public-only copy the same as the full list. Returns whether
        it changed. Runs at boot too, because a volume from before this existed
        has either no copy or the one tld fetched once and never refreshed."""
        try:
            with open(self.path, "rb") as handle:
                full = handle.read()
        except OSError:
            return False  # no list at all; _seed has already said why
        try:
            with open(self.public_only_path, "rb") as handle:
                if handle.read() == full:
                    return False
        except OSError:
            pass
        try:
            self._replace(self.public_only_path, full)
        except OSError:
            logging.exception(
                "Could not write the public-only suffix list to %s",
                self.public_only_path,
            )
            return False
        # Drop that parser's trie only; the full list's is still current.
        reset_tld_names(self._PUBLIC_ONLY_RELATIVE_PATH)
        return True

    def age_days(self) -> float | None:
        """Age of the downloaded list, or None when there isn't one — the file
        is missing, or it is the bundled seed stamped with mtime 0."""
        try:
            mtime = os.path.getmtime(self.path)
        except OSError:
            return None
        return None if mtime == 0 else (time.time() - mtime) / 86400

    def is_stale(self) -> bool:
        age = self.age_days()
        return age is None or age >= TLD_MAX_AGE_DAYS

    def is_overdue(self) -> bool:
        """Past the point a working refresh would have replaced it, for
        /healthz. is_stale() turns true at TLD_MAX_AGE_DAYS, but the job that
        acts on it runs once a day, so a healthy list sits up to a day past
        that; the second day of grace keeps that from reading as a fault."""
        age = self.age_days()
        return age is None or age >= TLD_MAX_AGE_DAYS + 2

    def update(self, force: bool = False) -> bool:
        """Fetch the list and swap it in when the local copy has aged out.

        Returns whether the local copy is current afterwards, so a run skipped
        because the list is still fresh counts as success and does not arm the
        retry timer.
        """
        if not force and not self.is_stale():
            # Still current, but a public-only copy that went missing, or failed
            # to write last time, should not wait out the whole interval.
            self._mirror_public_only()
            return True
        try:
            # url is the hardcoded https publicsuffix.org endpoint by default.
            with urllib.request.urlopen(  # noqa: S310
                self.url, timeout=TIMEOUT_SECONDS * 4
            ) as response:
                text = response.read().decode("utf-8")
            # A truncated download or a captive-portal error page must never
            # replace a working list: the parser would build a trie that matches
            # nothing, is_valid_domain would answer False for every domain, and
            # the middleware would then read ordinary lookups as probes and ban
            # the visitors making them.
            if "===BEGIN ICANN DOMAINS===" not in text:
                raise ValueError(f"{self.url} did not return a public suffix list")
            self._replace(self.path, text.encode("utf-8"))
            self._mirror_public_only()
            # Drop the parsed tries, or get_tld keeps answering from the copies
            # it read at boot for the life of the process.
            reset_tld_names()
            logging.info("Public suffix list updated (%d bytes)", len(text))
            return True
        except Exception:
            logging.exception("Error updating the public suffix list")
            return False

    def status(self) -> Dict[str, Any]:
        age = self.age_days()
        if not os.path.exists(self.path):
            source = "missing"
        else:
            source = "downloaded" if age is not None else "bundled"
        return {
            "source": source,
            "age_days": round(age, 1) if age is not None else None,
            "stale": self.is_stale(),
        }


class DomainManager:
    def is_ipv4(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).version == 4
        except ValueError:
            return False

    def is_valid_domain(self, domain) -> bool:
        """Whether the string has a public suffix, per the list TldNamesManager
        keeps current.

        TldBadUrl is caught alongside TldDomainNotFound: an empty or
        punctuation-only target ("", "//") raises the former, not the latter,
        and this has to be total — the MCP lookup tool passes user input
        straight in, and the security middleware asks it whether a suspicious
        path is a real domain before deciding to ban.
        """
        try:
            get_tld(domain, fix_protocol=True)
            return True
        except (tld_exceptions.TldDomainNotFound, tld_exceptions.TldBadUrl):
            return False

    def zone_apex(self, domain: str) -> str:
        """The apex of the DNS zone that serves `domain`: where its NS live, and
        the MX and SPF it falls back to.

        Counting labels cannot find it -- keeping the last two turned
        naver.co.kr into co.kr, whose NS are the registry's and whose MX is
        empty, which reads as "this domain has no mail server". DNS knows: one
        SOA query usually answers, because a name below an apex comes back with
        the apex's SOA in the authority section. The walk up the labels gets
        one query's budget in total, not one per label.

        The registrable domain is a floor. A name that does not exist comes back
        NXDOMAIN with the registry's SOA, which is true of the DNS tree but
        would list co.kr's nameservers as the name's own. It is also the
        fallback when DNS cannot answer. ICANN suffixes only: a private one
        (github.io) is a real operator's zone, not a registry's.
        """
        floor = (
            get_fld(domain, fail_silently=True, fix_protocol=True, search_private=False)
            or domain
        )
        try:
            zone = dns.resolver.zone_for_name(
                domain, resolver=_recursive_resolver(), lifetime=DNS_QUERY_LIFETIME
            )
        except Exception as e:
            # %r: the name may be user input, and repr escapes control chars.
            logging.debug("Zone lookup failed for %r: %s", domain, e)
            return floor
        zone = zone.to_text(omit_final_dot=True).lower()
        if zone == floor or zone.endswith("." + floor):
            return zone
        return floor

    def get_records(
        self, domain: str, ns_servers: list | None = None, ip: str | None = None
    ) -> dict:
        # ns_servers is kept for signature compatibility but unused: every query
        # now goes to the cached public resolvers (see _recursive_resolver).
        # A PTR target arrives as DNS text, trailing dot and all ('dns.google.').
        domain = domain.rstrip(".").lower()
        # NS, the MX fallback and the zone's SPF all hang off the zone, so it
        # is found once, up front. Running it alongside the sweep would not end
        # it any sooner: the NS chain (zone, NS, host A) is the long pole anyway.
        base_domain = self.zone_apex(domain)
        records = {
            "queried_name": domain,
            "zone": base_domain,
            "mx": [],
            "ns": [],
            "cname": None,
            "txt": [],
            "spf": [],
            "ptr": [],
            "a": [],
            "aaaa": [],
            # Each type's dns_status(), or "ok". An empty list above says only
            # that nothing came back; this says whether that was the answer
            # (noanswer, nxdomain) or the query failing (timeout, servfail,
            # error), which the lists alone used to render identically.
            "status": {},
        }
        status = records["status"]

        def fetch_ns() -> tuple[list, str]:
            try:
                answer = _recursive_resolver().resolve(base_domain, "NS")
            except Exception as e:
                return [], dns_status(e)
            targets = [r.target for r in answer]
            return _with_host_ips(
                [{"hostname": t.to_text(), "ttl": answer.rrset.ttl} for t in targets]
            ), "ok"

        def fetch_a() -> tuple[list, str]:
            try:
                answer = _recursive_resolver().resolve(domain, "A")
            except Exception as e:
                return [], dns_status(e)
            return [{"ip": str(r), "ttl": answer.rrset.ttl} for r in answer], "ok"

        def fetch_aaaa() -> tuple[list, str]:
            # Asked over IPv4 like every other type: the public resolvers are
            # IPv4 addresses, and this server has no IPv6 route to use anyway.
            try:
                answer = _recursive_resolver().resolve(domain, "AAAA")
            except Exception as e:
                return [], dns_status(e)
            return [{"ip": str(r), "ttl": answer.rrset.ttl} for r in answer], "ok"

        def mx_answer():
            """The queried name's own MX; failing that, the zone's, and whose."""
            try:
                return _recursive_resolver().resolve(domain, "MX"), None
            except dns.resolver.NoAnswer:
                # The name exists but has no MX of its own, so mail looks to the
                # zone -- labelled, so it is never read as this name's own.
                if base_domain == domain:
                    raise
            return _recursive_resolver().resolve(base_domain, "MX"), base_domain

        def fetch_mx() -> tuple[list, str]:
            try:
                answer, from_zone = mx_answer()
            except Exception as e:
                # Whichever query raised is the one the row stands on. Once the
                # name has answered "no MX of my own", the row is the zone's, so
                # a zone that timed out is a timeout: reporting the name's
                # noanswer would read as "no mail server", the very misreading
                # the zone fallback is there to prevent.
                return [], dns_status(e)
            # Most-preferred first, so when _with_host_ips stops resolving at
            # its limit, the hosts it skipped are the ones mail tries last.
            rows = sorted(answer, key=lambda r: r.preference)
            return _with_host_ips(
                [
                    {
                        "preference": r.preference,
                        "hostname": r.exchange.to_text(),
                        "ttl": answer.rrset.ttl,
                        **({"from_zone": from_zone} if from_zone else {}),
                    }
                    for r in rows
                ]
            ), "ok"

        def fetch_cname() -> tuple[dict | None, str]:
            try:
                answer = _recursive_resolver().resolve(domain, "CNAME")
            except Exception as e:
                return None, dns_status(e)
            return {
                "cname": answer.rrset[0].target.to_text(),
                "ttl": answer.rrset.ttl,
            }, "ok"

        def spf_from(answer) -> list:
            spf = []
            for r in answer:
                # A policy over 255 bytes arrives split wherever byte 255
                # falls, often mid-address; RFC 7208 §3.3 says concatenate
                # with no separator.
                joined = "".join(s.decode("utf-8", errors="replace") for s in r.strings)
                if joined.startswith("v=spf1"):
                    spf.append({"text": joined, "ttl": answer.rrset.ttl})
            return spf

        def fetch_txt() -> tuple[list, list, str]:
            try:
                answer = _recursive_resolver().resolve(domain, "TXT")
            except Exception as e:
                return [], [], dns_status(e)
            txt = [
                {
                    "text": [s.decode("utf-8", errors="replace") for s in r.strings],
                    "ttl": answer.rrset.ttl,
                }
                for r in answer
            ]
            return txt, spf_from(answer), "ok"

        def fetch_base_spf() -> tuple[list, str | None]:
            if base_domain == domain:
                return [], None
            try:
                answer = _recursive_resolver().resolve(base_domain, "TXT")
            except Exception as e:
                return [], dns_status(e)
            return spf_from(answer), "ok"

        def spf_status(txt_status: str, base_status: str | None) -> str:
            """SPF is two queries (the name's TXT and the zone's) filtered to
            v=spf1. A policy found in either is an answer; with none found, a
            query that failed means "unknown", not "no SPF"."""
            if records["spf"]:
                return "ok"
            for outcome in (txt_status, base_status):
                if outcome in DNS_FAILURES:
                    return outcome
            return "nxdomain" if txt_status == "nxdomain" else "noanswer"

        def fetch_ptr(lookup_ip: str) -> tuple[list, str]:
            try:
                answer = _recursive_resolver().resolve(
                    dns.reversename.from_address(lookup_ip), "PTR"
                )
            except Exception as e:
                logging.debug("PTR record lookup failed for %s", lookup_ip)
                return [], dns_status(e)
            return [{"hostname": str(r), "ttl": answer.rrset.ttl} for r in answer], "ok"

        # Every record type is independent, so sweep them at once against the
        # cached public resolvers instead of walking them in series.
        with ThreadPoolExecutor(max_workers=8) as pool:
            f_ns = pool.submit(fetch_ns)
            f_a = pool.submit(fetch_a)
            f_aaaa = pool.submit(fetch_aaaa)
            f_mx = pool.submit(fetch_mx)
            f_cname = pool.submit(fetch_cname)
            f_txt = pool.submit(fetch_txt)
            f_base_spf = pool.submit(fetch_base_spf)
            f_ptr = pool.submit(fetch_ptr, ip) if ip else None

            records["ns"], status["ns"] = f_ns.result()
            records["a"], status["a"] = f_a.result()
            records["aaaa"], status["aaaa"] = f_aaaa.result()
            records["mx"], status["mx"] = f_mx.result()
            records["cname"], status["cname"] = f_cname.result()
            records["txt"], records["spf"], status["txt"] = f_txt.result()
            base_spf, base_spf_status = f_base_spf.result()
            for entry in base_spf:
                if not any(s["text"] == entry["text"] for s in records["spf"]):
                    records["spf"].append(entry)
            status["spf"] = spf_status(status["txt"], base_spf_status)
            if f_ptr is not None:
                records["ptr"], status["ptr"] = f_ptr.result()

        # Fallback only when a caller omits ip -- which gather() does when its
        # own A and AAAA queries failed, so the sweep's answers may still
        # supply one.
        if not ip:
            address = next(iter(records["a"] or records["aaaa"]), None)
            if address:
                records["ptr"], status["ptr"] = fetch_ptr(address["ip"])
            else:
                # No address, so no PTR question was asked: the row is exactly
                # as known as the A query that would have supplied one.
                status["ptr"] = status["a"]

        return records

    def perform_reverse_lookup(self, ip: str) -> str:
        try:
            reverse_name = dns.reversename.from_address(ip)
            # The public resolvers, not the system one: in the container that
            # is Docker's 127.0.0.11 with a 5s lifetime, and the self page
            # waits on this answer before it starts the DNS sweep.
            ptr_records = _recursive_resolver().resolve(reverse_name, "PTR")
            return str(ptr_records[0])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
            # Most client IPs have no PTR record. That is an answer, not a
            # failure, so it stays out of the warning stream.
            logging.debug("No PTR record for %s: %s", ip, e)
            return None
        except Exception as e:
            # Timeouts and SERVFAIL are the resolver failing and stay visible,
            # at warning rather than error so SigNoz error metrics stay clean.
            logging.warning(f"Reverse lookup failed for IP {ip}: {str(e)}")
            return None


# X509_V_ERR_* codes as OpenSSL reports them on SSLCertVerificationError,
# folded into the reasons a reader actually asks about. Any other code keeps
# its number and OpenSSL's message under "other".
_VERIFY_REASONS = {
    2: "chain_incomplete",  # unable to get issuer certificate
    9: "not_yet_valid",
    10: "expired",
    18: "self_signed",
    19: "untrusted_root",  # self-signed certificate in certificate chain
    # "unable to get local issuer certificate": the server left an intermediate
    # out (kaia.org), or its root is a private CA it never sends.
    20: "chain_incomplete",
    21: "chain_incomplete",  # unable to verify the first certificate
    62: "hostname_mismatch",
}

# getpeercert() keys subject and issuer attributes by OpenSSL's long names.
_NAME_KEYS = {
    NameOID.COUNTRY_NAME: "countryName",
    NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
    NameOID.LOCALITY_NAME: "localityName",
    NameOID.ORGANIZATION_NAME: "organizationName",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
    NameOID.COMMON_NAME: "commonName",
    NameOID.SERIAL_NUMBER: "serialNumber",
    NameOID.BUSINESS_CATEGORY: "businessCategory",
    NameOID.JURISDICTION_COUNTRY_NAME: "jurisdictionCountryName",
    NameOID.EMAIL_ADDRESS: "emailAddress",
}
_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def _asn1_time(when: datetime) -> str:
    # OpenSSL's print form, "Nov  9 23:22:58 2026 GMT". The month is spelled
    # out here because strftime's %b follows the process locale.
    return f"{_MONTHS[when.month - 1]} {when.day:2d} {when:%H:%M:%S} {when.year} GMT"


def _rdns(name: x509.Name) -> tuple:
    return tuple(
        tuple(
            (_NAME_KEYS.get(attr.oid, attr.oid.dotted_string), str(attr.value))
            for attr in rdn
        )
        for rdn in name.rdns
    )


def _peercert_from_der(der: bytes) -> dict:
    """getpeercert()'s dict, rebuilt from a DER certificate.

    getpeercert() decodes only a certificate that verified; after a CERT_NONE
    handshake it returns {}. Rebuilding the same shape keeps every reader
    downstream (viewmodel, mcp_server) unaware of which handshake it came from.
    """
    cert = x509.load_der_x509_certificate(der)
    serial = f"{cert.serial_number:X}"
    peercert = {
        "subject": _rdns(cert.subject),
        "issuer": _rdns(cert.issuer),
        "version": cert.version.value + 1,
        # Whole bytes, upper case: how OpenSSL prints an ASN.1 INTEGER.
        "serialNumber": serial.zfill(len(serial) + len(serial) % 2),
        "notBefore": _asn1_time(cert.not_valid_before_utc),
        "notAfter": _asn1_time(cert.not_valid_after_utc),
    }
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except (x509.ExtensionNotFound, ValueError):  # ValueError: malformed extensions
        return peercert
    names = []
    for entry in san.value:
        if isinstance(entry, x509.DNSName):
            names.append(("DNS", entry.value))
        elif isinstance(entry, x509.IPAddress):
            names.append(("IP Address", str(entry.value)))
    if names:
        peercert["subjectAltName"] = tuple(names)
    return peercert


def _hostname_matches(peercert: dict, hostname: str) -> bool:
    """RFC 6125: whether the certificate names `hostname`. A wildcard covers
    exactly one left-most label, and the CN counts only when there is no DNS
    SAN, as in OpenSSL's own check. viewmodel._host_covered does the same for
    display; restated rather than imported, since managers depend only on
    config."""
    host = hostname.lower().rstrip(".")
    names = [v for kind, v in peercert.get("subjectAltName", ()) if kind == "DNS"]
    if not names:
        names = [
            v
            for rdn in peercert.get("subject", ())
            for k, v in rdn
            if k == "commonName"
        ]
    for name in (n.lower().rstrip(".") for n in names):
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]  # ".example.com"
            label = host[: -len(suffix)]
            if host.endswith(suffix) and label and "." not in label:
                return True
    return False


def _failure_reason(exc: OSError) -> str:
    """A short phrase for why a connect or a handshake failed."""
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, TimeoutError):
        return "timed out"
    if isinstance(exc, ssl.SSLError) and exc.reason:
        return exc.reason.lower().replace("_", " ")  # WRONG_VERSION_NUMBER
    return str(exc.strerror or exc).lower()


# What get_ssl_info answers for an IPv6 address instead of a handshake.
# Production has no IPv6 route out, and _connect's socket is IPv4 only, so the
# connect could only fail and read as "port 443 unreachable", the host's fault.
# gather() passes an IPv6 address only for a name that has no A record.
TLS_SKIPPED_IPV6 = {
    "error": "TLS not checked",
    "reason": "IPv6-only host; this server has no IPv6 connectivity",
}


class SSLManager:
    @staticmethod
    def get_ssl_info(hostname: str, verified_ip: str | None = None) -> dict | None:
        """The certificate `hostname` serves on port 443, and whether it is
        trusted.

        None only when there was no address to connect to. A certificate that
        fails verification still comes back, parsed, with trusted=False and
        verify_error saying why; a port that never answers, or a handshake
        that never completes, comes back as {"error", "reason"}, and so does an
        IPv6 address, which is never tried (TLS_SKIPPED_IPV6). All of these
        used to be None, which the page and MCP could only call "no
        certificate".
        """
        # Connect only to the caller-verified IP. Falling back to hostname
        # would re-resolve DNS and reopen the rebinding window between an
        # earlier is_safe_ip() check and this socket connection.
        if not verified_ip:
            logging.debug("SSL lookup skipped for %s: no verified IP", str(hostname))
            return None
        if ipaddress.ip_address(verified_ip).version == 6:
            return dict(TLS_SKIPPED_IPV6)
        try:
            sock = SSLManager._connect(verified_ip)
        except OSError as exc:
            reason = _failure_reason(exc)
            logging.info(
                "TLS lookup for %s: port 443 unreachable: %s", hostname, reason
            )
            return {"error": "port 443 unreachable", "reason": reason}
        try:
            ctx = SSLManager._context(verify=True)
            with ctx.wrap_socket(sock, server_hostname=hostname) as s:
                cert = s.getpeercert()
                if not cert:
                    return None
                cert = {**cert, **SSLManager._session(s)}
            return {
                **cert,
                "trusted": True,
                "verify_error": None,
                "hostname_match": True,
            }
        except ssl.SSLCertVerificationError as exc:
            # The site's certificate is broken; nothing here is. INFO, not
            # ERROR: kaia.org's missing intermediate used to log as an error.
            logging.info(
                "TLS lookup for %s: certificate not trusted: %s",
                hostname,
                exc.verify_message,
            )
            return SSLManager._untrusted(hostname, verified_ip, exc)
        except OSError as exc:
            # Port 443 answered but no TLS session came of it: plain HTTP on
            # 443, nothing newer than TLS 1.1, a reset, a stalled handshake.
            reason = _failure_reason(exc)
            logging.info("TLS lookup for %s: handshake failed: %s", hostname, reason)
            return {"error": "TLS handshake failed", "reason": reason}
        except Exception:
            logging.exception(
                f"Error performing SSL certificate lookup for hostname: {str(hostname)}"
            )
            return {"error": "TLS lookup failed"}

    @staticmethod
    def _connect(verified_ip: str) -> socket.socket:
        sock = socket.socket()
        sock.settimeout(TIMEOUT_SECONDS)
        try:
            sock.connect((verified_ip, 443))
        except OSError:
            sock.close()
            raise
        return sock

    @staticmethod
    def _context(verify: bool) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not verify:
            # In this order: verify_mode cannot drop to CERT_NONE while
            # check_hostname is still on.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    @staticmethod
    def _session(s: ssl.SSLSocket) -> dict:
        # Connection-level details ("SSL type"): the negotiated TLS protocol
        # and cipher. Must be read inside the with-block, before the socket
        # closes.
        session = {"protocol": s.version()}
        negotiated = s.cipher()
        if negotiated:
            session["cipher"] = {
                "name": negotiated[0],
                "protocol": negotiated[1],
                "bits": negotiated[2],
            }
        return session

    @staticmethod
    def _untrusted(
        hostname: str, verified_ip: str, exc: ssl.SSLCertVerificationError
    ) -> dict:
        """Re-read a certificate the verifying handshake rejected.

        A second handshake with verification off, to the same verified IP:
        never the hostname, so there is no second DNS lookup and no new SSRF
        surface. The hostname rides along only as SNI, so the server picks the
        certificate it served the first time.
        """
        reason = _VERIFY_REASONS.get(exc.verify_code, "other")
        verdict = {
            "trusted": False,
            "verify_error": {
                "code": exc.verify_code,
                "message": exc.verify_message,
                "reason": reason,
            },
            # OpenSSL stops at the first failure and checks the chain before
            # the name, so only a mismatch is known yet; any other failure
            # leaves the name to be checked against the certificate below.
            "hostname_match": False if reason == "hostname_mismatch" else None,
        }
        try:
            sock = SSLManager._connect(verified_ip)
            ctx = SSLManager._context(verify=False)
            with ctx.wrap_socket(sock, server_hostname=hostname) as s:
                der = s.getpeercert(binary_form=True)
                session = SSLManager._session(s)
            cert = _peercert_from_der(der) if der else None
        except (OSError, ValueError) as reread:
            logging.info(
                "TLS lookup for %s: untrusted certificate not re-read: %s",
                hostname,
                reread,
            )
            cert = None
        if cert is None:
            # The verdict is still the answer, certificate or not.
            return verdict
        if verdict["hostname_match"] is None:
            verdict["hostname_match"] = _hostname_matches(cert, hostname)
        return {**cert, **session, **verdict}


class HeaderManager:
    @staticmethod
    def filter_out_unwanted(original_headers: dict, exclude_prefixes: list) -> dict:
        return {
            k: v
            for k, v in original_headers.items()
            if not any(k.lower().startswith(prefix) for prefix in exclude_prefixes)
        }
