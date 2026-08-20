"""Data-gathering managers: GeoIP + city overlay, DNS, SSL, and header hygiene.

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

import dns.resolver
import dns.reversename
import maxminddb
from geoip2fast import GeoIP2Fast
from tld import exceptions as tld_exceptions
from tld import get_tld

from tld import defaults as tld_defaults
from tld.conf import set_setting as set_tld_setting
from tld.utils import MozillaTLDSourceParser, reset_tld_names

from config import (
    DNS_QUERY_LIFETIME,
    DNS_QUERY_TIMEOUT,
    GEOIP_ASN_DB_FILE,
    GEOIP_ASN_DB_URL,
    GEOIP_CITY_DB_FILE,
    GEOIP_CITY_DB_URL,
    GEOIP_DATA_FILE,
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


class GeoIpManager:
    def __init__(self):
        self.instance, source = self._load_instance()
        self.db_info = self._describe_db(self.instance, source)
        self.city_reader = self._open_mmdb_reader(GEOIP_CITY_DB_FILE)
        self.asn_reader = self._open_mmdb_reader(GEOIP_ASN_DB_FILE)
        self._log_db_status()

    @staticmethod
    def _load_instance():
        """Load the volume database, falling back to the bundled one when the
        volume file is missing or corrupt. An interrupted download can leave a
        truncated .dat.gz that GeoIP2Fast raises on; that must degrade the app to
        the built-in country DB, not crash it at startup. update_database()
        refreshes a good copy on the next run. Returns (instance, source) so the
        fallback shows up in logs and the health endpoint."""
        if os.path.exists(GEOIP_DATA_FILE):
            try:
                return GeoIP2Fast(geoip2fast_data_file=GEOIP_DATA_FILE), "volume"
            except Exception:
                logging.exception(
                    "GeoIP DB at %s is unreadable; using the bundled database",
                    GEOIP_DATA_FILE,
                )
        return GeoIP2Fast(), "bundled"

    @staticmethod
    def _describe_db(instance: GeoIP2Fast, source: str) -> Dict[str, Any]:
        """A snapshot of what the loaded geoip2fast DB contains, captured at
        load time — get_database_info() re-reads the file path the instance was
        loaded from, which is gone once a refreshed temp file has been
        os.replace()d over the live one."""
        try:
            info = instance.get_database_info()
            return {
                "source": source,
                "content": info.get("database_content"),
                "build": info.get("source_info"),
            }
        except Exception:
            return {"source": source, "content": None, "build": None}

    @staticmethod
    def _open_mmdb_reader(path: str):
        if os.path.exists(path):
            try:
                return maxminddb.open_database(path)
            except Exception:
                logging.exception("Could not open mmdb database at %s", path)
        return None

    def _log_db_status(self):
        info = self.db_info
        logging.info(
            "GeoIP DB loaded: source=%s content=%r build=%r "
            "city_overlay=%s asn_overlay=%s",
            info["source"],
            info["content"],
            info["build"],
            self.city_reader is not None,
            self.asn_reader is not None,
        )
        if "ASN" not in (info["content"] or "") and self.asn_reader is None:
            logging.warning(
                "No ASN data available (geoip2fast DB is %r, no GeoLite2-ASN "
                "overlay); carrier lookups stay empty until a refresh succeeds",
                info["content"],
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
        visible from outside."""
        return {
            "geoip2fast": dict(self.db_info),
            "city_overlay": self._mmdb_status(self.city_reader),
            "asn_overlay": self._mmdb_status(self.asn_reader),
        }

    def update_database(self) -> bool:
        # The temp name must keep the .dat.gz suffix: update_file() refuses any
        # other extension with an {'error': ...} result instead of raising, and
        # downloads nothing.
        tmp = GEOIP_DATA_FILE + ".tmp.dat.gz"
        try:
            data_dir = os.path.dirname(GEOIP_DATA_FILE)
            if data_dir:
                os.makedirs(data_dir, exist_ok=True)
            # Download to a temp file and only swap it in once it loads cleanly.
            # Writing straight to GEOIP_DATA_FILE meant an interrupted download
            # left a truncated file that crashed the next startup; os.replace is
            # atomic, so the live file is only ever a complete, loadable DB.
            if os.path.exists(tmp):
                os.remove(tmp)
            update_result = self.instance.update_file(
                "geoip2fast-city-asn-ipv6.dat.gz", tmp, verbose=False
            )
            # update_file reports failures as a result dict, not an exception.
            if isinstance(update_result, dict) and update_result.get("error"):
                raise RuntimeError(update_result["error"])
            new_instance = GeoIP2Fast(geoip2fast_data_file=tmp)  # validates it loads
            new_info = self._describe_db(new_instance, "volume")  # before the swap
            os.replace(tmp, GEOIP_DATA_FILE)
            self.instance = new_instance
            self.db_info = new_info
            logging.info(f"{update_result=}")
            return True
        except Exception as e:
            logging.exception(f"Error updating GeoIP2Fast database: {str(e)}")
            try:
                os.remove(tmp)
            except OSError:
                pass
            return False

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
        """A single flat location record for the IP: country (plus coarse ASN
        fallback) from geoip2fast, precise city/lat/lon/accuracy/time zone
        overlaid from GeoLite2-City, and the AS org/number/announced block
        overlaid from GeoLite2-ASN when loaded. Callers add reverse_dns; the
        response assembly adds the resolved coordinates, the origin_* fields,
        and distance_km."""
        raw = self.instance.lookup(ip).to_dict()
        city = raw.get("city") if isinstance(raw.get("city"), dict) else {}
        self._overlay_city(ip, raw.get("is_private"), city)
        asn = self._asn_overlay(ip, raw.get("is_private"))
        return {
            "ip": raw.get("ip"),
            "country_code": raw.get("country_code"),
            "country_name": raw.get("country_name"),
            "city_name": city.get("name") or "",
            "subdivision_name": city.get("subdivision_name") or "",
            "subdivision_code": city.get("subdivision_code") or "",
            "lat": city.get("latitude"),
            "lon": city.get("longitude"),
            "accuracy_km": city.get("accuracy_radius"),
            "time_zone": city.get("time_zone"),
            "cidr": raw.get("cidr"),
            "asn_name": asn.get("name") or raw.get("asn_name"),
            "asn_cidr": asn.get("cidr") or raw.get("asn_cidr"),
            "asn_number": asn.get("number"),
            "is_private": raw.get("is_private"),
            "hostname": raw.get("hostname"),
        }

    def _asn_overlay(self, ip: str, is_private: Any) -> Dict[str, Any]:
        """AS org/number/announced block from GeoLite2-ASN, which refreshes
        twice weekly upstream — fresher than geoip2fast's release snapshot.
        Empty when the reader is absent, the IP is private, or the DB has no
        record; callers then fall back to geoip2fast's ASN fields."""
        if not self.asn_reader or is_private:
            return {}
        try:
            record, prefix_len = self.asn_reader.get_with_prefix_len(ip)
        except Exception:
            return {}
        if not record:
            return {}
        try:
            network = str(ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False))
        except ValueError:
            network = None
        return {
            "name": record.get("autonomous_system_organization"),
            "number": record.get("autonomous_system_number"),
            "cidr": network,
        }

    def _overlay_city(self, ip: str, is_private: Any, city: Dict[str, Any]) -> None:
        """Overlay the precise city, coordinates, accuracy and time zone from
        GeoLite2-City onto the (still nested) geoip2fast city dict before it is
        flattened. geoip2fast keeps country/ASN duty; MaxMind supplies the
        latitude/longitude geoip2fast always leaves null."""
        if not self.city_reader or is_private:
            return
        try:
            record = self.city_reader.get(ip)
        except Exception:
            record = None
        if not record:
            return
        loc = record.get("location") or {}
        if loc.get("latitude") is not None and loc.get("longitude") is not None:
            city["latitude"] = loc.get("latitude")
            city["longitude"] = loc.get("longitude")
            city["accuracy_radius"] = loc.get("accuracy_radius")
            city["time_zone"] = loc.get("time_zone")
        mm_city = ((record.get("city") or {}).get("names") or {}).get("en")
        if mm_city:
            city["name"] = mm_city
        subdivisions = record.get("subdivisions") or []
        if subdivisions:
            names = subdivisions[0].get("names") or {}
            if names.get("en"):
                city["subdivision_name"] = names["en"]
            if subdivisions[0].get("iso_code"):
                city["subdivision_code"] = subdivisions[0]["iso_code"]


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

    def __init__(self, directory: str = TLD_NAMES_DIR, url: str = TLD_LIST_URL):
        self.url = url
        self.directory = directory
        self.path = os.path.join(directory, self._RELATIVE_PATH)
        self.bundled_path = os.path.join(
            tld_defaults.NAMES_LOCAL_PATH_PARENT, self._RELATIVE_PATH
        )
        # Must happen before anything calls get_tld(); see lookup.py, where this
        # manager is constructed ahead of DomainManager.
        set_tld_setting("NAMES_LOCAL_PATH_PARENT", directory)
        self._seed()

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

    def update(self, force: bool = False) -> bool:
        """Fetch the list and swap it in when the local copy has aged out.

        Returns whether the local copy is current afterwards, so a run skipped
        because the list is still fresh counts as success and does not arm the
        retry timer.
        """
        if not force and not self.is_stale():
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
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write(text)
            os.replace(tmp, self.path)
            # Drop the parsed trie, or get_tld keeps answering from the copy it
            # read at boot for the life of the process.
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

    def remove_subdomains(self, domain: str) -> str:
        # remove subdomains
        return ".".join(domain.split(".")[-2:])

    def get_records(
        self, domain: str, ns_servers: list | None = None, ip: str | None = None
    ) -> dict:
        # ns_servers is kept for signature compatibility but unused: every query
        # now goes to the cached public resolvers (see _recursive_resolver).
        records = {
            "mx": [],
            "ns": [],
            "cname": None,
            "txt": [],
            "spf": [],
            "ptr": [],
            "a": [],
        }
        base_domain = self.remove_subdomains(domain)

        def a_ip(name: str) -> str | None:
            try:
                return str(_recursive_resolver().resolve(name, "A")[0])
            except Exception:
                return None

        def fetch_ns() -> list:
            try:
                answer = _recursive_resolver().resolve(base_domain, "NS")
            except Exception:
                return []
            targets = [r.target for r in answer]
            with ThreadPoolExecutor(max_workers=max(len(targets), 1)) as pool:
                ips = list(pool.map(lambda t: a_ip(str(t)), targets))
            return [
                {"hostname": t.to_text(), "ttl": answer.rrset.ttl, "ip": ip_}
                for t, ip_ in zip(targets, ips)
            ]

        def fetch_a() -> list:
            try:
                answer = _recursive_resolver().resolve(domain, "A")
            except Exception:
                return []
            return [{"ip": str(r), "ttl": answer.rrset.ttl} for r in answer]

        def fetch_mx() -> list:
            try:
                answer = _recursive_resolver().resolve(base_domain, "MX")
            except Exception:
                return []
            rows = list(answer)
            with ThreadPoolExecutor(max_workers=max(len(rows), 1)) as pool:
                ips = list(pool.map(lambda r: a_ip(str(r.exchange)), rows))
            return [
                {
                    "preference": r.preference,
                    "hostname": r.exchange.to_text(),
                    "ttl": answer.rrset.ttl,
                    "ip": ip_,
                }
                for r, ip_ in zip(rows, ips)
            ]

        def fetch_cname():
            try:
                answer = _recursive_resolver().resolve(domain, "CNAME")
            except Exception:
                return None
            return {
                "cname": answer.rrset[0].target.to_text(),
                "ttl": answer.rrset.ttl,
            }

        def spf_from(answer) -> list:
            spf = []
            for r in answer:
                joined = " ".join(
                    s.decode("utf-8", errors="replace") for s in r.strings
                )
                if joined.startswith("v=spf1"):
                    spf.append({"text": joined, "ttl": answer.rrset.ttl})
            return spf

        def fetch_txt():
            try:
                answer = _recursive_resolver().resolve(domain, "TXT")
            except Exception:
                return [], []
            txt = [
                {
                    "text": [s.decode("utf-8", errors="replace") for s in r.strings],
                    "ttl": answer.rrset.ttl,
                }
                for r in answer
            ]
            return txt, spf_from(answer)

        def fetch_base_spf() -> list:
            if base_domain == domain:
                return []
            try:
                answer = _recursive_resolver().resolve(base_domain, "TXT")
            except Exception:
                return []
            return spf_from(answer)

        def fetch_ptr(lookup_ip: str) -> list:
            try:
                answer = _recursive_resolver().resolve(
                    dns.reversename.from_address(lookup_ip), "PTR"
                )
            except Exception:
                logging.debug("PTR record lookup failed for %s", lookup_ip)
                return []
            return [{"hostname": str(r), "ttl": answer.rrset.ttl} for r in answer]

        # Every record type is independent, so sweep them at once against the
        # cached public resolvers instead of walking them in series.
        with ThreadPoolExecutor(max_workers=7) as pool:
            f_ns = pool.submit(fetch_ns)
            f_a = pool.submit(fetch_a)
            f_mx = pool.submit(fetch_mx)
            f_cname = pool.submit(fetch_cname)
            f_txt = pool.submit(fetch_txt)
            f_base_spf = pool.submit(fetch_base_spf)
            f_ptr = pool.submit(fetch_ptr, ip) if ip else None

            records["ns"] = f_ns.result()
            records["a"] = f_a.result()
            records["mx"] = f_mx.result()
            records["cname"] = f_cname.result()
            records["txt"], records["spf"] = f_txt.result()
            for entry in f_base_spf.result():
                if not any(s["text"] == entry["text"] for s in records["spf"]):
                    records["spf"].append(entry)
            if f_ptr is not None:
                records["ptr"] = f_ptr.result()

        # Fallback only when a caller omits ip (all current callers pass it).
        if not ip and records["a"]:
            records["ptr"] = fetch_ptr(records["a"][0]["ip"])

        return records

    def perform_reverse_lookup(self, ip: str) -> str:
        try:
            reverse_name = dns.reversename.from_address(ip)
            ptr_records = dns.resolver.resolve(
                reverse_name, "PTR", lifetime=TIMEOUT_SECONDS
            )
            return str(ptr_records[0])
        except Exception as e:
            # Most reverse lookups miss because client IPs lack a PTR record
            # (NXDOMAIN). Log at warning level so SigNoz error metrics stay clean.
            logging.warning(f"Reverse lookup failed for IP {ip}: {str(e)}")
            return None


class SSLManager:
    @staticmethod
    def get_ssl_info(hostname: str, verified_ip: str | None = None) -> dict | None:
        # Connect only to the caller-verified IP. Falling back to hostname
        # would re-resolve DNS and reopen the rebinding window between an
        # earlier is_safe_ip() check and this socket connection.
        if not verified_ip:
            logging.debug("SSL lookup skipped for %s: no verified IP", str(hostname))
            return None
        cert = None
        try:
            ctx = ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            sock = socket.socket()
            sock.settimeout(TIMEOUT_SECONDS)
            sock.connect((verified_ip, 443))
            with ctx.wrap_socket(sock, server_hostname=hostname) as s:
                cert = s.getpeercert()
                if not cert:
                    return None
                # Enrich with connection-level details ("SSL type"): the
                # negotiated TLS protocol and cipher. Must be read inside the
                # with-block, before the socket closes.
                cert = dict(cert)
                cert["protocol"] = s.version()
                negotiated = s.cipher()
                if negotiated:
                    cert["cipher"] = {
                        "name": negotiated[0],
                        "protocol": negotiated[1],
                        "bits": negotiated[2],
                    }
            return cert
        except Exception:
            logging.exception(
                f"Error performing SSL certificate lookup for hostname: {str(hostname)}"
            )
            return None


class HeaderManager:
    @staticmethod
    def filter_out_unwanted(original_headers: dict, exclude_prefixes: list) -> dict:
        return {
            k: v
            for k, v in original_headers.items()
            if not any(k.lower().startswith(prefix) for prefix in exclude_prefixes)
        }
