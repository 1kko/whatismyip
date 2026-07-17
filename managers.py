"""Data-gathering managers: GeoIP + city overlay, DNS, SSL, and header hygiene.

Each is a thin wrapper over one external source. They depend only on config, so
main.py can import them without an import cycle.
"""

import gzip
import ipaddress
import logging
import os
import socket
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict

import dns.resolver
import dns.reversename
import maxminddb
from geoip2fast import GeoIP2Fast
from tld import exceptions as tld_exceptions
from tld import get_tld

from config import (
    DNS_QUERY_LIFETIME,
    DNS_QUERY_TIMEOUT,
    GEOIP_CITY_DB_FILE,
    GEOIP_CITY_DB_URL,
    GEOIP_DATA_FILE,
    PUBLIC_RESOLVERS,
    TIMEOUT_SECONDS,
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


class GeoIpManager:
    def __init__(self):
        self.instance = self._load_instance()
        self.city_reader = self._open_city_reader()

    @staticmethod
    def _load_instance() -> GeoIP2Fast:
        """Load the volume database, falling back to the bundled one when the
        volume file is missing or corrupt. An interrupted download can leave a
        truncated .dat.gz that GeoIP2Fast raises on; that must degrade the app to
        the built-in country DB, not crash it at startup. update_database()
        refreshes a good copy on the next run."""
        if os.path.exists(GEOIP_DATA_FILE):
            try:
                return GeoIP2Fast(geoip2fast_data_file=GEOIP_DATA_FILE)
            except Exception:
                logging.exception(
                    "GeoIP DB at %s is unreadable; using the bundled database",
                    GEOIP_DATA_FILE,
                )
        return GeoIP2Fast()

    @staticmethod
    def _open_city_reader():
        if os.path.exists(GEOIP_CITY_DB_FILE):
            try:
                return maxminddb.open_database(GEOIP_CITY_DB_FILE)
            except Exception:
                logging.exception("Could not open GeoLite2-City database")
        return None

    def update_database(self):
        tmp = GEOIP_DATA_FILE + ".tmp"
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
            new_instance = GeoIP2Fast(geoip2fast_data_file=tmp)  # validates it loads
            os.replace(tmp, GEOIP_DATA_FILE)
            self.instance = new_instance
            logging.info(f"{update_result=}")
        except Exception as e:
            logging.exception(f"Error updating GeoIP2Fast database: {str(e)}")
            try:
                os.remove(tmp)
            except OSError:
                pass

    def update_city_database(self):
        """Download and unpack the GeoLite2-City mmdb, then hot-swap the reader.
        The mirror tracks MaxMind's twice-weekly release; the URL is env-tunable
        so it can point at a licensed MaxMind download or a local file instead."""
        try:
            os.makedirs(os.path.dirname(GEOIP_CITY_DB_FILE), exist_ok=True)
            # GEOIP_CITY_DB_URL is operator-set config (an https mirror or a
            # local file:// path), not user input, so any scheme is intentional.
            with urllib.request.urlopen(  # noqa: S310
                GEOIP_CITY_DB_URL, timeout=120
            ) as resp:
                data = gzip.decompress(resp.read())
            tmp = GEOIP_CITY_DB_FILE + ".tmp"
            with open(tmp, "wb") as handle:
                handle.write(data)
            os.replace(tmp, GEOIP_CITY_DB_FILE)
            old = self.city_reader
            self.city_reader = maxminddb.open_database(GEOIP_CITY_DB_FILE)
            if old:
                old.close()
            logging.info("GeoLite2-City database updated (%d bytes)", len(data))
        except Exception:
            logging.exception("Error updating GeoLite2-City database")

    def fetch_location(self, ip: str) -> Dict[str, Any]:
        """A single flat location record for the IP: country + ASN from
        geoip2fast, precise city/lat/lon/accuracy/time zone overlaid from
        GeoLite2-City. Callers add reverse_dns; the response assembly adds the
        resolved coordinates, the origin_* fields, and distance_km."""
        raw = self.instance.lookup(ip).to_dict()
        city = raw.get("city") if isinstance(raw.get("city"), dict) else {}
        self._overlay_city(ip, raw.get("is_private"), city)
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
            "asn_name": raw.get("asn_name"),
            "asn_cidr": raw.get("asn_cidr"),
            "is_private": raw.get("is_private"),
            "hostname": raw.get("hostname"),
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


class DomainManager:
    def is_ipv4(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).version == 4
        except ValueError:
            return False

    def is_valid_domain(self, domain) -> bool:
        try:
            get_tld(domain, fix_protocol=True)
            return True
        except tld_exceptions.TldDomainNotFound:
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
