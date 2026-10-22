"""Map the API response onto exactly what the template prints.

Pure functions only: no request, no I/O. The template does no logic beyond
looping over what comes out of build_view().
"""

from __future__ import annotations

import datetime
import ipaddress
import math
from typing import Any, Callable
from urllib.parse import quote

from config import ASINFO_MIN_RIS_PEERS, SUBDOMAIN_ENABLED, YOUNG_DOMAIN_DAYS
from countrynames import country_name
from eppstatus import explain_status
from reputation import grade

# Mirrors rdap.NOT_REGISTERED rather than importing it: `rdap` pulls in whoisit,
# which costs ~400ms of import time -- twelve times this whole module's -- and
# viewmodel is the pure module every template test imports. Same trade as
# subdomain_store.sanitize_log. If the sentinel changes, it changes in both.
NOT_REGISTERED = "not registered"

DASH = "—"
# Under the country in the hero when the fix is a country centroid: GeoLite2's
# (8.8.8.8, ± 1000 km) or the gazetteer's. Said in place of a city, because the
# map draws a pin either way and a pin reads as a place.
APPROXIMATE_LINE = "approximate · country-level"
# The self page's registration while it is still being looked up: main.py
# sends the page before a slow RDAP answer and app.js fills it in from
# /?whois=only. It is neither an answer nor a failure, so it reads as neither.
LOADING = "loading…"
PENDING_VALUE = "…"

# The self page describes whoever opens it, so its <title> and link-preview
# text are fixed. A preview card is built from the <head>, and a shared link to
# `/` must not carry the IP of whoever -- or whichever bot -- fetched it. The
# visitor's address is the <h1> and nowhere in the <head>.
SELF_TITLE = "What is my IP address? — WhatIsMyIP"
SITE_DESCRIPTION = (
    "WHOIS, GeoIP, DNS and TLS certificate details for any IP address or domain. "
    "Also an MCP server, so AI agents can run the same lookups."
)

# What the page says in place of a record count when the query failed. Keyed by
# managers.DNS_FAILURES, mirrored rather than imported for the same reason as
# NOT_REGISTERED: managers loads dnspython and the GeoIP readers. noanswer and
# nxdomain are answers, so they keep the plain dash (nxdomain also raises the
# dns_banner below).
DNS_FAILURE_TEXT = {
    "timeout": "(timed out)",
    "servfail": "(server failure)",
    "error": "(lookup failed)",
}

# The shape of main.lookup_href: a hostname or address -> the path of its own
# lookup, or None when the page must print it as text. main passes it into
# build_view(); the default, None, links nothing, and this module stays free of
# lookup (whose import builds the GeoIP, suffix-list and DNS managers).
LinkFor = Callable[[str], str | None]


def _href(link_for: LinkFor | None, value: Any) -> str | None:
    """link_for(value), or None without a link function or a name to link."""
    if link_for is None or not isinstance(value, str) or not value:
        return None
    return link_for(value)


def _linked(item: dict, link_for: LinkFor | None, value: Any) -> dict:
    """A facts row or a hero tag with an `href` when `value` links, else the
    dict exactly as it was: no href key at all, so a view built without
    link_for -- and every row and tag tests compare whole -- is unchanged."""
    href = _href(link_for, value)
    return {**item, "href": href} if href else item


def country_flag(country_code: str | None) -> str:
    code = (country_code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)


def format_distance(distance_km: float | None) -> str | None:
    if not distance_km:
        return None
    return f"≈ {round(distance_km):,} km from you"


def osm_link(location: dict | None) -> str | None:
    """Deep link to the target's spot on openstreetmap.org."""
    location = location or {}
    lat, lon = location.get("lat"), location.get("lon")
    if lat is None or lon is None:
        return None
    zoom = 11 if location.get("precision") == "city" else 5
    return f"https://www.openstreetmap.org/#map={zoom}/{lat}/{lon}"


def _city_line(location: dict) -> str:
    """The line under the country in the hero.

    The city and region when the fix is city-level. Otherwise what the
    coordinates are worth, since the map draws a pin either way:
    APPROXIMATE_LINE for a country centroid, and "registered in <country> ·
    location unknown" when GeoLite2 had only the country the block is
    registered in (1.1.1.1). Not "anycast": GeoLite2 carries no such trait,
    and this only says what was and was not found. Nothing under an empty
    country or a private address: there is no fix to qualify."""
    if location.get("precision") == "city":
        city = location.get("city_name") or ""
        subdivision = location.get("subdivision_name") or ""
        return " · ".join(part for part in (city, subdivision) if part)
    country = location.get("country_name") or ""
    if not country or location.get("is_private"):
        return ""
    if location.get("country_source") == "registered":
        return f"registered in {country} · location unknown"
    return APPROXIMATE_LINE


def _precise_route(response: dict) -> bool:
    """Whether the distance is worth printing: only between two city-level
    fixes. With a country centroid at either end -- 8.8.8.8 was "≈ 10,462 km
    from you" from Seoul, to the middle of Kansas -- the number is the
    centroid's, not the address's. build_map_payload still draws the arc and
    the JSON keeps distance_km; only the chip goes."""
    location = response.get("location") or {}
    origin = response.get("origin") or {}
    return location.get("precision") == "city" and origin.get("precision") == "city"


def _accuracy_text(location: dict) -> str:
    """The GeoIP card's Accuracy row. A city-level fix is its radius. A
    country-level one says so, with the radius when GeoLite2 gave one
    ("country-level (± 1000 km)" for 8.8.8.8) and without when the
    coordinates are the gazetteer's centroid. A block GeoLite2 could only
    register, not locate, says that in place of a radius it never had."""
    precision = location.get("precision")
    accuracy = location.get("accuracy_km")
    radius = f"± {accuracy} km" if accuracy is not None else ""
    if location.get("country_source") == "registered" and precision != "city":
        return "country-level · registered country only"
    if precision == "country":
        return f"country-level ({radius})" if radius else "country-level"
    return radius or DASH


def format_meta(elapsed_ms: int | None, when: Any) -> str:
    """Footer line: how long the lookup took, and the server's clock."""
    parts = []
    if elapsed_ms:
        parts.append(f"resolved in {elapsed_ms} ms")
    if isinstance(when, datetime.datetime):
        parts.append(f"{when.astimezone(datetime.timezone.utc):%Y-%m-%d %H:%M} UTC")
    return " · ".join(parts)


def _count(items: Any, unit: str = "record") -> str:
    total = len(items or [])
    if not total:
        return DASH
    return f"{total} {unit}{'s' if total != 1 else ''}"


def _is_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def _ip_version(address: str) -> int:
    """4 or 6. An IPv4-mapped address (::ffff:a.b.c.d, what a dual-stack
    socket reports for an IPv4 peer) is the IPv4 address it carries."""
    ip = ipaddress.ip_address(address)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return 4
    return ip.version


def _first(value: Any) -> Any:
    """python-whois returns some fields (dates, especially) as lists."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _age_days(value: Any, now: datetime.datetime | None = None) -> int | None:
    """Whole days from `value` to `now` (the current time by default), in UTC.

    `value` is a canonical date field: a datetime from RDAP or python-whois,
    or a string for the odd WHOIS record that hands one back, read only when
    it is ISO 8601. A naive time is taken as UTC. A time up to a day ahead
    counts as 0: python-whois returns a registry's local time as a naive
    datetime, so a name registered an hour ago east of UTC reads as a few
    hours in the future. Anything else, a time further ahead included, has no
    age: None, never an exception.
    """
    if isinstance(value, str):
        try:
            value = datetime.datetime.fromisoformat(value.strip())
        except ValueError:
            return None
    if not isinstance(value, datetime.datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=datetime.timezone.utc)
    now = now or datetime.datetime.now(tz=datetime.timezone.utc)
    days = (now - value).days
    if days < -1:
        return None
    return max(days, 0)


def _cert_issuer(ssl_data: dict) -> str:
    for rdn in ssl_data.get("issuer", ()):
        for key, value in rdn:
            if key == "organizationName":
                return value
    return DASH


def _cert_expiry(ssl_data: dict) -> tuple[str, int | None]:
    raw = ssl_data.get("notAfter")
    if not raw:
        return DASH, None
    try:
        parsed = datetime.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=datetime.timezone.utc
        )
    except ValueError:
        # getpeercert()'s notAfter is always this exact format in practice, but
        # a malformed value must not raise past every caller's contract —
        # mirrors _format_cert_date below, which guards the same parse.
        return raw, None
    days_left = (parsed - datetime.datetime.now(tz=datetime.timezone.utc)).days
    return parsed.date().isoformat(), days_left


def _cert_subject_cn(ssl_data: dict) -> str:
    for rdn in ssl_data.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return DASH


def _cert_san(ssl_data: dict) -> list[str]:
    return [
        value for kind, value in ssl_data.get("subjectAltName", ()) if kind == "DNS"
    ]


def _subject_field(ssl_data: dict, name: str) -> str | None:
    for rdn in ssl_data.get("subject", ()):
        for key, value in rdn:
            if key == name:
                return value
    return None


def _cert_validation(ssl_data: dict) -> str:
    """The validation level the CA vetted. getpeercert() does not expose the
    certificate-policy OID, so EV is inferred from the businessCategory field EV
    certs carry, OV from an organizationName, and DV when the subject is only a
    common name (the Let's Encrypt / ACME shape)."""
    org = _subject_field(ssl_data, "organizationName")
    if _subject_field(ssl_data, "businessCategory") and org:
        return f"EV · {org}"
    if org:
        return f"OV · {org}"
    return "DV (domain validated)"


def _dns_name_matches(pattern: str, host: str) -> bool:
    """RFC 6125 name match. A wildcard covers exactly one left-most label, so
    *.naver.com matches www.naver.com but neither naver.com nor a.b.naver.com."""
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".naver.com"
        if not host.endswith(suffix):
            return False
        leftmost = host[: -len(suffix)]
        return bool(leftmost) and "." not in leftmost
    return False


def _host_covered(ssl_data: dict, host: str | None) -> bool | None:
    """Whether the served certificate is actually valid for the looked-up host.
    None when there is nothing to check (IP lookups have no hostname)."""
    host = (host or "").strip().lower().rstrip(".")
    if not host or _is_ip(host):
        return None
    names = [name.lower().rstrip(".") for name in _cert_san(ssl_data)]
    if not names:  # pre-2017 certs with no SAN fall back to the common name
        cn = _cert_subject_cn(ssl_data)
        names = [cn.lower().rstrip(".")] if cn and cn != DASH else []
    return any(_dns_name_matches(pattern, host) for pattern in names)


def _parse_cert_date(raw: str | None) -> datetime.datetime | None:
    """getpeercert()'s 'Jun  1 00:00:00 2026 GMT' as an aware UTC datetime;
    None when the field is absent or not in that form."""
    if not raw:
        return None
    try:
        parsed = datetime.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
    return parsed.replace(tzinfo=datetime.timezone.utc)


def _format_cert_date(raw: str | None) -> str:
    if not raw:
        return DASH
    parsed = _parse_cert_date(raw)
    return parsed.date().isoformat() if parsed else raw


def cert_age(ssl_data: dict | None, now: datetime.datetime | None = None) -> int | None:
    """Whole days since the certificate's notBefore, read the way the SSL
    panel's Valid from row reads it; None with no certificate or no readable
    date."""
    if not ssl_data or ssl_data.get("error"):
        return None
    return _age_days(_parse_cert_date(ssl_data.get("notBefore")), now)


# managers.SSLManager's verify_error["reason"], in the words a reader expects.
# Mirrored rather than imported, like NOT_REGISTERED: managers loads dnspython,
# maxminddb and geoip2fast, and this module stays light.
_VERIFY_LABELS = {
    "expired": "expired",
    "not_yet_valid": "not yet valid",
    "self_signed": "self-signed",
    "untrusted_root": "untrusted root",
    "chain_incomplete": "chain incomplete",
    "hostname_mismatch": "hostname mismatch",
}


def _ssl_problem(ssl_data: dict) -> str | None:
    """Why the served certificate fails, in a word or two; None if it doesn't.
    Expiry is read off the certificate, so it shows even when OpenSSL stopped
    at an earlier failure (an expired self-signed cert reports "self-signed")."""
    _, days_left = _cert_expiry(ssl_data)
    if days_left is not None and days_left < 0:
        return "expired"
    if ssl_data.get("trusted") is False:
        reason = (ssl_data.get("verify_error") or {}).get("reason")
        return _VERIFY_LABELS.get(reason, "not trusted")
    return None


def _ssl_status(ssl_data: dict) -> tuple[str, str]:
    problem = _ssl_problem(ssl_data)
    if problem:
        return problem, "danger"
    _, days_left = _cert_expiry(ssl_data)
    if days_left is None:
        return DASH, "muted"
    if days_left < 14:
        return f"valid · {days_left}d left", "warning"
    return f"valid · {days_left}d left", "success"


def ssl_rows(ssl_data: dict | None, address: str | None = None) -> list[dict]:
    """Detailed certificate rows for the SSL accordion. Empty when no handshake
    was attempted (IP lookups, private/reserved targets, no A record)."""
    if not ssl_data:
        return []
    if ssl_data.get("error"):
        # Port 443 never answered, or no TLS session came of it. That is not
        # "no certificate": there was nothing to read one from.
        return [
            {"label": "Status", "value": ssl_data["error"], "tone": "warning"},
            {
                "label": "Reason",
                "value": ssl_data.get("reason") or DASH,
                "tone": "default",
            },
        ]
    status, tone = _ssl_status(ssl_data)
    cipher = ssl_data.get("cipher") or {}
    cipher_text = f"{cipher.get('name')} ({cipher.get('bits')}-bit)" if cipher else DASH
    san = _cert_san(ssl_data)
    rows = [
        {"label": "Status", "value": status, "tone": tone},
    ]
    verify_error = ssl_data.get("verify_error")
    if verify_error:
        rows.append(
            {
                "label": "Verification",
                "value": f"{verify_error.get('message')} "
                f"(code {verify_error.get('code')})",
                "tone": "danger",
            }
        )
    # Does the served cert actually cover the name the visitor looked up? The
    # cert is fetched with SNI = that name, so a mismatch means a misconfigured
    # host (or a shared cert that forgot to list it) — worth flagging loudly.
    # SSLManager's own verdict wins when there is one (None: it never got to
    # read the certificate); the SAN check is for a dict without it.
    if "hostname_match" in ssl_data:
        covered = ssl_data["hostname_match"]
    else:
        covered = _host_covered(ssl_data, address)
    if covered is not None:
        rows.append(
            {
                "label": "Host match",
                "value": f"valid for {address}"
                if covered
                else f"not valid for {address}",
                "tone": "success" if covered else "danger",
            }
        )
    rows += [
        {"label": "Issuer (CA)", "value": _cert_issuer(ssl_data), "tone": "default"},
        {"label": "Subject", "value": _cert_subject_cn(ssl_data), "tone": "default"},
        {
            "label": "Validation",
            "value": _cert_validation(ssl_data),
            "tone": "default",
        },
        {
            "label": "Protocol",
            "value": ssl_data.get("protocol") or DASH,
            "tone": "default",
        },
        {"label": "Cipher", "value": cipher_text, "tone": "default"},
        {
            "label": "Valid from",
            "value": _format_cert_date(ssl_data.get("notBefore")),
            "tone": "default",
        },
        {
            "label": "Valid until",
            "value": _format_cert_date(ssl_data.get("notAfter")),
            "tone": "default",
        },
        {"label": "SAN", "value": ", ".join(san) if san else DASH, "tone": "default"},
        {
            "label": "Serial",
            "value": ssl_data.get("serialNumber") or DASH,
            "tone": "default",
        },
    ]
    return rows


def _asn_org(location: dict) -> str:
    """'AS4766 Korea Telecom' from the GeoLite2-ASN record; just the org name
    when the record carries no AS number."""
    name = location.get("asn_name")
    number = location.get("asn_number")
    if name and number:
        return f"AS{number} {name}"
    return name or DASH


def _org_row(location: dict, link_for: LinkFor | None) -> dict:
    """The Org row. With an AS number its anchor wraps the number alone
    ('AS4766' links, ' Korea Telecom' follows as plain text)."""
    number = location.get("asn_number")
    name = location.get("asn_name")
    row = {"label": "Org", "value": _asn_org(location), "tone": "default"}
    href = _href(link_for, f"AS{number}") if number and name else None
    if not href:
        return row
    return {**row, "value": f"AS{number}", "suffix": f" {name}", "href": href}


def _network_column(
    location: dict, address: str, link_for: LinkFor | None = None
) -> dict:
    rows = [
        {"label": "CIDR", "value": location.get("cidr") or DASH, "tone": "default"},
        {
            "label": "AS block",
            "value": location.get("asn_cidr") or DASH,
            "tone": "default",
        },
        _org_row(location, link_for),
    ]
    if _is_ip(address):
        rows.append(
            {
                "label": "Scope",
                "value": "private" if location.get("is_private") else "public",
                "tone": "warning" if location.get("is_private") else "default",
            }
        )
    else:
        rows.append(
            _linked(
                {
                    "label": "rDNS",
                    "value": location.get("reverse_dns") or DASH,
                    "tone": "default" if location.get("reverse_dns") else "muted",
                },
                link_for,
                location.get("reverse_dns"),
            )
        )
    return {"title": "NETWORK", "rows": rows}


def dns_failure_text(domain: dict | None, key: str) -> str | None:
    """'(timed out)' and the like when the `key` query failed, else None."""
    status = (domain or {}).get("status") or {}
    return DNS_FAILURE_TEXT.get(status.get(key))


def dns_banner(domain: dict | None) -> str | None:
    """'<name> does not resolve (NXDOMAIN)' when the queried name does not
    exist. Every per-type row is then an honest dash, and a page of dashes
    alone reads as a name that exists with nothing published."""
    domain = domain or {}
    if (domain.get("status") or {}).get("a") != "nxdomain":
        return None
    return f"{domain.get('queried_name')} does not resolve (NXDOMAIN)"


def dns_names(domain: dict | None, address: str) -> tuple[str, str]:
    """(queried name, zone) for the DNS table: the name the sweep was of -- an
    IP target's PTR name -- and the zone apex its NS and fallback MX were
    answered by (DomainManager.get_records sets both). A response without them
    (an IP with no PTR gets `{}`; older fixtures carry neither) names the
    address twice, which the template reads as "no zone to mention".
    """
    domain = domain or {}
    queried = domain.get("queried_name") or address
    return queried, domain.get("zone") or queried


def _canonical_ip(text: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """One value per address however it is spelled, as gather() gives every
    target: an IPv4-mapped address (::ffff:a.b.c.d) is the IPv4 address it
    carries. None for anything that is not an address."""
    try:
        ip = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def fcrdns_state(
    reverse_dns: str | None, domain: dict | None, address: str
) -> str | None:
    """Whether the PTR name of `address` resolves back to it: forward-confirmed
    reverse DNS, what a mail server checks. Read off the PTR and the sweep of
    that name a lookup has already made, so it costs no query.

    "confirmed": one of the name's A records (AAAA for an IPv6 address) is the
    address, so one match in a round robin is enough. "unconfirmed": none is,
    or the name has no address of that family, or does not exist. "no_ptr":
    the address has no PTR. "unknown": that A/AAAA query failed, which says
    nothing either way. None when there is nothing to judge: `address` is not
    an IP (a domain's sweep is of the domain, not of a PTR name), or `domain`
    holds no sweep (?fields= on `/` runs none).
    """
    ip = _canonical_ip(address)
    if ip is None:
        return None
    if not reverse_dns:
        return "no_ptr"
    if not domain:
        return None
    key = "aaaa" if ip.version == 6 else "a"
    if dns_failure_text(domain, key):
        return "unknown"
    for record in domain.get(key) or []:
        if isinstance(record, dict) and _canonical_ip(record.get("ip")) == ip:
            return "confirmed"
    return "unconfirmed"


# How the REVERSE DNS column's PTR row words a verdict. "Does not point back"
# and no further: CDNs and shared hosts fail the check legitimately, so the row
# never says spoofed or forged. "unknown" adds nothing, because the A/AAAA row
# under it already reads "(timed out)" or the like.
_FCRDNS_SUFFIX = {
    "confirmed": (" → confirmed", "success"),
    "unconfirmed": (" → does not point back", "warning"),
}


def _ptr_row(
    reverse: str | None, domain: dict, address: str, link_for: LinkFor | None = None
) -> dict:
    # Only the name links (`href`); the verdict stays its own `suffix`, which
    # the template prints after the anchor as plain text.
    if not reverse:
        return {"label": "PTR", "value": DASH, "tone": "muted"}
    verdict = _FCRDNS_SUFFIX.get(fcrdns_state(reverse, domain, address))
    if verdict is None:
        row = {"label": "PTR", "value": reverse, "tone": "default"}
    else:
        suffix, tone = verdict
        row = {"label": "PTR", "value": reverse, "suffix": suffix, "tone": tone}
    return _linked(row, link_for, reverse)


def _dns_count_row(label: str, domain: dict, key: str) -> dict:
    failure = dns_failure_text(domain, key)
    if failure:
        return {"label": label, "value": failure, "tone": "warning"}
    return {"label": label, "value": _count(domain.get(key)), "tone": "default"}


# The tags read from a DMARC record (RFC 7489 §6.3). Any other tag is
# skipped, as a receiver skips one it does not know.
_DMARC_TAGS = ("p", "sp", "pct", "rua")
_DMARC_POLICIES = ("none", "quarantine", "reject")


def _parse_dmarc(text: str) -> dict[str, str]:
    """p=, sp=, pct= and rua= from a DMARC record, read leniently: tag names in
    any case, spaces around "=" and ";", empty or doubled semicolons. Another
    tag is skipped, and so is a p= or sp= that names no policy; of a repeated
    tag the first usable one wins. {} when the text does not open with
    v=DMARC1, the value spelled exactly as managers._is_dmarc_record and
    RFC 7489 §6.3 require: it is some other TXT record. For display only:
    nothing here grades a policy.
    """
    parts = [part.strip() for part in str(text or "").split(";")]
    parts = [part for part in parts if part]
    if not parts:
        return {}
    name, sep, value = parts[0].partition("=")
    if not sep or name.strip().lower() != "v" or value.strip() != "DMARC1":
        return {}
    tags: dict[str, str] = {}
    for part in parts[1:]:
        name, sep, value = part.partition("=")
        name, value = name.strip().lower(), value.strip()
        if not sep or name not in _DMARC_TAGS or name in tags:
            continue
        if name in ("p", "sp"):
            value = value.lower()
            if value not in _DMARC_POLICIES:
                continue
        tags[name] = value
    return tags


def dmarc_policy(domain: dict | None) -> dict | None:
    """The DMARC policy that governs the queried name, from domain["dmarc"]:
    {"tag": "p" | "sp", "policy", "pct", "inherited_from"}.

    None unless exactly one record came back: with none there is no policy,
    and two or more end policy discovery (RFC 7489 §6.6.3), so neither
    applies. A record inherited from the registrable domain governs a
    subdomain by its sp= when it has one, by its p= otherwise (§6.3), and
    "inherited_from" names that domain so the policy is never read as the
    name's own. "policy" is None when the record names none; "pct" only when
    it narrows the policy below 100.
    """
    domain = domain or {}
    records = domain.get("dmarc") or []
    if len(records) != 1:
        return None
    record = records[0]
    tags = _parse_dmarc(record.get("text", ""))
    source = str(record.get("queried_name") or "").removeprefix("_dmarc.")
    inherited = bool(source) and source != domain.get("queried_name")
    tag = "sp" if inherited and "sp" in tags else "p"
    pct = tags.get("pct")
    return {
        "tag": tag,
        "policy": tags.get(tag),
        "pct": pct if pct and pct != "100" else None,
        "inherited_from": source if inherited else None,
    }


def _dmarc_text(domain: dict) -> str | None:
    """The DMARC half of the Mail row: a failure, the policy, or None when
    there is no record."""
    failure = dns_failure_text(domain, "dmarc")
    if failure:
        return failure
    records = domain.get("dmarc") or []
    if not records:
        return None
    policy = dmarc_policy(domain)
    if policy is None:
        return f"{len(records)} records"
    text = f"{policy['tag']}={policy['policy']}" if policy["policy"] else "no p= tag"
    if policy["pct"]:
        text += f" pct={policy['pct']}"
    if policy["inherited_from"]:
        text += f" ({policy['inherited_from']})"
    return text


def _mail_row(domain: dict) -> dict:
    """SPF and DMARC on one line: whether the name has an SPF policy (its own
    or its zone's), and the DMARC policy that governs it, as published. A
    failed query says so and warns, as a count row does; p=none asks for
    reports only, so it is an answer like any other policy, never a warning."""
    spf_failure = dns_failure_text(domain, "spf")
    dmarc_failure = dns_failure_text(domain, "dmarc")
    spf = spf_failure or ("yes" if domain.get("spf") else None)
    dmarc = _dmarc_text(domain)
    if spf is None and dmarc is None:
        return {"label": "Mail", "value": DASH, "tone": "default"}
    return {
        "label": "Mail",
        "value": f"SPF {spf or DASH} · DMARC {dmarc or DASH}",
        "tone": "warning" if spf_failure or dmarc_failure else "default",
    }


def _dns_column(domain: dict) -> dict:
    domain = domain or {}
    return {
        "title": "DNS",
        "rows": [
            _dns_count_row("A", domain, "a"),
            _dns_count_row("AAAA", domain, "aaaa"),
            _dns_count_row("MX", domain, "mx"),
            _dns_count_row("NS", domain, "ns"),
            _dns_count_row("TXT", domain, "txt"),
            _mail_row(domain),
        ],
    }


def _reverse_column(
    location: dict, domain: dict, address: str, link_for: LinkFor | None = None
) -> dict:
    domain = domain or {}
    reverse = location.get("reverse_dns")
    # The PTR name's own addresses of the looked-up address's family: the
    # ones fcrdns_state() compares with the address for the PTR row.
    label, key = ("AAAA", "aaaa") if _ip_version(address) == 6 else ("A", "a")
    ttl = next(iter(domain.get(key) or []), {}).get("ttl")
    return {
        "title": "REVERSE DNS",
        "rows": [
            _ptr_row(reverse, domain, address, link_for),
            _dns_count_row(label, domain, key),
            _dns_count_row("NS", domain, "ns"),
            {
                "label": "TTL",
                "value": f"{ttl}s" if ttl else DASH,
                "tone": "default" if ttl else "muted",
            },
        ],
    }


_WHOIS_COLUMN_ROWS = (
    ("network", "Network"),
    ("rir", "RIR"),
    ("abuse_email", "Abuse"),
    ("updated", "Updated"),
)


def whois_pending(whois_data: dict | None) -> bool:
    """Whether the page went out before its registration lookup answered (see
    _self_lookup in main.py)."""
    return bool(whois_data) and whois_data.get("pending") is True


def _whois_column(whois_data: dict | None) -> dict:
    # Registration data only. This takes no GeoIP `location` on purpose: the
    # column used to fill Netblock and Country from GeoIP, which made a column
    # titled WHOIS disagree with the WHOIS accordion below it. GeoIP values
    # live in the NETWORK column and the GeoIP accordion.
    #
    # The id is how app.js finds the column to fill a pending one.
    if whois_pending(whois_data):
        rows = [{"label": "Status", "value": LOADING, "tone": "muted"}]
        rows += [
            {"label": label, "value": PENDING_VALUE, "tone": "muted"}
            for _, label in _WHOIS_COLUMN_ROWS
        ]
        return {"title": "WHOIS", "id": "whois", "rows": rows}
    whois_data = whois_data or {}
    error = whois_data.get("error")
    # Four states. "not registered" is an answer -- the registry was
    # reached and found no registration for the registrable domain -- while
    # "unavailable" means we could not find out.
    if error == NOT_REGISTERED:
        status, tone = "not registered", "muted"
    elif error or not whois_data:
        status, tone = "unavailable", "warning"
    elif whois_data.get("thin"):
        status, tone = "no details", "muted"
    else:
        # "record found", not "available": this Status is the lookup's, and
        # "available" beside a name reads as "available to register".
        status, tone = "record found", "success"
    # Separate from the status above: this one only asks whether there is a
    # usable record to draw values from, and there isn't in either failing case.
    no_record = bool(error) or not whois_data
    rows = [{"label": "Status", "value": status, "tone": tone}]
    for key, label in _WHOIS_COLUMN_ROWS:
        # Same renderer as the accordion, so a value reads identically in both.
        value = DASH if no_record else _whois_value(key, whois_data.get(key))
        rows.append(
            {
                "label": label,
                "value": value,
                "tone": "muted" if value == DASH else "default",
            }
        )
    return {"title": "WHOIS", "id": "whois", "rows": rows}


def _certificate_column(ssl_data: dict | None) -> dict:
    if not ssl_data or ssl_data.get("error"):
        # No handshake attempted ("none"), or one that failed before any
        # certificate arrived ("port 443 unreachable").
        failure = (ssl_data or {}).get("error")
        return {
            "title": "CERTIFICATE",
            "rows": [
                {
                    "label": "Status",
                    "value": failure or "none",
                    "tone": "warning" if failure else "muted",
                },
                {"label": "Issuer", "value": DASH, "tone": "muted"},
                {"label": "SAN", "value": DASH, "tone": "muted"},
                {"label": "Expires", "value": DASH, "tone": "muted"},
            ],
        }

    expires, _ = _cert_expiry(ssl_data)
    status, tone = _ssl_status(ssl_data)

    san = ssl_data.get("subjectAltName") or ()
    return {
        "title": "CERTIFICATE",
        "rows": [
            {"label": "Status", "value": status, "tone": tone},
            {"label": "Issuer", "value": _cert_issuer(ssl_data), "tone": "default"},
            {"label": "SAN", "value": _count(san, unit="name"), "tone": "default"},
            {"label": "Expires", "value": expires, "tone": "default"},
        ],
    }


# A reputation signal's tag, and the card's level, take the colour of the
# grade it carries on its own: a Spamhaus listing is red, Tor and VPN amber, a
# datacenter (weight 0, informational) plain.
_LEVEL_TONES = {"high": "danger", "medium": "warning", "low": "warning"}

# The level's word on the card. `none` is the band below `low`
# (reputation.LEVELS[0]); printed as "Level None" beside "Listed on 1 of 5
# lists" (an informational datacenter listing) it reads as "no level at all".
# "no signals" says what it is. None, when no list could be read, stays
# "unknown". The JSON and `?fields=risk_level` keep the word `none`.
_LEVEL_TEXT = {"none": "no signals"}


def _level_text(level: str | None) -> str:
    return _LEVEL_TEXT.get(level, level or "unknown")


def _score_text(score: int | None) -> str:
    """'50 of 100', or 'Unknown' when nothing could be checked.

    A missing score must not print as 0: 0 means the lists were read and
    none of them carried weight.
    """
    if score is None:
        return "Unknown"
    return f"{score} of 100"


def _signal_name(signal: dict) -> str:
    """A signal as a tag or hint names it: the list ("Tor exit"), or for
    AbuseIPDB its confidence score as well ("AbuseIPDB 87%")."""
    if signal.get("score") is not None:
        return f"{signal['label']} {signal['score']}%"
    return signal["label"]


def _reputation_tags(response: dict, informational: bool) -> list[dict]:
    """A tag per list the address is on, named for the list ("Tor exit"),
    never for a verdict. An informational signal is left off a domain's hero:
    nearly every website is hosted in a datacenter, so that tag would be on
    every domain page and say nothing there."""
    signals = (response.get("reputation") or {}).get("signals") or []
    return [
        {
            "text": _signal_name(signal),
            "tone": _LEVEL_TONES.get(grade([signal]), "default"),
        }
        for signal in signals
        if informational or signal["weight"] > 0
    ]


def _status_tags(whois_data: dict | None) -> list[dict]:
    """One red tag when a domain's registry status says the name is out of the
    DNS or about to be dropped (clientHold, serverHold, pendingDelete,
    redemptionPeriod): the code itself, which the WHOIS accordion glosses. It
    names the status, not a verdict, and it is no reputation signal:
    reputation.grade() never sees it."""
    whois_data = whois_data or {}
    if "registrar" not in whois_data:
        return []
    codes = [
        entry["code"]
        for entry in explain_status(whois_data.get("status"))
        if entry["severity"] == "danger"
    ]
    return [{"text": " · ".join(codes), "tone": "danger"}] if codes else []


def _young_domain_tag(whois_data: dict | None) -> dict | None:
    """'REGISTERED 6 DAYS AGO', amber, for a domain registered fewer than
    YOUNG_DOMAIN_DAYS ago. A young name is worth a closer look, which is all
    the tag says: it is no verdict, and an old name proves nothing either. A
    certificate's age is never tagged: ACME renews every few weeks, so nearly
    every certificate is young."""
    created, _ = registration_age(whois_data)
    if created is None or created >= YOUNG_DOMAIN_DAYS:
        return None
    return {"text": f"REGISTERED {_ago(created)}".upper(), "tone": "warning"}


def _tags(response: dict, is_ip: bool, link_for: LinkFor | None = None) -> list[dict]:
    location = response.get("location") or {}
    domain = response.get("domain") or {}
    if is_ip:
        return [
            {"text": f"IPv{_ip_version(response['address'])}", "tone": "default"},
            {
                "text": "PRIVATE" if location.get("is_private") else "PUBLIC",
                "tone": "warning" if location.get("is_private") else "default",
            },
            *_reputation_tags(response, informational=True),
        ]

    tags = [{"text": "DOMAIN", "tone": "default"}]
    first_a = next(iter(domain.get("a") or []), None)
    first_aaaa = next(iter(domain.get("aaaa") or []), None)
    # The address tag is the one tag that names a lookup target, so it is the
    # one that links (when link_for allows); no other tag gains an href key.
    if first_a:
        tags.append(
            _linked(
                {"text": f"A → {first_a['ip']}", "tone": "default"},
                link_for,
                first_a["ip"],
            )
        )
    elif first_aaaa:
        # An IPv6-only name: its address, rather than no address at all.
        tags.append(
            _linked(
                {"text": f"AAAA → {first_aaaa['ip']}", "tone": "default"},
                link_for,
                first_aaaa["ip"],
            )
        )
    # "TLS valid" only for a certificate that verified: any certificate at all
    # used to earn it, and a broken one now comes back rather than None.
    ssl_data = response.get("ssl") or {}
    problem = _ssl_problem(ssl_data)
    if problem:
        tags.append({"text": f"TLS {problem}", "tone": "danger"})
    elif ssl_data.get("trusted"):
        tags.append({"text": "TLS valid", "tone": "success"})
    tags += _status_tags(response.get("whois"))
    young = _young_domain_tag(response.get("whois"))
    if young:
        tags.append(young)
    return tags + _reputation_tags(response, informational=False)


def _summary(response: dict, address: str, is_ip: bool) -> str:
    """'nasa.gov · AS2635 Automattic, Inc · United States · TLS valid': the
    one line a link preview shows under the title. A part nobody knows is left
    out rather than shown as a dash, which reads as noise in a chat."""
    location = response.get("location") or {}
    org = _asn_org(location)
    parts = [address, "" if org == DASH else org, location.get("country_name") or ""]
    # Read off the hero's tags, so the preview never says more about the
    # certificate than the page itself does.
    parts += [
        tag["text"] for tag in _tags(response, is_ip) if tag["text"].startswith("TLS")
    ]
    return " · ".join(part for part in parts if part)


# The canonical registration record (see rdap.py) rendered as an ordered set of
# labelled rows. Empty fields are dropped, so an IP result simply omits the
# domain-only rows (registrar, name servers, expiry) and vice versa.
_WHOIS_ROWS = (
    ("source", "Source"),
    ("name", "Name"),
    ("handle", "Handle"),
    ("registrar", "Registrar"),
    ("registrant", "Registrant"),
    ("abuse_email", "Abuse contact"),
    ("status", "Status"),
    ("name_servers", "Name servers"),
    ("created", "Created"),
    ("updated", "Updated"),
    ("expires", "Expires"),
    ("dnssec", "DNSSEC"),
    ("country", "Country"),
    ("network", "Network"),
    ("assignment_type", "Assignment"),
    ("parent_handle", "Parent handle"),
    ("rir", "RIR"),
    ("whois_server", "WHOIS server"),
    ("url", "RDAP URL"),
)


def _year(value: Any) -> str:
    """Four-digit year from a canonical date field (datetime, or a string for
    the odd WHOIS record that hands one back)."""
    if isinstance(value, datetime.datetime):
        return str(value.year)
    return str(value or "")[:4]


def registration_age(
    whois_data: dict | None, now: datetime.datetime | None = None
) -> tuple[int | None, int | None]:
    """(days since `created`, days since `updated`) of a canonical
    registration record. None for a date the record lacks or that cannot be
    read, and both None when there is no record: a failed lookup, "not
    registered", or a self page's registration still loading."""
    if not whois_data or whois_data.get("error"):
        return None, None
    return (
        _age_days(whois_data.get("created"), now),
        _age_days(whois_data.get("updated"), now),
    )


def _days(count: int) -> str:
    """'1 day', '6 days', '10,599 days'."""
    return f"{count:,} day{'' if count == 1 else 's'}"


def _ago(count: int) -> str:
    """'today', '1 day ago', '6 days ago'."""
    return "today" if count == 0 else f"{_days(count)} ago"


def _age_row(whois_data: dict) -> str | None:
    """The WHOIS panel's Age row, '6 days (updated 2 days ago)', for a
    domain's record with a readable created date; None otherwise.

    The update's age rides along because a name that changed hands, at an
    expiry auction or by transfer, keeps its old created date, and often only
    the update shows the change. An address block's record gets no row, so an
    IP lookup and the self page read as they did. A domain's record is told by
    its `registrar` key, the test the Status row makes (_status_text): both
    domain shapes set it, None included, and rdap._normalize_rdap_ip never
    does.
    """
    if "registrar" not in whois_data:
        return None
    created, updated = registration_age(whois_data)
    if created is None:
        return None
    if updated is None:
        return _days(created)
    return f"{_days(created)} (updated {_ago(updated)})"


def _whois_value(key: str, value: Any) -> str:
    """Render one canonical field. RDAP and WHOIS both feed this, so it copes
    with datetimes, lists, and the odd bool without leaking Python reprs."""
    if value is None or value == "":
        return DASH
    if key in ("source", "rir"):
        # whoisit names the RIR in lower case ("arin"); it is an acronym.
        return str(value).upper()
    if key == "dnssec":
        if isinstance(value, bool):
            return "signed" if value else "unsigned"
        return str(value)
    if isinstance(value, datetime.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(datetime.timezone.utc)
        return value.strftime("%Y-%m-%d %H:%M UTC")
    if isinstance(value, (list, tuple, set)):
        seen, parts = set(), []
        for item in value:
            text = _whois_value(key, item)
            if text and text != DASH and text not in seen:
                seen.add(text)
                parts.append(text)
        return ", ".join(parts) if parts else DASH
    return str(value)


def _status_text(record: dict) -> str:
    """The Status row. For a domain, each registry status as its EPP code with
    its meaning -- "clientTransferProhibited — transfer lock set by the
    registrar (a common setting)" -- whichever of the three spellings the
    source used, and a code outside RFC 8056 (DENIC's "connect") as the bare
    word. An IP allocation's statuses are RDAP's words for a network
    ("active"), not EPP codes, so they are rendered as they are. Entries are
    separated with ";" because the meanings themselves read as prose."""
    if "registrar" not in record:
        # rdap._normalize_rdap_ip sets no registrar key; both domain shapes do.
        return _whois_value("status", record.get("status"))
    parts = [
        f"{entry['code']} — {entry['meaning']}" if entry["meaning"] else entry["code"]
        for entry in explain_status(record.get("status"))
    ]
    return "; ".join(parts) if parts else DASH


def _covering_registration(whois_data: dict) -> str | None:
    """Return the registrable domain when its record covers another name."""
    registrable = whois_data.get("registrable_domain")
    if registrable and registrable != whois_data.get("queried_name"):
        return registrable
    return None


def whois_display(whois_data: dict | None) -> dict:
    """Turn a canonical registration record into ordered, labelled strings for
    the WHOIS accordion. Returns an error row on failure and {} when absent."""
    if not whois_data:
        return {}
    error = whois_data.get("error")
    if error == NOT_REGISTERED:
        # Labelling this "Error" would send a reader off to retry a lookup that
        # already succeeded. Subdomains land here on every visit.
        return {"Status": "no registration record for this name"}
    if error:
        return {"Error": str(error)}
    out: dict[str, str] = {}
    covering = _covering_registration(whois_data)
    if covering:
        out["Registration of"] = covering
    for key, label in _WHOIS_ROWS:
        if key == "status":
            text = _status_text(whois_data)
        else:
            text = _whois_value(key, whois_data.get(key))
        if text and text != DASH:
            out[label] = text
        if key == "updated":
            age = _age_row(whois_data)
            if age:
                out["Age"] = age
    return out


def resolved_via(domain: dict | None) -> str | None:
    """The canonical name a domain target's address was found under, when it
    is not the queried name: the last hop of the CNAME chain the resolver
    followed for the A answer. None without a chain, and None when the sweep
    did not answer (canonical_name null): the chain is then unknown, not
    absent, and status.a says why."""
    domain = domain or {}
    canonical = domain.get("canonical_name")
    if not canonical or canonical == domain.get("queried_name"):
        return None
    return str(canonical)


def name_server_links(
    whois_data: dict | None, link_for: LinkFor | None = None
) -> list[dict]:
    """The registration record's name servers, one {text, href} each, for the
    template to draw the "Name servers" row as links: whois_display() joins
    them into one string, which cannot carry a link per name. Same names,
    order and deduplication as that string, so the row reads the same with or
    without links. [] for a record with no list (an IP's), or one in error."""
    if not whois_data or whois_data.get("error"):
        return []
    servers = whois_data.get("name_servers")
    if not isinstance(servers, (list, tuple, set)):
        return []
    seen: set[str] = set()
    out = []
    for item in servers:
        text = _whois_value("name_servers", item)
        if not text or text == DASH or text in seen:
            continue
        seen.add(text)
        out.append({"text": text, "href": _href(link_for, text)})
    return out


def geoip_rows(location: dict | None, domain: dict | None = None) -> list[dict]:
    """Detailed geolocation for the GeoIP accordion: country, region, city,
    coordinates, accuracy radius, time zone and network from GeoLite2-City, and
    the AS org from GeoLite2-ASN. Until GeoLite2-City loads, the bundled
    geoip2fast snapshot fills in the country and network alone.

    `domain` is a domain target's record sweep; an IP target passes none, its
    location being its own. When the sweep's A answer went through a CNAME
    chain, a last row names the canonical name the address belongs to, so the
    location and ASN above it are not read as the queried name's own. Only
    that the names differ is known, so the row does not call it a CDN."""
    location = location or {}
    code = (location.get("country_code") or "").strip()
    name = location.get("country_name") or ""
    country = f"{country_flag(code)} {name} ({code})".strip() if name else DASH

    subdivision = location.get("subdivision_name") or ""
    sub_code = location.get("subdivision_code") or ""
    region = (
        f"{subdivision} ({sub_code})"
        if subdivision and sub_code
        else (subdivision or DASH)
    )

    lat, lon = location.get("lat"), location.get("lon")
    coords = f"{lat}, {lon}" if lat is not None and lon is not None else DASH
    accuracy_text = _accuracy_text(location)

    rows = [
        {"label": "Country", "value": country, "tone": "default"},
        {"label": "Region", "value": region, "tone": "default"},
        {
            "label": "City",
            "value": location.get("city_name") or DASH,
            "tone": "default",
        },
        {"label": "Coordinates", "value": coords, "tone": "default"},
        {"label": "Accuracy", "value": accuracy_text, "tone": "default"},
        {
            "label": "Time zone",
            "value": location.get("time_zone") or DASH,
            "tone": "default",
        },
        {
            "label": "ASN org",
            "value": _asn_org(location),
            "tone": "default",
        },
        {
            "label": "Network",
            "value": location.get("cidr") or location.get("asn_cidr") or DASH,
            "tone": "default",
        },
    ]
    via = resolved_via(domain)
    if via:
        rows.append(
            {
                "label": "Resolves via",
                "value": f"{via} — the location and ASN above are its",
                "tone": "default",
            }
        )
    return rows


def _whois_hint(whois_data: dict | None) -> str:
    whois_data = whois_data or {}
    if whois_pending(whois_data):
        return LOADING
    whois_error = whois_data.get("error")
    if whois_error == NOT_REGISTERED:
        return "not registered"
    if whois_error or not whois_data:
        return "lookup failed"
    who = whois_data.get("registrar") or whois_data.get("registrant") or "registry data"
    if whois_data.get("thin"):
        who = "no details over WHOIS"
    created = _year(whois_data.get("created"))
    expires = _year(whois_data.get("expires"))
    span = f" · {created} → {expires}" if created and expires else ""
    hint = f"{who}{span}"
    covering = _covering_registration(whois_data)
    return f"registration of {covering} · {hint}" if covering else hint


def whois_fill(whois_data: dict | None) -> dict:
    """What a self page sent with its registration still loading needs in
    order to show it: the WHOIS accordion's hint, the WHOIS column's rows and
    the accordion's rows, worded exactly as a page that waited has them.
    /?whois=only carries this beside the record, so app.js only writes text
    into the page and never words a registration itself."""
    return {
        "hint": _whois_hint(whois_data),
        "column": _whois_column(whois_data)["rows"],
        "rows": [
            {"label": label, "value": value}
            for label, value in whois_display(whois_data).items()
        ],
    }


def _as_of(value: str | None) -> str:
    """'2026-10-09T06:13:20Z' -> '2026-10-09 06:13 UTC'."""
    return f"{value[:16].replace('T', ' ')} UTC" if value else DASH


def _plural(count: int, unit: str) -> str:
    return f"{count} {unit}{'' if count == 1 else 's'}"


def _abuse_text(entry: dict) -> str:
    """AbuseIPDB's answer as a card row: its confidence score, then the
    reports behind it. The reports themselves are on AbuseIPDB's page for the
    address, which the row links to."""
    text = f"Abuse confidence {entry['score']}%"
    reports, window = entry.get("reports"), entry.get("window_days")
    period = f" in the last {window} days" if window else ""
    if reports == 0:
        text += f": no reports{period}"
    elif reports:
        text += f": {_plural(reports, 'report')}"
        if entry.get("reporters"):
            text += f" from {_plural(entry['reporters'], 'user')}"
        text += period
        if entry.get("last_reported_at"):
            text += f", the latest {_as_of(entry['last_reported_at'])}"
    return f"{text} (as of {_as_of(entry['as_of'])})"


def _lists_checked(count: int) -> str:
    return f"{count} list{'' if count == 1 else 's'} checked"


def reputation_view(reputation: dict | None) -> dict | None:
    """The Reputation card. Evidence before the grade: each list the address
    is on, each list it is not on, and each list that could not be checked,
    with its source and when the copy was taken. Worded as what a list says
    ("Listed on Tor exit"), never as a verdict on the address, and "on none of
    them" says how many were read rather than reading as "safe"."""
    if not reputation:
        return None
    level = reputation.get("level")
    signals = reputation.get("signals") or []
    checked = reputation.get("checked") or []
    unavailable = reputation.get("unavailable") or []
    listed = {signal["id"] for signal in signals}

    if level is None:
        summary = "No list could be checked, so there is no level: unknown."
    elif signals:
        summary = f"Listed on {len(signals)} of the {_lists_checked(len(checked))}."
    else:
        summary = f"Not on any of the {_lists_checked(len(checked))}."
    if unavailable:
        summary += f" {len(unavailable)} could not be checked."

    tone = _LEVEL_TONES.get(level, "default" if level else "muted")
    score = reputation.get("score")
    rows = [
        {
            "label": "Level",
            "value": _level_text(level).capitalize(),
            "tone": tone,
        },
        {
            "label": "Score",
            "value": _score_text(score if isinstance(score, int) else None),
            "tone": tone,
        },
    ]
    for signal in signals:
        effect = "" if signal["weight"] else " · informational, no effect on the level"
        if signal.get("score") is not None:
            value = _abuse_text(signal)
        else:
            value = f"Listed on {signal['label']} (as of {_as_of(signal['as_of'])})"
        rows.append(
            {
                "label": signal["source"],
                "value": value + effect,
                "tone": _LEVEL_TONES.get(grade([signal]), "default"),
                "href": signal.get("url"),
            }
        )
    for entry in checked:
        if entry["id"] not in listed:
            if entry.get("score") is not None:
                value = _abuse_text(entry)
            else:
                as_of = _as_of(entry["as_of"])
                value = f"Not listed on {entry['label']} (as of {as_of})"
            rows.append(
                {
                    "label": entry["source"],
                    "value": value,
                    "tone": "muted",
                    "href": entry.get("url"),
                }
            )
    for entry in unavailable:
        rows.append(
            {
                "label": entry["source"],
                "value": f"Could not check {entry['label']}: {entry['reason']}",
                "tone": "warning",
            }
        )

    if level is None:
        hint = "could not check"
    elif signals:
        names = ", ".join(_signal_name(signal) for signal in signals)
        hint = (
            f"{level} · {names}"
            if not isinstance(score, int)
            else f"{score} · {level} · {names}"
        )
    else:
        quiet = f"not on {_lists_checked(len(checked))}"
        hint = quiet if not isinstance(score, int) else f"{score} · {quiet}"
    return {
        "hint": hint,
        "summary": summary,
        "rows": rows,
        "note": (
            "A list records what its maintainer has seen of an address or its "
            "network, not what the address will do; being on none of them is "
            "no guarantee either. The score runs from 0 to 100, and 100 is the "
            "most dangerous. Unknown means no list could be checked."
        ),
        "attribution": reputation.get("attribution") or [],
    }


# asinfo.default_datasets' ids and labels, repeated so this module imports
# nothing of asinfo (a None section whose dataset loaded is "Not in <label>");
# tests/test_as_surfaces.py keeps the two equal.
_AS_DATASET_LABELS = {
    "asnames": "RIPE NCC AS names",
    "nro": "NRO delegated statistics",
    "ris_v4": "RIPE RIS routes (IPv4)",
    "ris_v6": "RIPE RIS routes (IPv6)",
    "rpki": "rpki-client VRPs",
    "caida_rel": "CAIDA AS relationships",
    "caida_org": "CAIDA AS organizations",
}
# A route's (and an announced prefix's) state is spelled "not-found"; the AS's
# counts are keyed "not_found".
_RPKI_STATES = {
    "valid": "Valid",
    "invalid": "Invalid",
    "not-found": "Not found",
    "not_found": "Not found",
}
_RPKI_TONES = {"valid": "success", "invalid": "warning"}
# How many neighbours of an AS (and siblings of its organization) the panel
# names; the rest are counted. The JSON carries the whole capped list.
AS_LIST_SHOWN = 10
# The rows of the AS page's details panel, out of the AS card.
_AS_DETAILS = ("Registry", "Organization", "ASN-DROP")


def _part(text: str, href: str | None = None) -> dict:
    return {"text": text, "href": href} if href else {"text": text}


def _as_part(asn: Any, link_for: LinkFor | None) -> dict:
    return _part(f"AS{asn}", _href(link_for, f"AS{asn}"))


def _as_row(label: str, parts: list[dict], tone: str = "default", href=None) -> dict:
    """A row of the AS panel. `value` is the plain text; `parts` is what the
    template draws, an anchor around each AS number that links and nothing
    around the rest."""
    row = {
        "label": label,
        "value": "".join(part["text"] for part in parts),
        "tone": tone,
        "parts": parts,
    }
    if href:
        row["href"] = href
    return row


def _as_absent(as_info: dict, dataset_ids: tuple[str, ...]) -> str:
    """Why a section is None: 'Unknown: <reason>' when a dataset it reads could
    not be used, 'Not in <dataset>' when the data loaded and lacks this AS."""
    unavailable = {
        entry.get("dataset"): entry for entry in as_info.get("unavailable") or []
    }
    for dataset_id in dataset_ids:
        if dataset_id in unavailable:
            return f"Unknown: {unavailable[dataset_id].get('reason')}"
    return f"Not in {_AS_DATASET_LABELS[dataset_ids[0]]}"


def _as_neighbours(
    entries: list[dict], total: int, one: str, many: str, link_for: LinkFor | None
) -> tuple[list[dict], dict]:
    """'565 customers: AS1 NAME; AS2 NAME; and 555 more' as parts, and the
    structured list the view also carries."""
    shown = entries[:AS_LIST_SHOWN]
    word = one if total == 1 else many
    if not total:
        return [_part(f"No {many}")], {"total": 0, "shown": [], "more": 0}
    parts = [_part(f"{total} {word}")]
    for position, entry in enumerate(shown):
        parts.append(_part(": " if position == 0 else "; "))
        parts.append(_as_part(entry.get("asn"), link_for))
        if entry.get("name"):
            parts.append(_part(f" {entry['name']}"))
    more = total - len(shown)
    if more > 0:
        parts.append(_part(f"; and {more} more"))
    items = [
        {
            "asn": entry.get("asn"),
            "name": entry.get("name"),
            "href": _href(link_for, f"AS{entry.get('asn')}"),
        }
        for entry in shown
    ]
    return parts, {"total": total, "shown": items, "more": max(more, 0)}


def _as_route_rows(as_info: dict, link_for: LinkFor | None) -> list[dict]:
    route = as_info.get("route")
    if not route:
        if as_info.get("announced") is False:
            return [
                _as_row("Route", [_part("Not announced in RIS")], "muted"),
                _as_row("RPKI", [_part("No route to validate")], "muted"),
            ]
        reason = _as_absent(as_info, ("ris_v4", "ris_v6"))
        return [
            _as_row("Route", [_part(reason)], "muted"),
            _as_row("RPKI", [_part(reason)], "muted"),
        ]
    origins = route.get("origins") or []
    parts = [_part(f"{route.get('prefix')} · originated by ")]
    for position, origin in enumerate(origins):
        if position:
            parts.append(_part(", "))
        parts.append(_as_part(origin.get("asn"), link_for))
        peers = origin.get("ris_peers")
        if isinstance(peers, int):
            parts.append(_part(f" ({peers} RIS peer{'' if peers == 1 else 's'})"))
    states = []
    tone = "default"
    for origin in origins:
        rpki = origin.get("rpki") or {}
        state = rpki.get("state")
        text = _RPKI_STATES.get(state, "Unknown")
        if state == "invalid" and rpki.get("reason"):
            text += f": {rpki['reason']}"
        states.append(text if len(origins) == 1 else f"AS{origin.get('asn')} {text}")
        if state == "invalid":
            tone = "warning"
        elif state == "valid" and tone == "default":
            tone = "success"
    return [
        _as_row("Route", parts),
        _as_row("RPKI", [_part("; ".join(states) or "Unknown")], tone),
    ]


def _as_counts(as_info: dict) -> list[str]:
    """'3 prefixes', 'RPKI 67% valid': the AS's own counts, as its hint and its
    page's link preview print them."""
    pieces = []
    prefixes = as_info.get("prefixes")
    if prefixes:
        count = (prefixes.get("v4") or 0) + (prefixes.get("v6") or 0)
        pieces.append(f"{count} prefix{'' if count == 1 else 'es'}")
    rpki = as_info.get("rpki")
    if rpki:
        total = sum(rpki.get(key) or 0 for key in ("valid", "invalid", "not_found"))
        if total:
            pieces.append(
                f"RPKI {round(100 * (rpki.get('valid') or 0) / total)}% valid"
            )
    return pieces


def _as_hint(as_info: dict) -> str:
    asn = as_info.get("asn")
    special = as_info.get("special")
    if asn is None:
        return "not announced" if as_info.get("announced") is False else "unknown"
    if special:
        return f"AS{asn} · {str(special.get('label', '')).lower()}"
    return " · ".join([f"AS{asn}", *_as_counts(as_info)])


def as_view(
    as_info: dict | None,
    link_for: LinkFor | None = None,
    route: bool = True,
    credit_links: dict[str, str] | None = None,
) -> dict | None:
    """The AS panel: the route an address is announced on, its RPKI state, and
    the AS behind it (holder, registry, organization, prefixes, neighbours,
    ASN-DROP). Pure, over `lookup.address_as_info` / `as_info_for_asn`'s dict.

    Returns {hint, rows, lists, attribution}. A section that is None reads
    'Unknown: <reason>' (muted) when its dataset could not be used and
    'Not in <dataset>' when it could. A special-purpose number (`special`)
    keeps Route and RPKI, names itself and says what it is for; the sections
    it leaves out are not gaps, so no Unknown row is drawn for them.

    An address with no AS (`asn` None: no route covers it and GeoLite2 has
    no number) stops after the AS row; every row below it would describe an
    AS there is none of.

    `route` False leaves out the Route and RPKI rows, which describe an
    address: the /AS<n> page lists the AS's prefixes instead.

    `attribution` is the answer's credit lines as {text, href?}: `href` is
    the dataset page `credit_links` (main passes
    asinfo_manager.credit_links) gives the line, CAIDA's citations."""
    if not as_info:
        return None
    asn = as_info.get("asn")
    special = as_info.get("special")
    links = credit_links or {}
    attribution = [
        _part(str(line), links.get(line)) for line in as_info.get("attribution") or []
    ]
    as_href = _href(link_for, f"AS{asn}") if asn is not None else None
    rows = _as_route_rows(as_info, link_for) if route else []
    lists: dict = {}

    if special:
        rows.append(
            _as_row(
                "AS",
                [_as_part(asn, link_for), _part(f" · {special.get('label')}")],
                href=as_href,
            )
        )
        rows.append(
            _as_row(
                "Purpose",
                [_part(f"{special.get('purpose')} ({special.get('defined_in')})")],
            )
        )
        return {
            "hint": _as_hint(as_info),
            "rows": rows,
            "lists": lists,
            "attribution": attribution,
        }

    if asn is None:
        rows.append(_as_row("AS", [_part("No AS number found")], "muted"))
        return {
            "hint": _as_hint(as_info),
            "rows": rows,
            "lists": lists,
            "attribution": attribution,
        }
    parts = [_as_part(asn, link_for)]
    if as_info.get("source") == "geolite2":
        # The route data had no route for the address, or could not be read:
        # the AS row says which, as the Route row does.
        why = (
            "not announced in RIS"
            if as_info.get("announced") is False
            else "route data unavailable"
        )
        parts.append(_part(f" · from GeoLite2, {why}"))
    rows.append(_as_row("AS", parts, href=as_href))

    name = as_info.get("name")
    if name:
        holder = f"{name} · {as_info['country']}" if as_info.get("country") else name
        rows.append(_as_row("Holder", [_part(holder)]))
    else:
        rows.append(
            _as_row("Holder", [_part(_as_absent(as_info, ("asnames",)))], "muted")
        )

    registry = as_info.get("registry")
    if registry:
        assigned = " ".join(
            str(word)
            for word in (registry.get("status"), registry.get("assigned"))
            if word
        )
        text = " · ".join(
            word
            for word in (
                str(registry.get("rir") or "").upper(),
                registry.get("country"),
                assigned,
            )
            if word
        )
        rows.append(_as_row("Registry", [_part(text)]))
    else:
        rows.append(
            _as_row("Registry", [_part(_as_absent(as_info, ("nro",)))], "muted")
        )

    org = as_info.get("org")
    if org:
        siblings = org.get("siblings") or []
        count = org.get("sibling_count")
        count = count if isinstance(count, int) else len(siblings)
        parts = [_part(org.get("name") or org.get("id") or "Unnamed organization")]
        if count:
            parts.append(_part(f" · {count} sibling AS{'' if count == 1 else 'es'}"))
            shown = siblings[:AS_LIST_SHOWN]
            for position, sibling in enumerate(shown):
                parts.append(_part(": " if position == 0 else "; "))
                parts.append(_as_part(sibling, link_for))
            if count > len(shown):
                parts.append(_part(f"; and {count - len(shown)} more"))
            lists["siblings"] = {
                "total": count,
                "shown": [{"asn": s, "href": _href(link_for, f"AS{s}")} for s in shown],
                "more": max(count - len(shown), 0),
            }
        else:
            parts.append(_part(" · no sibling ASes"))
        rows.append(_as_row("Organization", parts))
    else:
        rows.append(
            _as_row(
                "Organization", [_part(_as_absent(as_info, ("caida_org",)))], "muted"
            )
        )

    prefixes = as_info.get("prefixes")
    if prefixes:
        text = f"IPv4 {prefixes.get('v4') or 0} · IPv6 {prefixes.get('v6') or 0}"
        rows.append(_as_row("Prefixes", [_part(text)]))
    else:
        rows.append(
            _as_row(
                "Prefixes", [_part(_as_absent(as_info, ("ris_v4", "ris_v6")))], "muted"
            )
        )

    rpki = as_info.get("rpki")
    total = sum((rpki or {}).get(key) or 0 for key in ("valid", "invalid", "not_found"))
    if rpki and total:
        text = (
            f"{round(100 * (rpki.get('valid') or 0) / total)}% valid · "
            f"{rpki.get('valid') or 0} valid · {rpki.get('invalid') or 0} invalid · "
            f"{rpki.get('not_found') or 0} not found"
        )
        rows.append(
            _as_row(
                "RPKI coverage",
                [_part(text)],
                "warning" if rpki.get("invalid") else "default",
            )
        )
    elif rpki:
        rows.append(
            _as_row("RPKI coverage", [_part("No prefixes to validate")], "muted")
        )
    else:
        rows.append(
            _as_row(
                "RPKI coverage",
                [_part(_as_absent(as_info, ("rpki", "ris_v4", "ris_v6")))],
                "muted",
            )
        )

    upstreams = as_info.get("upstreams")
    if upstreams is not None:
        parts, lists["upstreams"] = _as_neighbours(
            upstreams, len(upstreams), "provider", "providers", link_for
        )
        rows.append(_as_row("Upstreams", parts))
    else:
        rows.append(
            _as_row("Upstreams", [_part(_as_absent(as_info, ("caida_rel",)))], "muted")
        )
    for key, label, one, many in (
        ("downstreams", "Downstreams", "customer", "customers"),
        ("peers", "Peers", "peer", "peers"),
    ):
        section = as_info.get(key)
        if section is not None:
            parts, lists[key] = _as_neighbours(
                section.get("list") or [],
                section.get("count") or 0,
                one,
                many,
                link_for,
            )
            rows.append(_as_row(label, parts))
        else:
            rows.append(
                _as_row(label, [_part(_as_absent(as_info, ("caida_rel",)))], "muted")
            )

    listed = as_info.get("asn_drop")
    if listed is True:
        rows.append(
            _as_row("ASN-DROP", [_part("Listed on Spamhaus ASN-DROP")], "danger")
        )
    elif listed is False:
        rows.append(_as_row("ASN-DROP", [_part("Not listed")]))
    else:
        rows.append(_as_row("ASN-DROP", [_part("Unknown")], "muted"))

    return {
        "hint": _as_hint(as_info),
        "rows": rows,
        "lists": lists,
        "attribution": attribution,
    }


def _as_special_rows(special: dict) -> list[dict]:
    """Use, Range, Defined in and Purpose: what a special-purpose number is."""
    first, last = special.get("first"), special.get("last")
    span = f"AS{first}" if first == last else f"AS{first} – AS{last}"
    return [
        _as_row("Use", [_part(str(special.get("label")))]),
        _as_row("Range", [_part(span)]),
        _as_row("Defined in", [_part(str(special.get("defined_in")))]),
        _as_row("Purpose", [_part(str(special.get("purpose")))]),
    ]


def as_page_view(
    as_info: dict,
    link_for: LinkFor | None = None,
    credit_links: dict[str, str] | None = None,
    page: dict | None = None,
    as_map: dict | None = None,
) -> dict:
    """The /AS<n> page (templates/as.html) over its answer: as_info_for_asn's
    card with `address` and `elapsed_ms`. Pure, like build_view;
    `credit_links` as for as_view.

    The hero is the number, its holder and its tags. Then, for an assignable
    number: the sentence, the four tiles, the upstream graph ending on the
    address map, the composition bars, one neighbours table and one prefixes
    table (their first rows; every loaded row in `lists_payload` for the
    page's script), the details rows and credits out of as_view's card, and
    Raw JSON. A special-purpose number is its Use, Range, Defined in and
    Purpose in one card (`card`, `accordions`), and nothing else: no dataset
    was read for it. The page's own number does not link to the page it is
    on.

    `page` is AsInfoManager.page_data's dict and `as_map` the map's inputs
    (see as_map_view); both may be None."""
    asn = as_info.get("asn")
    target = f"AS{asn}"
    special = as_info.get("special")

    def link(value: str) -> str | None:
        return None if link_for is None or value == target else link_for(value)

    if special:
        label = special.get("label")
        tags = [{"text": label, "tone": "default"}]
        title = f"{target} · {label}"
        description = " · ".join(
            str(part) for part in (target, label, special.get("purpose")) if part
        )
        card = {
            "hint": _as_hint(as_info),
            "rows": _as_special_rows(special),
            "attribution": [],
        }
        extra: dict = {
            "node": None,
            "card": card,
            "accordions": [
                {"id": "as", "title": "AS", "hint": card["hint"]},
                {"id": "raw", "title": "Raw JSON", "hint": "full response"},
            ],
            "summary": None,
            "tiles": [],
            "graph": None,
            "map": None,
            "glance": None,
            "neighbours": None,
            "prefix_table": None,
            "details": None,
            "lists_payload": None,
        }
    else:
        name = as_info.get("name")
        registry = as_info.get("registry") or {}
        tags = [{"text": "ASN", "tone": "default"}]
        if registry.get("rir"):
            tags.append({"text": str(registry["rir"]).upper(), "tone": "default"})
        year = str(registry.get("assigned") or "")[:4]
        if year.isdigit():
            tags.append({"text": f"since {year}", "tone": "default"})
        if as_info.get("announced") is False:
            tags.append({"text": "NOT ANNOUNCED", "tone": "default"})
        if as_info.get("asn_drop") is True:
            tags.append({"text": "ASN-DROP", "tone": "danger"})
        title = f"{target} · {name}" if name else target
        description = " · ".join(
            part
            for part in (target, name, as_info.get("country"), *_as_counts(as_info))
            if part
        )
        card = as_view(as_info, link, route=False, credit_links=credit_links)
        neighbours = as_neighbour_table(as_info, page, link)
        prefix_table = as_prefix_table(as_info, page)
        extra = {
            # The graph's end when there is no map to carry it (as_map_view's
            # node otherwise): the number and its handle.
            "node": {"label": target, "sub": as_handle(name)},
            "summary": as_summary(as_info, page),
            "tiles": as_tiles(as_info, page),
            "graph": as_upstream_graph(as_info, page, link),
            "map": as_map_view(as_info, as_map),
            "glance": as_glance(as_info, page),
            "neighbours": neighbours,
            "prefix_table": prefix_table,
            "details": {
                "rows": [row for row in card["rows"] if row["label"] in _AS_DETAILS],
                "attribution": card["attribution"],
            },
            "lists_payload": {
                "own": asn,
                "neighbours": neighbours["payload"],
                "prefixes": prefix_table["payload"],
            },
        }

    return {
        "target": target,
        "title": f"{title} — WhatIsMyIP",
        "description": description,
        # The spelling every link to it uses (main.lookup_href): AS4766.
        "canonical_path": target,
        "tags": tags,
        "holder": None if special else as_info.get("name"),
        "flag": country_flag(as_info.get("country")),
        "meta_line": format_meta(as_info.get("elapsed_ms"), None),
        "special": bool(special),
        **extra,
    }


# dnssecurity.LABELS and its state words, repeated so this module keeps its
# imports to config and the pure helpers.
_SECURITY_LABELS = {
    "spf": "SPF",
    "dmarc": "DMARC",
    "dkim": "DKIM",
    "caa": "CAA",
    "dnssec": "DNSSEC",
    "mta_sts": "MTA-STS",
    "tls_rpt": "TLS-RPT",
    "bimi": "BIMI",
}
_SECURITY_TONES = {
    "pass": "success",
    "warn": "warning",
    "fail": "danger",
    "info": "muted",
    "unknown": "muted",
}
_SECURITY_STATES = ("pass", "warn", "fail", "info", "unknown")


def dns_security_view(data: dict | None) -> dict | None:
    """The DNS security accordion: one row per check, with its state, summary
    and findings, and the counts for the hint. None when nothing was graded
    (an IP, the self page, a name that does not exist)."""
    if not data:
        return None
    rows = []
    for check, result in data.items():
        state = result.get("state", "unknown")
        rows.append(
            {
                "label": _SECURITY_LABELS.get(check, check),
                "state": state,
                "tone": _SECURITY_TONES.get(state, "muted"),
                "summary": result.get("summary", ""),
                "findings": [
                    {
                        "text": f.get("text", ""),
                        "tone": _SECURITY_TONES.get(f.get("severity"), "muted"),
                    }
                    for f in result.get("findings") or []
                ],
            }
        )
    counts = [(s, sum(r["state"] == s for r in rows)) for s in _SECURITY_STATES]
    hint = " · ".join(f"{n} {s}" for s, n in counts if n)
    return {"hint": hint, "rows": rows}


def _accordions(response: dict, subdomains_enabled: bool) -> list[dict]:
    domain = response.get("domain") or {}
    headers = response.get("headers") or {}

    whois_hint = _whois_hint(response.get("whois"))

    dns_hint = (
        "does not resolve"
        if dns_banner(domain)
        else " · ".join(
            f"{label} {dns_failure_text(domain, key) or len(domain.get(key) or [])}"
            for label, key in (
                ("A", "a"),
                ("AAAA", "aaaa"),
                ("MX", "mx"),
                ("NS", "ns"),
                ("TXT", "txt"),
            )
        )
    )

    ssl_data = response.get("ssl")
    if not ssl_data:
        ssl_hint = "no certificate"
    elif ssl_data.get("error"):
        ssl_hint = ssl_data["error"]
    else:
        issuer = _cert_issuer(ssl_data)
        _, days_left = _cert_expiry(ssl_data)
        problem = _ssl_problem(ssl_data)
        if problem:
            ssl_hint = f"{issuer} · {problem}"
        else:
            ssl_hint = issuer if days_left is None else f"{issuer} · {days_left}d left"

    location = response.get("location") or {}
    geo_city = location.get("city_name")
    geo_country = location.get("country_code")
    geoip_hint = " · ".join(p for p in (geo_city, geo_country) if p) or "no data"

    header_count = len(headers)
    accordions = [
        {"id": "whois", "title": "WHOIS", "hint": whois_hint},
        {"id": "dns", "title": "DNS records", "hint": dns_hint},
        {"id": "ssl", "title": "SSL certificate", "hint": ssl_hint},
        {"id": "geoip", "title": "GeoIP", "hint": geoip_hint},
    ]
    # Right after GeoIP: the AS behind the address (asinfo.py).
    as_card = as_view(response.get("as_info"))
    if as_card:
        accordions.append({"id": "as", "title": "AS", "hint": as_card["hint"]})
    # Beside the DNS records it grades (dnssecurity.py).
    security = dns_security_view(response.get("dns_security"))
    if security:
        accordions.insert(
            2, {"id": "security", "title": "DNS security", "hint": security["hint"]}
        )
    reputation = reputation_view(response.get("reputation"))
    if reputation:
        accordions.append(
            {"id": "reputation", "title": "Reputation", "hint": reputation["hint"]}
        )

    # Only for a domain. An IP address has no subdomains, so offering the panel
    # would invite a request that can only fail. `domain` truthiness alone
    # isn't a reliable signal here: an IP lookup still carries a populated
    # `domain` dict (its own A record, used for the DNS accordion's hint
    # above), so this checks the address shape instead, same as build_view().
    #
    # Also gated on the kill switch: SUBDOMAIN_ENABLED=false must not leave
    # the page still advertising a panel whose only possible outcome is a 400
    # from the route.
    subdomain_data = response.get("subdomains")
    if subdomains_enabled and not _is_ip(response.get("address") or ""):
        # The hint doubles as the panel's call to action: nothing is fetched
        # until the accordion is opened, so before that it says what opening it
        # will do rather than where the data comes from. static/js/app.js
        # rewrites it to the same "N subdomains found" wording once the lazy
        # fetch lands, so the two paths read identically.
        if subdomain_data and subdomain_data.get("error"):
            hint = "lookup failed"
        elif subdomain_data:
            count = subdomain_data.get("count", 0)
            hint = f"{count:,} subdomain{'s' if count != 1 else ''} found"
        else:
            hint = "click to lookup"
        accordions.append({"id": "subdomains", "title": "Subdomains", "hint": hint})

    accordions.extend(
        [
            {
                "id": "headers",
                "title": "Your headers",
                "hint": f"{header_count} header{'s' if header_count != 1 else ''}",
            },
            {"id": "raw", "title": "Raw JSON", "hint": "full response"},
        ]
    )
    return accordions


def build_view(
    response: dict,
    is_self: bool,
    subdomains_enabled: bool = SUBDOMAIN_ENABLED,
    link_for: LinkFor | None = None,
    credit_links: dict[str, str] | None = None,
) -> dict:
    """The template's view of a response. `link_for` (main.lookup_href) decides
    which hostnames and addresses link to their own lookup -- the rDNS and PTR
    rows, the A → tag and the name servers; the DNS table's rows are main's --
    and None, the default, links nothing. `credit_links` is as_view's."""
    location = response.get("location") or {}
    domain = response.get("domain") or {}
    address = response.get("address") or ""
    is_ip = _is_ip(address)
    dns_queried_name, dns_zone = dns_names(domain, address)

    if is_ip:
        facts = [
            _network_column(location, address, link_for),
            _reverse_column(location, domain, address, link_for),
            _whois_column(response.get("whois")),
        ]
    else:
        facts = [
            _network_column(location, address, link_for),
            _dns_column(domain),
            _certificate_column(response.get("ssl")),
        ]

    return {
        "is_self": is_self,
        "eyebrow": "YOUR IP ADDRESS" if is_self else "LOOKUP",
        "target": address,
        "title": SELF_TITLE if is_self else f"{address} — WhatIsMyIP",
        "description": (
            SITE_DESCRIPTION if is_self else _summary(response, address, is_ip)
        ),
        # The page's path under the public base URL, for og:url and the
        # canonical link. gather() already supplies the canonical spelling;
        # lower() is harmless defense for a synthetic response in a test.
        "canonical_path": "" if is_self else quote(address.lower(), safe=""),
        "tags": _tags(response, is_ip, link_for),
        "flag": country_flag(location.get("country_code")),
        "country_name": location.get("country_name") or "",
        "city_line": _city_line(location),
        "asn_line": location.get("asn_name") or "",
        "distance_text": (
            format_distance(response.get("distance_km"))
            if _precise_route(response)
            else None
        ),
        "map_link": osm_link(location),
        "meta_line": format_meta(response.get("elapsed_ms"), response.get("datetime")),
        "facts": facts,
        "dns_banner": dns_banner(domain),
        "dns_queried_name": dns_queried_name,
        "dns_zone": dns_zone,
        "whois_pending": whois_pending(response.get("whois")),
        "whois_name_servers": name_server_links(response.get("whois"), link_for),
        "accordions": _accordions(response, subdomains_enabled),
        "ssl_rows": ssl_rows(response.get("ssl"), response.get("address")),
        # A domain's address may have been found under another name (a CNAME
        # chain); an IP's sweep is of its PTR name, and its location is its own.
        "geoip_rows": geoip_rows(location, None if is_ip else domain),
        "reputation": reputation_view(response.get("reputation")),
        "as_info": as_view(
            response.get("as_info"), link_for, credit_links=credit_links
        ),
        "dns_security": dns_security_view(response.get("dns_security")),
        "subdomains": response.get("subdomains"),
        "subdomains_shown": (response.get("subdomains") or {}).get("names", [])[:100],
    }


# ---------------------------------------------------------------------------
# The /AS<n> page's words and numbers: a sentence, four tiles, four bars.
# ---------------------------------------------------------------------------


def human_count(n: int) -> str:
    """999, 1.0k, 131k, 8.7M, 29M. static/js/as.js repeats this digit for
    digit, so the server-drawn and the client-drawn number cannot disagree."""
    if n < 1000:
        return str(n)
    if n < 999_500:
        t = (n + 50) // 100
        return f"{t // 10}.{t % 10}k" if t < 100 else f"{(n + 500) // 1000}k"
    t = (n + 50_000) // 100_000
    return f"{t // 10}.{t % 10}M" if t < 100 else f"{(n + 500_000) // 1_000_000}M"


def _split_as_name(name: str | None) -> tuple[str, str] | None:
    """RIPE's 'HANDLE - Holder' or 'HANDLE Holder' as (handle, holder); a
    single word is both. None for no name."""
    name = (name or "").strip()
    if not name:
        return None
    if " - " in name:
        handle, holder = name.split(" - ", 1)
    elif " " in name:
        handle, holder = name.split(" ", 1)
    else:
        return name, name
    return handle.strip(), holder.strip() or handle.strip()


def as_handle(name: str | None) -> str | None:
    """The registry handle of a RIPE AS name (LGDACOM-KR)."""
    parts = _split_as_name(name)
    return parts[0] if parts else None


def as_holder(name: str | None) -> str | None:
    """The holder of a RIPE AS name (LG DACOM Corporation)."""
    parts = _split_as_name(name)
    return parts[1] if parts else None


_RIR_NAMES = {"ripencc": "RIPE NCC", "ripe": "RIPE NCC"}


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else many or one + 's'}"


def _join_clauses(clauses: list[str]) -> str:
    if len(clauses) <= 1:
        return "".join(clauses)
    return ", ".join(clauses[:-1]) + " and " + clauses[-1]


def _rpki_share(rpki: dict | None) -> tuple[int, float] | None:
    """(signed prefixes, their share of all, 0 to 100): signed is valid plus
    invalid. None without a section, or when it counts nothing."""
    if not rpki:
        return None
    valid, invalid = rpki.get("valid") or 0, rpki.get("invalid") or 0
    total = valid + invalid + (rpki.get("not_found") or 0)
    if not total:
        return None
    return valid + invalid, (valid + invalid) * 100 / total


def _share_text(share: float) -> str:
    """'under 1%' for a share that exists but would round to 0."""
    return "under 1%" if 0 < share < 0.5 else f"{round(share)}%"


def _is_complete(relation: dict | None) -> bool:
    return bool(relation) and len(relation.get("list") or []) == relation.get("count")


def _relation(as_info: dict, page: dict | None, key: str) -> dict | None:
    """{count, list} of upstreams, downstreams or peers: the page's when there
    is one, else the card's (whose upstreams are a bare list)."""
    if page and page.get(key):
        return page[key]
    value = as_info.get(key)
    if isinstance(value, list):
        return {"count": len(value), "list": value}
    return value or None


def _downstream_scope(as_info: dict, downstreams: dict) -> str:
    """' (all in X)' or ' (k in X)' for the AS's own country, from a complete
    list; '' when it is not the largest group or nothing is known."""
    own = as_info.get("country")
    if not own or not _is_complete(downstreams) or not downstreams["list"]:
        return ""
    tally: dict[str, int] = {}
    for entry in downstreams["list"]:
        if entry.get("country"):
            tally[entry["country"]] = tally.get(entry["country"], 0) + 1
    k = tally.get(own, 0)
    if not k or k < max(tally.values()):
        return ""
    name = country_name(own)
    if k == len(downstreams["list"]):
        return f" (all in {name})"
    return f" ({k} in {name})"


def _first_sentence(as_info: dict) -> str | None:
    registry = as_info.get("registry") or {}
    country = country_name(as_info.get("country"))
    rir = registry.get("rir")
    registered = ""
    if rir:
        rir = _RIR_NAMES.get(rir.lower(), rir.upper())
        year = str(registry.get("assigned") or "")[:4]
        registered = f"registered with {rir}" + (f" in {year}" if year else "")
    if country and registered:
        return f"A network in {country}, {registered}."
    if country:
        return f"A network in {country}."
    if registered:
        return f"A network {registered}."
    return None


def _second_sentence(as_info: dict, page: dict | None, subject: str) -> str | None:
    clauses = []
    ups = _relation(as_info, page, "upstreams")
    if ups is not None:
        n = ups["count"]
        clauses.append(
            f"buys transit from {_plural(n, 'upstream')}"
            if n
            else "has no upstreams in CAIDA's data"
        )
    downs = _relation(as_info, page, "downstreams")
    if downs is not None:
        n = downs["count"]
        clauses.append(
            f"serves {_plural(n, 'downstream network')}"
            + _downstream_scope(as_info, downs)
            if n
            else "serves no downstream networks"
        )
    peers = _relation(as_info, page, "peers")
    if peers is not None:
        n = peers["count"]
        if not n:
            clauses.append("has no peers in CAIDA's data")
        else:
            text = f"peers with {_plural(n, 'network')}"
            if _is_complete(peers):
                known = {e["country"] for e in peers["list"] if e.get("country")}
                text += f" in {_plural(len(known), 'country', 'countries')}"
            clauses.append(text)
    if not clauses:
        return None
    return f"{subject} {_join_clauses(clauses)}."


def _blocks(prefixes: list[str]) -> int:
    """Contiguous IPv4 blocks once overlapping and adjacent prefixes merge."""
    networks = [ipaddress.ip_network(p, strict=False) for p in prefixes]
    return sum(1 for _ in ipaddress.collapse_addresses(networks))


def _about_slash(addresses: int) -> int:
    return round(32 - math.log2(addresses))


def _third_sentence(as_info: dict, subject: str) -> str | None:
    prefixes = as_info.get("prefixes")
    if prefixes is None:
        return None
    v4, v6 = prefixes.get("v4") or 0, prefixes.get("v6") or 0
    if not v4 and not v6:
        return f"{subject} announces no prefixes."
    parts = []
    if v4:
        parts.append(f"{v4:,} IPv4")
    if v6:
        parts.append(f"{v6:,} IPv6")
    text = f"{subject} announces {' and '.join(parts)} " + (
        "prefix" if v4 + v6 == 1 else "prefixes"
    )
    addresses = prefixes.get("v4_addresses") or 0
    if v4 and addresses:
        text += (
            f" covering {human_count(addresses)} IPv4 addresses"
            f" (about one /{_about_slash(addresses)})"
        )
    share = _rpki_share(as_info.get("rpki"))
    if share:
        text += f"; {_share_text(share[1])} of its prefixes are RPKI-signed"
        invalid = as_info["rpki"].get("invalid") or 0
        if invalid:
            text += f" ({invalid} invalid)"
    return text + "."


def as_summary(as_info: dict, page: dict | None) -> str | None:
    """The page's plain-English paragraph: who and where, how it connects
    (only with CAIDA's relationships), what it announces (only with RIS). A
    part whose data is unavailable is left out, never filled with zeros."""
    first = _first_sentence(as_info)
    name = f"AS{as_info['asn']}"
    second = _second_sentence(as_info, page, "It" if first else name)
    third = _third_sentence(as_info, "It" if first or second else name)
    text = " ".join(part for part in (first, second, third) if part)
    return text or None


def _tile(key, label, value, sub, tone="default", segments=None) -> dict:
    return {
        "key": key,
        "label": label,
        "value": value,
        "sub": sub,
        "tone": tone,
        "segments": segments,
    }


def _unknown_tile(key, label, as_info, dataset_ids) -> dict:
    return _tile(key, label, "Unknown", _as_absent(as_info, dataset_ids), "muted")


def _segments(parts: list[tuple[str, int, str]]) -> list[dict]:
    """[(label, count, tone)] as bar segments with their share of the total."""
    total = sum(count for _, count, _ in parts)
    return [
        {
            "label": label,
            "count": count,
            "tone": tone,
            "pct": round(count * 100 / total, 2) if total else 0.0,
        }
        for label, count, tone in parts
    ]


def _rpki_parts(rpki: dict) -> list[tuple[str, int, str]]:
    return [
        ("valid", rpki.get("valid") or 0, "success"),
        ("invalid", rpki.get("invalid") or 0, "danger"),
        ("not found", rpki.get("not_found") or 0, "muted"),
    ]


def as_tiles(as_info: dict, page: dict | None) -> list[dict]:
    """The four count tiles: IPv4 space, prefixes, RPKI signed, neighbours."""
    ris = ("ris_v4", "ris_v6")
    prefixes = as_info.get("prefixes")
    v4_list = ((page or {}).get("prefixes") or {}).get("v4")
    if prefixes is None:
        space = _unknown_tile("space", "IPv4 space", as_info, ris)
        counts = _unknown_tile("prefixes", "Prefixes", as_info, ris)
    else:
        addresses = prefixes.get("v4_addresses") or 0
        sub = None
        if addresses:
            sub = f"addresses ≈ one /{_about_slash(addresses)}"
            if _is_complete(v4_list):
                blocks = _blocks([p["prefix"] for p in v4_list["list"]])
                sub += f" · {_plural(blocks, 'block')}"
        space = _tile("space", "IPv4 space", human_count(addresses), sub)
        sub = None
        if _is_complete(v4_list) and v4_list["list"]:
            k = sum(1 for p in v4_list["list"] if p.get("plen") == 24)
            sub = f"{k} of the v4 are /24s"
        counts = _tile(
            "prefixes",
            "Prefixes",
            f"{prefixes.get('v4') or 0} v4 · {prefixes.get('v6') or 0} v6",
            sub,
        )
    rpki = as_info.get("rpki")
    if rpki is None:
        signed = _unknown_tile("rpki", "RPKI signed", as_info, ("rpki",) + ris)
    else:
        share = _rpki_share(rpki)
        signed = _tile(
            "rpki",
            "RPKI signed",
            _share_text(share[1]) if share else "–",
            f"{rpki.get('valid') or 0} valid · {rpki.get('invalid') or 0} invalid"
            f" · {rpki.get('not_found') or 0} not found",
            segments=_segments(_rpki_parts(rpki)),
        )
    relations = [
        _relation(as_info, page, k) for k in ("upstreams", "downstreams", "peers")
    ]
    if any(r is None for r in relations):
        neighbours = _unknown_tile("neighbours", "Neighbours", as_info, ("caida_rel",))
    else:
        neighbours = _tile(
            "neighbours",
            "Neighbours",
            " · ".join(str(r["count"]) for r in relations),
            "upstreams · downstreams · peers",
        )
    return [space, counts, signed, neighbours]


def _size_bucket(plen: int) -> int:
    if plen >= 24:
        return 0
    if plen == 23:
        return 1
    if plen == 22:
        return 2
    return 3 if plen >= 17 else 4


def _visibility_bucket(peers: int, median: int) -> int:
    if peers >= 0.75 * median:
        return 0
    return 1 if peers >= 0.25 * median else 2


def _bar(key, label, parts=None, empty=None) -> dict:
    return {
        "key": key,
        "label": label,
        "segments": _segments(parts) if parts else [],
        "empty": empty,
    }


def as_glance(as_info: dict, page: dict | None) -> dict:
    """The four composition bars (RPKI, visibility, IPv4 sizes, family) and the
    note about what the counts leave out. A bar drawn from a truncated list
    says how many of the largest it drew."""
    ris = ("ris_v4", "ris_v6")
    lists = (page or {}).get("prefixes")
    medians = (page or {}).get("medians") or {}
    bars = []

    rpki = as_info.get("rpki")
    if rpki is None:
        bars.append(_bar("rpki", "RPKI", empty=_as_absent(as_info, ("rpki",) + ris)))
    elif not any(_rpki_parts(rpki)[i][1] for i in range(3)):
        bars.append(_bar("rpki", "RPKI", empty="No announced prefixes"))
    else:
        bars.append(_bar("rpki", "RPKI", _rpki_parts(rpki)))

    def from_lists(key, label, build):
        if lists is None:
            return _bar(key, label, empty=_as_absent(as_info, ris))
        return build(lists)

    def visibility(lists):
        counts, listed, cut = [0, 0, 0], 0, []
        for family in ("v4", "v6"):
            part = lists.get(family) or {}
            entries = part.get("list") or []
            listed += len(entries)
            if len(entries) < (part.get("count") or 0):
                cut.append(len(entries))
            median = medians.get(family)
            if not median:
                continue  # nothing to compare this family's peer counts with
            for entry in entries:
                counts[_visibility_bucket(entry["ris_peers"], median)] += 1
        label = "Visibility"
        if cut:
            label += f" (largest {max(cut):,} per family)"
        if not listed:
            return _bar("visibility", label, empty="No announced prefixes")
        if not sum(counts):
            return _bar("visibility", label, empty="Unknown")
        return _bar(
            "visibility",
            label,
            [
                ("widely seen", counts[0], "success"),
                ("partly", counts[1], "warning"),
                ("narrowly", counts[2], "muted"),
            ],
        )

    def sizes(lists):
        part = lists.get("v4") or {}
        entries = part.get("list") or []
        label = "Sizes (IPv4)" + _truncated(len(entries), part.get("count") or 0)
        if not entries:
            return _bar("sizes", label, empty="No announced prefixes")
        counts = [0] * 5
        for entry in entries:
            counts[_size_bucket(entry["plen"])] += 1
        names = ("/24", "/23", "/22", "/17–/21", "/16 and shorter")
        return _bar("sizes", label, [(n, c, "default") for n, c in zip(names, counts)])

    bars.append(from_lists("visibility", "Visibility", visibility))
    bars.append(from_lists("sizes", "Sizes (IPv4)", sizes))

    prefixes = as_info.get("prefixes")
    if prefixes is None:
        bars.append(_bar("family", "Family", empty=_as_absent(as_info, ris)))
    else:
        v4, v6 = prefixes.get("v4") or 0, prefixes.get("v6") or 0
        if v4 + v6:
            bars.append(
                _bar(
                    "family",
                    "Family",
                    [("IPv4", v4, "default"), ("IPv6", v6, "default")],
                )
            )
        else:
            bars.append(_bar("family", "Family", empty="No announced prefixes"))
    return {
        "bars": bars,
        "note": (
            f"Routes seen by fewer than {ASINFO_MIN_RIS_PEERS} RIS peers are left out, "
            "so counts can differ from other sites."
        ),
    }


def _truncated(drawn: int, total: int) -> str:
    """' (largest 1,000)' when a bar is drawn from fewer prefixes than exist."""
    return f" (largest {drawn:,})" if drawn < total else ""


# ---------------------------------------------------------------------------
# The /AS<n> page's graph, map and tables.
# ---------------------------------------------------------------------------

AS_GRAPH_ROWS = 12
AS_GRAPH_ROW_HEIGHT = 30
AS_TABLE_ROWS = 10
_NEIGHBOUR_RELATIONS = (
    ("upstream", "Upstreams", "upstreams"),
    ("downstream", "Downstreams", "downstreams"),
    ("peer", "Peers", "peers"),
)
NEIGHBOUR_NOTE = (
    "Sizes are each neighbour's own: its direct customers and its IPv4 space, "
    "not traffic through this AS."
)
MAP_CREDIT = "\u00a9 OpenStreetMap contributors \u00b7 GeoLite2 by MaxMind"


def _neighbour_href(link_for: LinkFor | None, asn: Any) -> str | None:
    return _href(link_for, f"AS{asn}")


def as_upstream_graph(
    as_info: dict, page: dict | None, link_for: LinkFor | None = None
) -> dict:
    """The upstream providers as bars (by their own direct customers, square
    root scaled so a giant does not flatten the rest) and the SVG paths that
    fan them into the AS. At most AS_GRAPH_ROWS rows; the rest are `more`."""
    relation = _relation(as_info, page, "upstreams")
    graph = {"rows": [], "more": 0, "fan": [], "height": 0, "empty": None}
    if relation is None:
        graph["empty"] = _as_absent(as_info, ("caida_rel",))
        return graph
    entries = relation.get("list") or []
    count = relation.get("count") or len(entries)
    if not count:
        graph["empty"] = "No upstreams in CAIDA's data"
        return graph
    shown = entries[:AS_GRAPH_ROWS]
    top = max((e.get("customers") or 0 for e in shown), default=0)
    rows = []
    for entry in shown:
        customers = entry.get("customers")
        pct = 100 * math.sqrt((customers or 0) / top) if top else 0
        rows.append(
            {
                "asn": entry.get("asn"),
                "href": _neighbour_href(link_for, entry.get("asn")),
                "flag": country_flag(entry.get("country")),
                "country": entry.get("country"),
                "handle": as_handle(entry.get("name")),
                "customers_text": f"{customers:,}"
                if customers is not None
                else "\u2014",
                "bar_pct": round(max(4, pct), 1),
            }
        )
    more = max(count - len(rows), 0)
    height = (len(rows) + (1 if more else 0)) * AS_GRAPH_ROW_HEIGHT
    mid = height / 2
    graph["rows"] = rows
    graph["more"] = more
    graph["height"] = height
    graph["fan"] = [
        f"M0,{y} C36,{y} 36,{mid} 72,{mid}"
        for y in (
            i * AS_GRAPH_ROW_HEIGHT + AS_GRAPH_ROW_HEIGHT // 2 for i in range(len(rows))
        )
    ]
    return graph


def as_map_view(as_info: dict, as_map: dict | None) -> dict | None:
    """Where the AS's IPv4 addresses geolocate, as tiles and dots in percent
    and pixels of the canvas `as_map` carries. None without a map, or when
    there is neither a footprint with cities nor a country to pin. `approx`
    is the country pin: drawn as "around here", never as a city."""
    if not as_map:
        return None
    canvas = as_map.get("canvas") or {}
    footprint = as_map.get("footprint")
    fallback = as_map.get("fallback")
    cities = (footprint or {}).get("cities") or []
    width, height = canvas.get("width") or 1, canvas.get("height") or 1
    size = canvas.get("tile_size") or 256
    inside = [
        p
        for p in canvas.get("points") or []
        if 0 <= p["x"] <= width and 0 <= p["y"] <= height
    ]
    if cities:
        dots = [
            {"x": p["x"], "y": p["y"], "r": round(2.5 + 16 * math.sqrt(p["weight"]), 1)}
            for p in inside
        ]
        caption = (
            "Dots: where its IPv4 addresses geolocate (GeoLite2, by city; "
            "area = share)."
        )
        left_out = []
        country_share = footprint.get("country_level_share") or 0
        if country_share:
            left_out.append(
                f"{_share_text(country_share * 100)} of the space is placed only "
                "at country level and is not drawn."
            )
        unplaced = footprint.get("unplaced_share") or 0
        if unplaced:
            left_out.append(f"{_share_text(unplaced * 100)} could not be placed.")
        caption = " ".join([caption, *left_out])
        alt = "Where its IPv4 addresses geolocate: " + ", ".join(
            f"{c.get('name') or 'unnamed place'} {round(c['share'] * 100)}%"
            for c in cities[:5]
        )
    elif fallback == "country":
        place = country_name(as_info.get("country")) or "its registered country"
        dots = [{"x": p["x"], "y": p["y"], "r": 6.0} for p in inside]
        # Without the route data there were no prefixes to place: that is
        # unknown, never "no city-level placement".
        unread = {entry.get("dataset") for entry in as_info.get("unavailable") or []}
        if unread & {"ris_v4", "ris_v6"}:
            absent = _as_absent(as_info, ("ris_v4", "ris_v6"))
            caption = f"{absent}. The pin marks {place}, at country level."
            alt = f"{absent}. The pin marks {place}"
        else:
            caption = (
                "No city-level placement for its IPv4 addresses; "
                f"the pin marks {place}, at country level."
            )
            alt = (
                f"No city-level placement for its IPv4 addresses; the pin marks {place}"
            )
    else:
        return None
    return {
        "width": width,
        "height": height,
        "tiles": [
            {
                "url": t["url"],
                "left": round(100 * t["x"] / width, 3),
                "top": round(100 * t["y"] / height, 3),
                "w": round(100 * size / width, 3),
                "h": round(100 * size / height, 3),
            }
            for t in canvas.get("tiles") or []
        ],
        "dots": dots,
        "node": {
            "label": f"AS{as_info.get('asn')}",
            "sub": as_handle(as_info.get("name")),
        },
        "caption": caption,
        "credit": MAP_CREDIT,
        "alt": alt,
        "approx": not cities,
    }


def as_neighbour_table(
    as_info: dict, page: dict | None, link_for: LinkFor | None = None
) -> dict:
    """Upstreams, downstreams and peers as one table ordered by each
    neighbour's own customers: the first AS_TABLE_ROWS drawn, every loaded one
    in `payload` for the page's script, and what was cut said in `truncated`."""
    relations = {
        key: _relation(as_info, page, plural) for key, _, plural in _NEIGHBOUR_RELATIONS
    }
    counts = {
        key: (rel.get("count") or len(rel.get("list") or [])) if rel else 0
        for key, rel in relations.items()
    }
    counts = {"all": sum(counts.values()), **counts}
    merged = []
    truncated = []
    for key, _, plural in _NEIGHBOUR_RELATIONS:
        rel = relations[key]
        if not rel:
            continue
        entries = rel.get("list") or []
        if len(entries) < counts[key]:
            truncated.append(
                f"Largest {len(entries):,} of {counts[key]:,} {plural} loaded."
            )
        merged += [(key, entry) for entry in entries]
    merged.sort(
        key=lambda item: (-(item[1].get("customers") or 0), item[1].get("asn") or 0)
    )
    top = max((e.get("customers") or 0 for _, e in merged), default=0)
    rows = []
    for key, entry in merged[:AS_TABLE_ROWS]:
        customers = entry.get("customers")
        space = entry.get("v4_addresses")
        rows.append(
            {
                "asn": entry.get("asn"),
                "href": _neighbour_href(link_for, entry.get("asn")),
                "holder": as_holder(entry.get("name")),
                "flag": country_flag(entry.get("country")),
                "country": entry.get("country"),
                "relation": key,
                "customers_text": f"{customers:,}"
                if customers is not None
                else "\u2014",
                "bar_pct": (
                    round(
                        100 * math.log10((customers or 0) + 1) / math.log10(top + 1), 1
                    )
                    if top
                    else 0
                ),
                "space_text": human_count(space) if space is not None else "\u2014",
            }
        )
    empty = None
    if all(rel is None for rel in relations.values()):
        empty = _as_absent(as_info, ("caida_rel",))
    elif not counts["all"]:
        empty = "No neighbours in CAIDA's data"
    return {
        "chips": [
            {"key": "all", "label": "All", "count": counts["all"]},
            *(
                {"key": key, "label": label, "count": counts[key]}
                for key, label, _ in _NEIGHBOUR_RELATIONS
            ),
        ],
        "rows": rows,
        "payload": {
            "columns": [
                "asn",
                "name",
                "country",
                "relation",
                "customers",
                "v4_addresses",
            ],
            "rows": [
                [
                    e.get("asn"),
                    e.get("name"),
                    e.get("country"),
                    key,
                    e.get("customers"),
                    e.get("v4_addresses"),
                ]
                for key, e in merged
            ],
            "counts": counts,
            "max_customers": top,
        },
        "truncated": truncated,
        "note": NEIGHBOUR_NOTE,
        "empty": empty,
    }


def _prefix_exponent(plen: int | None, family: str) -> int:
    """log2 of a prefix's size: addresses for IPv4, /48s for IPv6 (0 past /48)."""
    return max((32 if family == "v4" else 48) - (plen or 0), 0)


def _prefix_size_text(plen: int | None, family: str) -> str:
    exponent = _prefix_exponent(plen, family)
    if family == "v4":
        return human_count(2**exponent)
    if (plen or 0) > 48:
        return "under a /48"
    return f"{human_count(2**exponent)} /48s"


def as_prefix_table(as_info: dict, page: dict | None) -> dict:
    """The announced prefixes, largest first: the first AS_TABLE_ROWS of IPv4
    (of IPv6 when there is no IPv4 listed), every loaded one in `payload`."""
    lists = (page or {}).get("prefixes")
    table = {
        "rows": [],
        "counts": {"v4": 0, "v6": 0},
        "payload": {
            "columns": ["prefix", "plen", "ris_peers", "state", "reason"],
            "v4": [],
            "v6": [],
        },
        "truncated": [],
        "empty": None,
    }
    if lists is None:
        table["empty"] = _as_absent(as_info, ("ris_v4", "ris_v6"))
        return table
    entries = {}
    for family, word in (("v4", "IPv4"), ("v6", "IPv6")):
        part = lists.get(family) or {}
        loaded = sorted(part.get("list") or [], key=lambda e: e.get("plen") or 0)
        entries[family] = loaded
        count = part.get("count") or 0
        table["counts"][family] = count
        if len(loaded) < count:
            table["truncated"].append(
                f"Largest {len(loaded):,} of {count:,} {word} prefixes loaded."
            )
        table["payload"][family] = [
            [
                e.get("prefix"),
                e.get("plen"),
                e.get("ris_peers"),
                (e.get("rpki") or {}).get("state"),
                (e.get("rpki") or {}).get("reason"),
            ]
            for e in loaded
        ]
    if not any(table["counts"].values()):
        table["empty"] = "No announced prefixes"
        return table
    family = "v4" if entries["v4"] else "v6"
    loaded = entries[family]
    top = max((2 ** _prefix_exponent(e.get("plen"), family) for e in loaded), default=1)
    for entry in loaded[:AS_TABLE_ROWS]:
        plen = entry.get("plen")
        size = 2 ** _prefix_exponent(plen, family)
        rpki = entry.get("rpki") or {}
        state = rpki.get("state")
        text = _RPKI_STATES.get(state, "Unknown")
        if state == "invalid" and rpki.get("reason"):
            text += f": {rpki['reason']}"
        peers = entry.get("ris_peers")
        table["rows"].append(
            {
                "prefix": entry.get("prefix"),
                "size_text": _prefix_size_text(plen, family),
                "bar_pct": round(100 * math.log2(size + 1) / math.log2(top + 1), 1),
                "peers_text": f"{peers:,}" if isinstance(peers, int) else "\u2014",
                "rpki_text": text,
                "rpki_tone": _RPKI_TONES.get(state, "default" if state else "muted"),
            }
        )
    return table
