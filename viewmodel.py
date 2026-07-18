"""Map the API response onto exactly what the template prints.

Pure functions only: no request, no I/O. The template does no logic beyond
looping over what comes out of build_view().
"""

from __future__ import annotations

import datetime
import ipaddress
from typing import Any

DASH = "—"


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


def _first(value: Any) -> Any:
    """python-whois returns some fields (dates, especially) as lists."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


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
    parsed = datetime.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=datetime.timezone.utc
    )
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


def _format_cert_date(raw: str | None) -> str:
    if not raw:
        return DASH
    try:
        parsed = datetime.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
        return parsed.date().isoformat()
    except ValueError:
        return raw


def _ssl_status(ssl_data: dict) -> tuple[str, str]:
    _, days_left = _cert_expiry(ssl_data)
    if days_left is None:
        return DASH, "muted"
    if days_left < 0:
        return "expired", "danger"
    if days_left < 14:
        return f"valid · {days_left}d left", "warning"
    return f"valid · {days_left}d left", "success"


def ssl_rows(ssl_data: dict | None, address: str | None = None) -> list[dict]:
    """Detailed certificate rows for the SSL accordion. Empty when there is no
    certificate (IP lookups, private/reserved targets, or an unreachable host)."""
    if not ssl_data:
        return []
    status, tone = _ssl_status(ssl_data)
    cipher = ssl_data.get("cipher") or {}
    cipher_text = f"{cipher.get('name')} ({cipher.get('bits')}-bit)" if cipher else DASH
    san = _cert_san(ssl_data)
    rows = [
        {"label": "Status", "value": status, "tone": tone},
    ]
    # Does the served cert actually cover the name the visitor looked up? The
    # cert is fetched with SNI = that name, so a mismatch means a misconfigured
    # host (or a shared cert that forgot to list it) — worth flagging loudly.
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


def _network_column(location: dict, address: str) -> dict:
    # geoip2fast has no AS number, only the ASN's announced block and its name,
    # so this row is labelled for what it actually holds.
    rows = [
        {"label": "CIDR", "value": location.get("cidr") or DASH, "tone": "default"},
        {
            "label": "AS block",
            "value": location.get("asn_cidr") or DASH,
            "tone": "default",
        },
        {"label": "Org", "value": location.get("asn_name") or DASH, "tone": "default"},
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
            {
                "label": "rDNS",
                "value": location.get("reverse_dns") or DASH,
                "tone": "default" if location.get("reverse_dns") else "muted",
            }
        )
    return {"title": "NETWORK", "rows": rows}


def _dns_column(domain: dict) -> dict:
    domain = domain or {}
    return {
        "title": "DNS",
        "rows": [
            {"label": "A", "value": _count(domain.get("a")), "tone": "default"},
            {"label": "MX", "value": _count(domain.get("mx")), "tone": "default"},
            {"label": "NS", "value": _count(domain.get("ns")), "tone": "default"},
            {"label": "TXT", "value": _count(domain.get("txt")), "tone": "default"},
        ],
    }


def _reverse_column(location: dict, domain: dict) -> dict:
    domain = domain or {}
    reverse = location.get("reverse_dns")
    ttl = next(iter(domain.get("a") or []), {}).get("ttl")
    return {
        "title": "REVERSE DNS",
        "rows": [
            {
                "label": "PTR",
                "value": reverse or DASH,
                "tone": "default" if reverse else "muted",
            },
            {"label": "A", "value": _count(domain.get("a")), "tone": "default"},
            {"label": "NS", "value": _count(domain.get("ns")), "tone": "default"},
            {
                "label": "TTL",
                "value": f"{ttl}s" if ttl else DASH,
                "tone": "default" if ttl else "muted",
            },
        ],
    }


def _whois_column(whois_data: dict | None, location: dict) -> dict:
    whois_data = whois_data or {}
    failed = "error" in whois_data or not whois_data
    return {
        "title": "WHOIS",
        "rows": [
            {
                "label": "Status",
                "value": "unavailable" if failed else "available",
                "tone": "warning" if failed else "success",
            },
            {
                "label": "Netblock",
                "value": location.get("cidr") or DASH,
                "tone": "default",
            },
            {
                "label": "Country",
                "value": location.get("country_code") or DASH,
                "tone": "default",
            },
            {
                "label": "Updated",
                "value": str(whois_data.get("updated_date") or DASH),
                "tone": "muted" if failed else "default",
            },
        ],
    }


def _certificate_column(ssl_data: dict | None) -> dict:
    if not ssl_data:
        return {
            "title": "CERTIFICATE",
            "rows": [
                {"label": "Status", "value": "none", "tone": "muted"},
                {"label": "Issuer", "value": DASH, "tone": "muted"},
                {"label": "SAN", "value": DASH, "tone": "muted"},
                {"label": "Expires", "value": DASH, "tone": "muted"},
            ],
        }

    expires, days_left = _cert_expiry(ssl_data)
    if days_left is None:
        status, tone = DASH, "muted"
    elif days_left < 0:
        status, tone = "expired", "danger"
    elif days_left < 14:
        status, tone = f"valid · {days_left}d left", "warning"
    else:
        status, tone = f"valid · {days_left}d left", "success"

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


def _tags(response: dict, is_ip: bool) -> list[dict]:
    location = response.get("location") or {}
    domain = response.get("domain") or {}
    if is_ip:
        return [
            {"text": "IPv4", "tone": "default"},
            {
                "text": "PRIVATE" if location.get("is_private") else "PUBLIC",
                "tone": "warning" if location.get("is_private") else "default",
            },
        ]

    tags = [{"text": "DOMAIN", "tone": "default"}]
    first_a = next(iter(domain.get("a") or []), None)
    if first_a:
        tags.append({"text": f"A → {first_a['ip']}", "tone": "default"})
    if response.get("ssl"):
        tags.append({"text": "TLS valid", "tone": "success"})
    return tags


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


def _whois_value(key: str, value: Any) -> str:
    """Render one canonical field. RDAP and WHOIS both feed this, so it copes
    with datetimes, lists, and the odd bool without leaking Python reprs."""
    if value is None or value == "":
        return DASH
    if key == "source":
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


def whois_display(whois_data: dict | None) -> dict:
    """Turn a canonical registration record into ordered, labelled strings for
    the WHOIS accordion. Returns an error row on failure and {} when absent."""
    if not whois_data:
        return {}
    if whois_data.get("error"):
        return {"Error": str(whois_data["error"])}
    out: dict[str, str] = {}
    for key, label in _WHOIS_ROWS:
        text = _whois_value(key, whois_data.get(key))
        if text and text != DASH:
            out[label] = text
    return out


def geoip_rows(location: dict | None) -> list[dict]:
    """Detailed geolocation for the GeoIP accordion: country, region, city,
    coordinates, accuracy radius, time zone and network, from geoip2fast plus
    the GeoLite2-City overlay."""
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
    accuracy = location.get("accuracy_km")
    accuracy_text = f"± {accuracy} km" if accuracy is not None else DASH

    return [
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
            "value": location.get("asn_name") or DASH,
            "tone": "default",
        },
        {
            "label": "Network",
            "value": location.get("cidr") or location.get("asn_cidr") or DASH,
            "tone": "default",
        },
    ]


def _accordions(response: dict) -> list[dict]:
    whois_data = response.get("whois") or {}
    domain = response.get("domain") or {}
    headers = response.get("headers") or {}

    if "error" in whois_data or not whois_data:
        whois_hint = "lookup failed"
    else:
        who = (
            whois_data.get("registrar")
            or whois_data.get("registrant")
            or "registry data"
        )
        created = _year(whois_data.get("created"))
        expires = _year(whois_data.get("expires"))
        span = f" · {created} → {expires}" if created and expires else ""
        whois_hint = f"{who}{span}"

    dns_hint = " · ".join(
        f"{label} {len(domain.get(key) or [])}"
        for label, key in (("A", "a"), ("MX", "mx"), ("NS", "ns"), ("TXT", "txt"))
    )

    ssl_data = response.get("ssl")
    if not ssl_data:
        ssl_hint = "no certificate"
    else:
        issuer = _cert_issuer(ssl_data)
        _, days_left = _cert_expiry(ssl_data)
        ssl_hint = issuer if days_left is None else f"{issuer} · {days_left}d left"

    location = response.get("location") or {}
    geo_city = location.get("city_name")
    geo_country = location.get("country_code")
    geoip_hint = " · ".join(p for p in (geo_city, geo_country) if p) or "no data"

    header_count = len(headers)
    return [
        {"id": "whois", "title": "WHOIS", "hint": whois_hint},
        {"id": "dns", "title": "DNS records", "hint": dns_hint},
        {"id": "ssl", "title": "SSL certificate", "hint": ssl_hint},
        {"id": "geoip", "title": "GeoIP", "hint": geoip_hint},
        {
            "id": "headers",
            "title": "Your headers",
            "hint": f"{header_count} header{'s' if header_count != 1 else ''}",
        },
        {"id": "raw", "title": "Raw JSON", "hint": "full response"},
    ]


def build_view(response: dict, is_self: bool) -> dict:
    location = response.get("location") or {}
    domain = response.get("domain") or {}
    address = response.get("address") or ""
    is_ip = _is_ip(address)

    city = location.get("city_name") or ""
    subdivision = location.get("subdivision_name") or ""
    city_line = " · ".join(part for part in (city, subdivision) if part)

    if is_ip:
        facts = [
            _network_column(location, address),
            _reverse_column(location, domain),
            _whois_column(response.get("whois"), location),
        ]
    else:
        facts = [
            _network_column(location, address),
            _dns_column(domain),
            _certificate_column(response.get("ssl")),
        ]

    return {
        "is_self": is_self,
        "eyebrow": "YOUR IP ADDRESS" if is_self else "LOOKUP",
        "target": address,
        "tags": _tags(response, is_ip),
        "flag": country_flag(location.get("country_code")),
        "country_name": location.get("country_name") or "",
        "city_line": city_line,
        "asn_line": location.get("asn_name") or "",
        "distance_text": format_distance(response.get("distance_km")),
        "map_link": osm_link(location),
        "meta_line": format_meta(response.get("elapsed_ms"), response.get("datetime")),
        "facts": facts,
        "accordions": _accordions(response),
        "ssl_rows": ssl_rows(response.get("ssl"), response.get("address")),
        "geoip_rows": geoip_rows(location),
    }
