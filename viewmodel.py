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


def _network_column(location: dict, address: str) -> dict:
    rows = [
        {"label": "CIDR", "value": location.get("cidr") or DASH, "tone": "default"},
        {"label": "ASN", "value": location.get("asn_cidr") or DASH, "tone": "default"},
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


def _accordions(response: dict) -> list[dict]:
    whois_data = response.get("whois") or {}
    domain = response.get("domain") or {}
    headers = response.get("headers") or {}

    if "error" in whois_data or not whois_data:
        whois_hint = "lookup failed"
    else:
        registrar = whois_data.get("registrar") or "registry data"
        created = str(whois_data.get("creation_date") or "")[:4]
        expires = str(whois_data.get("expiration_date") or "")[:4]
        span = f" · {created} → {expires}" if created and expires else ""
        whois_hint = f"{registrar}{span}"

    dns_hint = " · ".join(
        f"{label} {len(domain.get(key) or [])}"
        for label, key in (("A", "a"), ("MX", "mx"), ("NS", "ns"), ("TXT", "txt"))
    )
    header_count = len(headers)
    return [
        {"id": "whois", "title": "WHOIS", "hint": whois_hint},
        {"id": "dns", "title": "DNS records", "hint": dns_hint},
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

    city = (location.get("city") or {}).get("name") or ""
    subdivision = (location.get("city") or {}).get("subdivision_name") or ""
    city_line = " · ".join(part for part in (city, subdivision) if part)

    asn_parts = [
        part for part in (location.get("asn_cidr"), location.get("asn_name")) if part
    ]

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
        "eyebrow": "YOUR IP ADDRESS" if is_self else "LOOKUP",
        "target": address,
        "tags": _tags(response, is_ip),
        "flag": country_flag(location.get("country_code")),
        "country_name": location.get("country_name") or "",
        "city_line": city_line,
        "asn_line": " · ".join(asn_parts),
        "distance_text": format_distance(response.get("distance_km")),
        "facts": facts,
        "accordions": _accordions(response),
    }
