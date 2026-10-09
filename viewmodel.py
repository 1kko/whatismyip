"""Map the API response onto exactly what the template prints.

Pure functions only: no request, no I/O. The template does no logic beyond
looping over what comes out of build_view().
"""

from __future__ import annotations

import datetime
import ipaddress
from typing import Any
from urllib.parse import quote

from config import SUBDOMAIN_ENABLED

# Mirrors rdap.NOT_REGISTERED rather than importing it: `rdap` pulls in whoisit,
# which costs ~400ms of import time -- twelve times this whole module's -- and
# viewmodel is the pure module every template test imports. Same trade as
# subdomain_store.sanitize_log. If the sentinel changes, it changes in both.
NOT_REGISTERED = "not registered"

DASH = "—"
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


def _format_cert_date(raw: str | None) -> str:
    if not raw:
        return DASH
    try:
        parsed = datetime.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
        return parsed.date().isoformat()
    except ValueError:
        return raw


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
    """'AS4766 Korea Telecom' when the GeoLite2-ASN overlay supplied the AS
    number; just the org name when only geoip2fast answered (it has no AS
    numbers, only the announced block and name)."""
    name = location.get("asn_name")
    number = location.get("asn_number")
    if name and number:
        return f"AS{number} {name}"
    return name or DASH


def _network_column(location: dict, address: str) -> dict:
    rows = [
        {"label": "CIDR", "value": location.get("cidr") or DASH, "tone": "default"},
        {
            "label": "AS block",
            "value": location.get("asn_cidr") or DASH,
            "tone": "default",
        },
        {"label": "Org", "value": _asn_org(location), "tone": "default"},
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


def _dns_count_row(label: str, domain: dict, key: str) -> dict:
    failure = dns_failure_text(domain, key)
    if failure:
        return {"label": label, "value": failure, "tone": "warning"}
    return {"label": label, "value": _count(domain.get(key)), "tone": "default"}


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
        ],
    }


def _reverse_column(location: dict, domain: dict, address: str) -> dict:
    domain = domain or {}
    reverse = location.get("reverse_dns")
    # The PTR name's own addresses of the looked-up address's family: the
    # ones that would confirm the PTR points back.
    label, key = ("AAAA", "aaaa") if _ip_version(address) == 6 else ("A", "a")
    ttl = next(iter(domain.get(key) or []), {}).get("ttl")
    return {
        "title": "REVERSE DNS",
        "rows": [
            {
                "label": "PTR",
                "value": reverse or DASH,
                "tone": "default" if reverse else "muted",
            },
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
    # Three states, not two. "not registered" is an answer -- the registry was
    # reached and said there is no such registration, which is the normal result
    # for a subdomain -- while "unavailable" means we could not find out.
    if error == NOT_REGISTERED:
        status, tone = "not registered", "muted"
    elif error or not whois_data:
        status, tone = "unavailable", "warning"
    else:
        status, tone = "available", "success"
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


def _tags(response: dict, is_ip: bool) -> list[dict]:
    location = response.get("location") or {}
    domain = response.get("domain") or {}
    if is_ip:
        return [
            {"text": f"IPv{_ip_version(response['address'])}", "tone": "default"},
            {
                "text": "PRIVATE" if location.get("is_private") else "PUBLIC",
                "tone": "warning" if location.get("is_private") else "default",
            },
        ]

    tags = [{"text": "DOMAIN", "tone": "default"}]
    first_a = next(iter(domain.get("a") or []), None)
    first_aaaa = next(iter(domain.get("aaaa") or []), None)
    if first_a:
        tags.append({"text": f"A → {first_a['ip']}", "tone": "default"})
    elif first_aaaa:
        # An IPv6-only name: its address, rather than no address at all.
        tags.append({"text": f"AAAA → {first_aaaa['ip']}", "tone": "default"})
    # "TLS valid" only for a certificate that verified: any certificate at all
    # used to earn it, and a broken one now comes back rather than None.
    ssl_data = response.get("ssl") or {}
    problem = _ssl_problem(ssl_data)
    if problem:
        tags.append({"text": f"TLS {problem}", "tone": "danger"})
    elif ssl_data.get("trusted"):
        tags.append({"text": "TLS valid", "tone": "success"})
    return tags


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
            "value": _asn_org(location),
            "tone": "default",
        },
        {
            "label": "Network",
            "value": location.get("cidr") or location.get("asn_cidr") or DASH,
            "tone": "default",
        },
    ]


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
    created = _year(whois_data.get("created"))
    expires = _year(whois_data.get("expires"))
    span = f" · {created} → {expires}" if created and expires else ""
    return f"{who}{span}"


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
    response: dict, is_self: bool, subdomains_enabled: bool = SUBDOMAIN_ENABLED
) -> dict:
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
            _reverse_column(location, domain, address),
            _whois_column(response.get("whois")),
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
        "title": SELF_TITLE if is_self else f"{address} — WhatIsMyIP",
        "description": (
            SITE_DESCRIPTION if is_self else _summary(response, address, is_ip)
        ),
        # The page's path under the public base URL, for og:url and the
        # canonical link. Hostnames are case-insensitive, and gather() keeps
        # the case it was given, so /NASA.gov and /nasa.gov are one page.
        "canonical_path": "" if is_self else quote(address.lower(), safe=""),
        "tags": _tags(response, is_ip),
        "flag": country_flag(location.get("country_code")),
        "country_name": location.get("country_name") or "",
        "city_line": city_line,
        "asn_line": location.get("asn_name") or "",
        "distance_text": format_distance(response.get("distance_km")),
        "map_link": osm_link(location),
        "meta_line": format_meta(response.get("elapsed_ms"), response.get("datetime")),
        "facts": facts,
        "dns_banner": dns_banner(domain),
        "whois_pending": whois_pending(response.get("whois")),
        "accordions": _accordions(response, subdomains_enabled),
        "ssl_rows": ssl_rows(response.get("ssl"), response.get("address")),
        "geoip_rows": geoip_rows(location),
        "subdomains": response.get("subdomains"),
        "subdomains_shown": (response.get("subdomains") or {}).get("names", [])[:100],
    }
