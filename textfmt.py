"""Shell-sized answers for the lookup routes: `?format=text` and `?fields=`.

Pure: no I/O, no FastAPI. main.py decides which legs to run (legs_for), runs
them through lookup.gather(), and hands the result here to be cut down to the
named fields and rendered.

Field names and values follow the MCP tools' compact shapes (mcp_server's
compact_* helpers), so `country_code`, `asn_number` or `registrar` mean the
same thing over HTTP as in a model's context.
"""

import re
import unicodedata
from typing import Any

from mcp_server import (
    compact_location,
    compact_network,
    compact_registration,
    compact_reputation,
    compact_ssl,
)
from viewmodel import DASH

_BOTH = frozenset({"domain", "ip"})
_DOMAIN = frozenset({"domain"})
_IP = frozenset({"ip"})

# Every field, in the order the text block lists them, with the lookup.gather()
# legs it needs and the kinds of target it applies to. An IP gets no registrar,
# registration expiry or certificate here (gather() makes no TLS handshake to a
# bare IP), and a domain's own PTR is not looked up; such a field is left out
# of the block, and asked for by ?fields= it costs nothing and prints "-".
FIELDS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "target": (frozenset(), _BOTH),
    "ip": (frozenset({"resolve"}), _BOTH),
    "reverse_dns": (frozenset({"ptr"}), _IP),
    "country_code": (frozenset({"geo"}), _BOTH),
    "country_name": (frozenset({"geo"}), _BOTH),
    "city": (frozenset({"geo"}), _BOTH),
    "asn_number": (frozenset({"geo"}), _BOTH),
    "asn_name": (frozenset({"geo"}), _BOTH),
    "cidr": (frozenset({"geo"}), _BOTH),
    "registrar": (frozenset({"whois"}), _DOMAIN),
    "registrant": (frozenset({"whois"}), _BOTH),
    "domain_expires": (frozenset({"whois"}), _DOMAIN),
    "cert_issuer": (frozenset({"tls"}), _DOMAIN),
    "cert_expires": (frozenset({"tls"}), _DOMAIN),
    "cert_days_remaining": (frozenset({"tls"}), _DOMAIN),
    "risk_level": (frozenset({"reputation"}), _BOTH),
    "risk_signals": (frozenset({"reputation"}), _BOTH),
    # AbuseIPDB is asked only about an address looked up directly.
    "abuse_score": (frozenset({"reputation"}), _IP),
}

# Asked for by name only, never in the text block. A bare "risk_level: none"
# among the other lines reads as a clean bill, which the lists cannot give; a
# script that asks for it knows what it asked for. With REPUTATION_ENABLED=false
# all three read "-", and abuse_score does without ABUSEIPDB_API_KEY too.
_RISK_FIELDS = ("risk_level", "risk_signals")
_NOT_IN_BLOCK = frozenset({*_RISK_FIELDS, "abuse_score"})

_REGISTRATION_FIELDS = ("registrar", "registrant", "domain_expires")

# Text placeholders. "-" is an answer: there is no such value, or the field
# does not apply to this target. "?" is not: the lookup behind the value
# failed, so whether there is one is unknown. Only a failed WHOIS/RDAP lookup
# can be told apart today; a DNS or TLS failure still reads as "-".
MISSING = "-"
UNKNOWN = "?"


class InvalidFieldError(ValueError):
    """`?fields=` named nothing, or something that is not a field.

    `code` and `message` mirror lookup.InvalidTargetError, so main.py answers
    both with the same {"error", "code"} shape.
    """

    code = "invalid_field"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def parse_fields(values: list[str]) -> list[str] | None:
    """The field names `?fields=` asks for, in the order asked; None when the
    parameter is absent. Comma-separated, and repeatable (?fields=a&fields=b).

    Duplicates are kept: one output line per name asked for is the contract a
    script reading lines by position depends on.
    """
    if not values:
        return None
    names = [
        name.strip().lower()
        for value in values
        for name in value.split(",")
        if name.strip()
    ]
    valid = ", ".join(FIELDS)
    if not names:
        raise InvalidFieldError(f"no field requested; valid fields: {valid}")
    unknown = [name for name in names if name not in FIELDS]
    if unknown:
        raise InvalidFieldError(
            f"unknown field: {', '.join(unknown)}; valid fields: {valid}"
        )
    return names


def block_fields(kind: str) -> list[str]:
    """The keys of the text block for a target of `kind` ("domain" or "ip")."""
    return [
        name
        for name, (_, kinds) in FIELDS.items()
        if kind in kinds and name not in _NOT_IN_BLOCK
    ]


def legs_for(names: list[str], kind: str) -> frozenset[str]:
    """The lookup.gather() legs that `names` need for a target of `kind`. A
    field that does not apply to the target needs none."""
    legs: set[str] = set()
    for name in names:
        needs, kinds = FIELDS[name]
        if kind in kinds:
            legs |= needs
    return frozenset(legs)


def _date(value: Any) -> str | None:
    """RDAP's ISO datetime cut to its date, like cert_expires; anything else a
    port-43 server sent is passed through as it came."""
    if not value:
        return None
    text = str(value)
    return text[:10] if re.match(r"\d{4}-\d{2}-\d{2}", text) else text


def field_values(data: dict, kind: str) -> tuple[dict[str, Any], dict[str, str]]:
    """Every field's value from a lookup.gather()-shaped dict for a target of
    `kind`, and the reason for each value whose lookup failed.

    A value is None when there is none; a field in the second dict is None
    because its lookup failed, not because there is nothing there.
    """
    location = data.get("location") or {}
    geo = {**compact_location(location), **compact_network(location)}
    registration = compact_registration(data.get("whois"))
    tls = compact_ssl(data.get("ssl")) or {}
    reputation = compact_reputation(data.get("reputation")) or {}
    values = {
        "target": data.get("address"),
        "ip": data.get("resolved_ip"),
        "reverse_dns": data.get("reverse_dns"),
        "country_code": geo["country_code"],
        "country_name": geo["country_name"],
        "city": geo["city"],
        "asn_number": geo["asn_number"],
        "asn_name": geo["asn_name"],
        "cidr": geo["cidr"],
        "registrar": registration.get("registrar"),
        "registrant": registration.get("registrant"),
        "domain_expires": _date(registration.get("expires")),
        "cert_issuer": tls.get("issuer"),
        "cert_expires": tls.get("expires"),
        "cert_days_remaining": tls.get("days_remaining"),
        "risk_level": reputation.get("level"),
        # The ids, comma-separated: one value per field is the format.
        "risk_signals": ",".join(s["id"] for s in reputation.get("signals") or []),
        "abuse_score": (reputation.get("abuseipdb") or {}).get("abuse_confidence"),
    }
    # The certificate helpers answer the page, which shows an em dash for "none".
    values = {
        name: None if value == "" or value == DASH else value
        for name, value in values.items()
    }
    # compact_registration reports "not registered" as registered: false, not
    # as an error, so only a lookup that broke lands here. A field that does
    # not apply to the target stays "-" whatever happened to the lookup.
    error = registration.get("error")
    errors = {
        name: str(error)
        for name in _REGISTRATION_FIELDS
        if error and kind in FIELDS[name][1]
    }
    # No list could be read: the level is unknown, not "none".
    if reputation and reputation.get("level") is None:
        for name in _RISK_FIELDS:
            errors[name] = "no reputation list could be checked"
    # Asked, but AbuseIPDB did not answer: unknown, not "-".
    for entry in reputation.get("could_not_check") or []:
        if entry["list"] == "AbuseIPDB" and kind in FIELDS["abuse_score"][1]:
            errors["abuse_score"] = entry["reason"]
    return values, errors


def _clean(value: Any) -> str:
    # One line per value is the whole format, so a newline in registration data
    # must not forge another line, and an escape sequence a registry sent must
    # not reach the reader's terminal.
    text = "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in str(value))
    return " ".join(text.split())


def _cell(name: str, values: dict, errors: dict) -> str:
    if name in errors:
        return UNKNOWN
    value = values[name]
    if value is None:
        return MISSING
    return _clean(value) or MISSING


def render_block(names: list[str], values: dict, errors: dict) -> str:
    """`key: value`, one per line: the answer to ?format=text without ?fields=."""
    return "".join(f"{name}: {_cell(name, values, errors)}\n" for name in names)


def render_lines(names: list[str], values: dict, errors: dict) -> str:
    """Bare values, one per line in the order asked: ?fields= as text."""
    return "".join(f"{_cell(name, values, errors)}\n" for name in names)


def render_json(names: list[str], values: dict, errors: dict) -> dict[str, Any]:
    """A flat object of just the fields asked for: ?fields= as JSON. "errors"
    appears only when a lookup failed, and says why each null is one."""
    out: dict[str, Any] = {name: values[name] for name in names}
    failed = {name: errors[name] for name in names if name in errors}
    if failed:
        out["errors"] = failed
    return out


def render_error(message: str) -> str:
    """A refused request as a text client reads it: one line."""
    return f"error: {_clean(message)}\n"
