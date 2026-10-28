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
    compact_reverse_ip,
    compact_reputation,
    compact_ssl,
)
from viewmodel import DASH, DNS_FAILURE_TEXT, dmarc_policy, fcrdns_state

_BOTH = frozenset({"domain", "ip"})
_DOMAIN = frozenset({"domain"})
_IP = frozenset({"ip"})
# The geo leg is there for the card's fallback AS (GeoLite2's number).
_ROUTE_LEGS = frozenset({"resolve", "geo", "asinfo"})

# Every field, in the order the text block lists them, with the lookup.gather()
# legs it needs and the kinds of target it applies to. An IP gets no registrar,
# registration expiry or certificate here (gather() makes no TLS handshake to a
# bare IP), and a domain's own PTR is not looked up; such a field is left out
# of the block, and asked for by ?fields= it costs nothing and prints "-".
FIELDS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "target": (frozenset(), _BOTH),
    "ip": (frozenset({"resolve"}), _BOTH),
    # How the A query ended, so a "?" ip can be read: the gather() resolution
    # ("ok", "nxdomain", "noanswer", "timeout", "servfail", "error"). A
    # domain's only; an IP's "literal" says nothing, and / has none.
    "resolution": (frozenset({"resolve"}), _DOMAIN),
    "reverse_dns": (frozenset({"ptr"}), _IP),
    # The sweep of the PTR name is what it compares the address with.
    "reverse_dns_confirmed": (frozenset({"ptr", "dns"}), _IP),
    "country_code": (frozenset({"geo"}), _BOTH),
    "country_name": (frozenset({"geo"}), _BOTH),
    "city": (frozenset({"geo"}), _BOTH),
    "asn_number": (frozenset({"geo"}), _BOTH),
    "asn_name": (frozenset({"geo"}), _BOTH),
    "cidr": (frozenset({"geo"}), _BOTH),
    # The announced route covering the address (RIPE RIS), the origin the AS
    # card describes, and that origin's RPKI state. A local read, so they cost
    # nothing and sit in the block, while AS information is on (block_fields).
    "route_prefix": (_ROUTE_LEGS, _BOTH),
    "route_origin": (_ROUTE_LEGS, _BOTH),
    "rpki_state": (_ROUTE_LEGS, _BOTH),
    "registrar": (frozenset({"whois"}), _DOMAIN),
    "registrant": (frozenset({"whois"}), _BOTH),
    "domain_expires": (frozenset({"whois"}), _DOMAIN),
    # Whole days since the registration was created and since the certificate
    # became valid: the MCP tools' registration.age_days and tls.age_days.
    "domain_age_days": (frozenset({"whois"}), _DOMAIN),
    "cert_issuer": (frozenset({"tls"}), _DOMAIN),
    "cert_expires": (frozenset({"tls"}), _DOMAIN),
    "cert_days_remaining": (frozenset({"tls"}), _DOMAIN),
    "cert_age_days": (frozenset({"tls"}), _DOMAIN),
    "risk_level": (frozenset({"reputation"}), _BOTH),
    "risk_signals": (frozenset({"reputation"}), _BOTH),
    # 0-100, 100 the most dangerous. Out of the text block: a bare 0 reads as safe.
    "risk_score": (frozenset({"reputation"}), _BOTH),
    # AbuseIPDB is asked only about an address looked up directly.
    "abuse_score": (frozenset({"reputation"}), _IP),
    # The DMARC policy that governs the name (viewmodel.dmarc_policy).
    "dmarc_policy": (frozenset({"dns"}), _DOMAIN),
    # dnssecurity.evaluate()'s state per check: pass, warn, fail or info;
    # "unknown" is "?" with the check's summary as the reason.
    # Reverse IP (OpenINTEL): names on public top lists that resolved to the
    # address, and the counts for its /24 or /48. The last three are licence
    # text, brought along by parse_fields beside any of the first four.
    "reverse_ip_total": (frozenset({"reverseip"}), _IP),
    "reverse_ip_names": (frozenset({"reverseip"}), _IP),
    "reverse_ip_block_addresses": (frozenset({"reverseip"}), _IP),
    "reverse_ip_block_names": (frozenset({"reverseip"}), _IP),
    "reverse_ip_license": (frozenset({"reverseip"}), _IP),
    "reverse_ip_attribution": (frozenset({"reverseip"}), _IP),
    "reverse_ip_terms_url": (frozenset({"reverseip"}), _IP),
    **{
        f"{check}_state": (frozenset({"dns", "security"}), _DOMAIN)
        for check in (
            "spf",
            "dmarc",
            "dkim",
            "caa",
            "dnssec",
            "mta_sts",
            "tls_rpt",
            "bimi",
        )
    },
}
# rpki_state ends in _state too, and is not one of them.
_SECURITY_FIELDS = tuple(
    name for name in FIELDS if name.endswith("_state") and name != "rpki_state"
)

# Asked for by name only, never in the text block. A bare "risk_level: none"
# or "risk_score: 0" among the other lines reads as a clean bill, which the
# lists cannot give; a script that asks for it knows what it asked for. With
# REPUTATION_ENABLED=false the risk fields and abuse_score read "-", and
# abuse_score does without ABUSEIPDB_API_KEY too.
# resolution stays out too: the block already says "?" where it matters, and
# "resolution: ok" is one more line for every reader to skip.
# reverse_dns_confirmed is left out for its cost: in the block, every IP lookup
# would pay for the sweep of its PTR name, which nothing else there reads.
# dmarc_policy needs the record sweep, which the block is built to skip.
# The DNS security states need the sweep and about 17 more queries.
# The reverse IP fields are by name too: they need the OpenINTEL database, and
# a bare "reverse_ip_total: 0" among the block's lines reads as "no domains".
_REVERSE_IP_DATA = (
    "reverse_ip_total",
    "reverse_ip_names",
    "reverse_ip_block_addresses",
    "reverse_ip_block_names",
)
_REVERSE_IP_LICENCE = (
    "reverse_ip_license",
    "reverse_ip_attribution",
    "reverse_ip_terms_url",
)
_RISK_FIELDS = ("risk_level", "risk_signals", "risk_score")
_NOT_IN_BLOCK = frozenset(
    {
        *_RISK_FIELDS,
        "abuse_score",
        "resolution",
        "reverse_dns_confirmed",
        "dmarc_policy",
        *_SECURITY_FIELDS,
        *_REVERSE_IP_DATA,
        *_REVERSE_IP_LICENCE,
    }
)

# viewmodel.fcrdns_state()'s two answers. "no_ptr" is "-" (there is no PTR to
# confirm) and "unknown" is "?": the PTR name's A/AAAA query failed.
_FCRDNS_ANSWERS = frozenset({"confirmed", "unconfirmed"})
_FCRDNS_FAILED = "the PTR name's A/AAAA query failed"

_ROUTE_FIELDS = ("route_prefix", "route_origin", "rpki_state")

_REGISTRATION_FIELDS = ("registrar", "registrant", "domain_expires", "domain_age_days")

# The legs that ask about the name, never the address it resolves to: the
# registry (whois), the record sweep (dns) and the DNS security checks
# (security), whose answers each carry their own status. A gating A query
# that failed leaves their answers standing; every other leg reads the
# address, and is unknown without one.
_NAME_LEGS = frozenset({"whois", "dns", "security"})

# Text placeholders. "-" is an answer: there is no such value, or the field
# does not apply to this target. "?" is not: the lookup behind the value
# failed, so whether there is one is unknown. field_values() tells them apart:
# a registration lookup that broke, a gating A query that ended in a
# managers.DNS_FAILURES status (every field read from the address), a TLS leg
# that read no certificate (the cert_* fields), a reputation list that could
# not be checked, and the PTR name's A/AAAA query behind reverse_dns_confirmed
# when it ended in one of those statuses. nxdomain and noanswer are answers:
# they stay "-", and for reverse_dns_confirmed they are "unconfirmed".
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
    # Names from OpenINTEL travel with their licence lines: asking for any of
    # the data fields appends the ones not already asked for, at the end.
    if any(name in _REVERSE_IP_DATA for name in names):
        names += [name for name in _REVERSE_IP_LICENCE if name not in names]
    return names


def block_fields(kind: str, *, as_info: bool) -> list[str]:
    """The keys of the text block for a target of `kind` ("domain" or "ip").
    The route fields are among them only with `as_info`, AS information on
    (main passes asinfo_manager.enabled): off, nothing reads them, and a "-"
    would read as "not announced". Asked for by name they still read "-", as
    the risk fields do with the reputation lists off."""
    left_out = _NOT_IN_BLOCK if as_info else _NOT_IN_BLOCK | set(_ROUTE_FIELDS)
    return [
        name
        for name, (_, kinds) in FIELDS.items()
        if kind in kinds and name not in left_out
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
    domain = data.get("domain") or {}
    dmarc = dmarc_policy(domain) or {}
    security = data.get("dns_security") or {}
    as_info = data.get("as_info")
    reverse_ip = compact_reverse_ip(data.get("reverse_ip")) or {}
    block = reverse_ip.get("block") or {}
    route = (as_info or {}).get("route") or {}
    # The origin the card describes: the one seen by the most RIS peers.
    origins = route.get("origins") or []
    origin = next(
        (o for o in origins if o.get("asn") == (as_info or {}).get("asn")),
        origins[0] if origins else {},
    )
    fcrdns = fcrdns_state(
        data.get("reverse_dns"), data.get("domain"), data.get("address") or ""
    )
    values = {
        "target": data.get("address"),
        "ip": data.get("resolved_ip"),
        "resolution": data.get("resolution"),
        "reverse_dns": data.get("reverse_dns"),
        "reverse_dns_confirmed": fcrdns if fcrdns in _FCRDNS_ANSWERS else None,
        "country_code": geo["country_code"],
        "country_name": geo["country_name"],
        "city": geo["city"],
        "asn_number": geo["asn_number"],
        "asn_name": geo["asn_name"],
        "cidr": geo["cidr"],
        "route_prefix": route.get("prefix"),
        "route_origin": origin.get("asn"),
        "rpki_state": (origin.get("rpki") or {}).get("state"),
        "registrar": registration.get("registrar"),
        "registrant": registration.get("registrant"),
        "domain_expires": _date(registration.get("expires")),
        # An IP's registration is its network's, and that block's age is not a
        # domain's: "-" for an IP even when ?fields= also asked for registrant
        # and the record came back.
        "domain_age_days": registration.get("age_days") if kind == "domain" else None,
        "cert_issuer": tls.get("issuer"),
        "cert_expires": tls.get("expires"),
        "cert_days_remaining": tls.get("days_remaining"),
        "cert_age_days": tls.get("age_days"),
        "risk_level": reputation.get("level"),
        # The ids, comma-separated: one value per field is the format.
        "risk_signals": ",".join(s["id"] for s in reputation.get("signals") or []),
        # An int, 0 included. The empty-string filter below must not eat it.
        "risk_score": reputation.get("score"),
        "abuse_score": (reputation.get("abuseipdb") or {}).get("abuse_confidence"),
        "dmarc_policy": dmarc.get("policy"),
        "reverse_ip_total": reverse_ip.get("total"),
        "reverse_ip_names": ",".join(reverse_ip.get("names") or []),
        "reverse_ip_block_addresses": block.get("addresses"),
        "reverse_ip_block_names": block.get("names"),
        "reverse_ip_license": reverse_ip.get("license"),
        "reverse_ip_attribution": reverse_ip.get("attribution"),
        "reverse_ip_terms_url": reverse_ip.get("terms_url"),
        **{
            name: (security.get(name.removesuffix("_state")) or {}).get("state")
            for name in _SECURITY_FIELDS
        },
    }
    # The certificate helpers answer the page, which shows an em dash for
    # "none"; and a field that does not apply to the target is "-" whatever the
    # lookup left in the dict (an IP's resolution is "literal").
    values = {
        name: None
        if value == "" or value == DASH or kind not in FIELDS[name][1]
        else value
        for name, value in values.items()
    }
    errors: dict[str, str] = {}
    # The gating A query failed (timeout, SERVFAIL, an error dnspython could
    # not name: the keys of DNS_FAILURE_TEXT, viewmodel's mirror of
    # managers.DNS_FAILURES), so the name has no address to go on: the address,
    # GeoIP, the certificate and the reputation are unknown, not empty. Chosen
    # by leg, so a field added to FIELDS later follows the rule: every field
    # that needs a leg reading the address (any but _NAME_LEGS) and applies to
    # the target. resolution itself is the reason and stays readable. nxdomain
    # and noanswer are answers, and reach here as "-".
    resolution = data.get("resolution")
    if resolution in DNS_FAILURE_TEXT:
        for name, (legs, kinds) in FIELDS.items():
            if name != "resolution" and kind in kinds and legs - _NAME_LEGS:
                errors[name] = str(resolution)
    # compact_registration reports "not registered" as registered: false, not
    # as an error, so only a lookup that broke lands here. A field that does
    # not apply to the target stays "-" whatever happened to the lookup.
    error = registration.get("error")
    for name in _REGISTRATION_FIELDS:
        if error and kind in FIELDS[name][1]:
            errors[name] = str(error)
    # A route dataset that could not be read: whether the address is announced
    # (and its origin's RPKI state) is unknown, not "-". Not announced is an
    # answer and stays "-".
    if as_info is not None:
        unavailable = {
            entry.get("dataset"): entry.get("reason") or "unavailable"
            for entry in as_info.get("unavailable") or []
        }
        if as_info.get("announced") is None:
            family = "ris_v6" if ":" in str(data.get("resolved_ip") or "") else "ris_v4"
            reason = unavailable.get(family) or "the route dataset is unavailable"
            for name in _ROUTE_FIELDS:
                if kind in FIELDS[name][1]:
                    errors[name] = reason
        elif route and not origin.get("rpki") and "rpki" in unavailable:
            errors["rpki_state"] = unavailable["rpki"]
    # No list could be read: the level is unknown, not "none".
    if reputation and reputation.get("level") is None:
        for name in _RISK_FIELDS:
            errors[name] = "no reputation list could be checked"
    # Asked, but AbuseIPDB did not answer: unknown, not "-".
    for entry in reputation.get("could_not_check") or []:
        if entry["list"] == "AbuseIPDB" and kind in FIELDS["abuse_score"][1]:
            errors["abuse_score"] = entry["reason"]
    # No certificate was read: port 443 never answered, the handshake never
    # completed, or the host is IPv6-only and this server has no route to try
    # (managers.TLS_SKIPPED_IPV6). Whether there is one is unknown, so every
    # tls field is "?", worded as the MCP ssl_certificate tool words it
    # (compact_ssl already built it). None from get_ssl_info -- no address, so
    # no handshake was attempted -- is not in `tls` at all and stays "-".
    tls_error = tls.get("error")
    if tls_error:
        for name, (legs, kinds) in FIELDS.items():
            if "tls" in legs and kind in kinds:
                errors[name] = str(tls_error)
    # The PTR name's A/AAAA query failed: whether it points back is unknown,
    # which "unconfirmed" would misstate.
    if fcrdns == "unknown" and kind in FIELDS["reverse_dns_confirmed"][1]:
        errors["reverse_dns_confirmed"] = _FCRDNS_FAILED
    # The _dmarc query failed: the policy is unknown, not "-". nxdomain and
    # noanswer are answers -- the name publishes none -- and stay "-". A
    # failed A query does not reach this field: the sweep asks about the name
    # (_NAME_LEGS), so its answer stands.
    dmarc_status = (domain.get("status") or {}).get("dmarc")
    if dmarc_status in DNS_FAILURE_TEXT and kind in FIELDS["dmarc_policy"][1]:
        errors["dmarc_policy"] = dmarc_status
    # The answer could not be read: the four data fields are unknown, not "-".
    # The licence lines are text and keep their values.
    if reverse_ip and reverse_ip.get("total") is None:
        reason = (
            "; ".join(
                f"{item['source']}: {item['reason']}"
                for item in reverse_ip.get("unavailable") or []
            )
            or "unavailable"
        )
        for name in _REVERSE_IP_DATA:
            if kind in FIELDS[name][1]:
                errors[name] = reason
    # The JSON says null beside the reason, never a policy.
    if "dmarc_policy" in errors:
        values["dmarc_policy"] = None
    # A check that could not be decided is "?", with its summary as the reason.
    for name in _SECURITY_FIELDS:
        result = security.get(name.removesuffix("_state")) or {}
        if result.get("state") == "unknown" and kind in FIELDS[name][1]:
            errors[name] = result.get("summary") or "unknown"
            values[name] = None
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


# The /AS<n> text block: the card's scalars and the upstream list, in this
# order, each with the asinfo datasets it reads. A value is "?" when one of
# them could not be used (the card's `unavailable`), "-" when they were read
# and hold nothing for this AS. ?fields= does not apply: the field table above
# is an address's and a domain's.
_AS_BLOCK = (
    ("asn", ()),
    ("name", ("asnames",)),
    ("country", ("asnames",)),
    ("rir", ("nro",)),
    ("assigned", ("nro",)),
    ("org", ("caida_org",)),
    ("prefixes_v4", ("ris_v4", "ris_v6")),
    ("prefixes_v6", ("ris_v4", "ris_v6")),
    ("rpki_valid", ("rpki", "ris_v4", "ris_v6")),
    ("rpki_invalid", ("rpki", "ris_v4", "ris_v6")),
    ("rpki_not_found", ("rpki", "ris_v4", "ris_v6")),
    ("upstreams", ("caida_rel",)),
    ("downstreams", ("caida_rel",)),
    ("peers", ("caida_rel",)),
    ("asn_drop", ()),
)


def as_block(as_info: dict) -> str:
    """GET /AS<n>?format=text: `key: value` lines from as_info_for_asn's card.

    The upstreams are AS numbers, space-separated; downstreams and peers are
    counts. asn_drop is "true" or "false", "?" when Spamhaus's list was not
    read (off, stale or never downloaded). A special-purpose number is its
    code, its range (AS64512-AS65534, or AS23456 alone), the document that
    defines it and its purpose: nothing was read for it."""
    special = as_info.get("special")
    if special:
        first, last = special.get("first"), special.get("last")
        values = {
            "asn": as_info.get("asn"),
            "special": special.get("code"),
            "range": f"AS{first}" if first == last else f"AS{first}-AS{last}",
            "defined_in": special.get("defined_in"),
            "purpose": special.get("purpose"),
        }
        return render_block(list(values), values, {})
    registry = as_info.get("registry") or {}
    org = as_info.get("org") or {}
    prefixes = as_info.get("prefixes") or {}
    rpki = as_info.get("rpki") or {}
    upstreams = as_info.get("upstreams") or []
    listed = as_info.get("asn_drop")
    values = {
        "asn": as_info.get("asn"),
        "name": as_info.get("name"),
        "country": as_info.get("country"),
        "rir": registry.get("rir"),
        "assigned": registry.get("assigned"),
        "org": org.get("name") or org.get("id"),
        "prefixes_v4": prefixes.get("v4"),
        "prefixes_v6": prefixes.get("v6"),
        "rpki_valid": rpki.get("valid"),
        "rpki_invalid": rpki.get("invalid"),
        "rpki_not_found": rpki.get("not_found"),
        "upstreams": " ".join(str(entry.get("asn")) for entry in upstreams) or None,
        "downstreams": (as_info.get("downstreams") or {}).get("count"),
        "peers": (as_info.get("peers") or {}).get("count"),
        "asn_drop": None if listed is None else str(listed).lower(),
    }
    unavailable = {
        entry.get("dataset"): entry.get("reason") or "unavailable"
        for entry in as_info.get("unavailable") or []
    }
    errors = {}
    for name, datasets in _AS_BLOCK:
        for dataset in datasets:
            if dataset in unavailable:
                errors[name] = unavailable[dataset]
                break
    if listed is None:
        errors["asn_drop"] = "the ASN-DROP list could not be checked"
    return render_block([name for name, _ in _AS_BLOCK], values, errors)
