"""The lookup page's status cards: one per section, each a value, a line under
it and a state, decided from the response dict.

Pure, like viewmodel.py: no I/O, and no import of lookup, main, managers,
dnssecurity or asinfo. What those modules own is mirrored here and pinned by a
test (tests/test_overview.py).

A card is {id, label, value, sub, state, href}. `state` is one of STATES;
`unknown` is never `pass` (a question that could not be asked has no good
answer), and reputation is never `pass` either, since "no signals" on a few
lists is not a clean bill. `href` is the section the card scrolls to.
"""

from __future__ import annotations

from typing import Any

import viewmodel
from viewmodel import DASH

STATES = ("pass", "warn", "danger", "info", "unknown", "request", "pending")

# dnssecurity's DKIM summary when no key sits at any common selector. DNS
# cannot list selectors, so that is not a finding about the domain.
DKIM_NOT_FOUND = "DKIM: not found at the common selectors"

# The checks the security card counts. MTA-STS, TLS-RPT and BIMI are opt-ins
# whose absence is `info`, and stay on the page's section, not in the count.
GRADED_CHECKS = ("spf", "dmarc", "dkim", "caa", "dnssec")

# managers.DNS_FAILURES, mirrored because managers loads dnspython and the
# GeoIP readers.
_DNS_FAILURES = frozenset({"timeout", "servfail", "error"})

# The record types the DNS card counts, as the section's own hint does. The
# sweep's other statuses (ptr, cname, dmarc, spf) say nothing about whether
# these records could be read.
_DNS_COUNTED = (
    ("A", "a"),
    ("AAAA", "aaaa"),
    ("MX", "mx"),
    ("NS", "ns"),
    ("TXT", "txt"),
)

_SSL_STATES = {"danger": "danger", "warning": "warn", "success": "pass"}
_RPKI_STATES = {"valid": "pass", "invalid": "danger", "not-found": "info"}
_REPUTATION_STATES = {"none": "info", "low": "warn", "medium": "warn", "high": "danger"}


def _card(
    card_id: str, label: str, value: str, sub: str, state: str, **extra: Any
) -> dict:
    return {
        "id": card_id,
        "label": label,
        "value": value,
        "sub": sub,
        "state": state,
        "href": f"#sec-{card_id}",
        **extra,
    }


def _age_text(days: int) -> str:
    if days >= 365:
        years = days // 365
        return f"{years} year{'' if years == 1 else 's'}"
    return viewmodel._days(days)


def registration_card(whois: dict | None, is_ip: bool) -> dict:
    """The registration: a domain's age, an address block's allocation."""
    label = "Allocation" if is_ip else "Registration"
    if viewmodel.whois_pending(whois):
        return _card("whois", label, "loading", "", "pending")
    whois = whois or {}
    error = whois.get("error")
    if error == viewmodel.NOT_REGISTERED:
        return _card("whois", label, "no record", "not registered", "info")
    if error or not whois:
        return _card("whois", label, "?", "lookup failed", "unknown")
    if whois.get("thin"):
        return _card("whois", label, "no details", "no details over WHOIS", "info")
    created, _ = viewmodel.registration_age(whois)
    value = DASH if created is None else _age_text(created)
    who = whois.get("registrar") or whois.get("registrant")
    expires = viewmodel._whois_value("expires", whois.get("expires"))[:10]
    parts = [who, None if expires == DASH else f"expires {expires}"]
    sub = " · ".join(part for part in parts if part)
    if viewmodel._status_tags(whois):
        state = "danger"
    elif viewmodel._young_domain_tag(whois):
        state = "warn"
    else:
        state = "info"
    return _card("whois", label, value, sub, state)


def dns_card(domain: dict | None) -> dict:
    """The record sweep: how many records, or why there are none to count."""
    domain = domain or {}
    if viewmodel.dns_banner(domain):
        return _card("dns", "DNS", "does not exist", "NXDOMAIN", "danger")
    status = domain.get("status") or {}
    counts = [(label, len(domain.get(key) or [])) for label, key in _DNS_COUNTED]
    sub = " · ".join(f"{label} {n}" for label, n in counts)
    value = f"{sum(n for _, n in counts)} records"
    if any(status.get(key) in _DNS_FAILURES for _, key in _DNS_COUNTED):
        return _card("dns", "DNS", value, sub, "unknown")
    if status.get("a") == "noanswer" and status.get("aaaa") == "noanswer":
        return _card("dns", "DNS", value, sub, "info")
    return _card("dns", "DNS", value, sub, "pass")


def security_card(dns_security: dict | None) -> dict | None:
    """SPF, DMARC, DKIM, CAA and DNSSEC as passes out of answers."""
    if dns_security is None:
        return None
    label = "DNS security"
    checks = list(dns_security.values())
    if (
        checks
        and all(check.get("state") == "unknown" for check in checks)
        and all(
            str(check.get("summary", "")).endswith("not checked") for check in checks
        )
    ):
        return _card("security", label, "?", "not checked", "unknown")
    kept = {name: dns_security[name] for name in GRADED_CHECKS if name in dns_security}
    dkim_dropped = (kept.get("dkim") or {}).get("summary") == DKIM_NOT_FOUND
    if dkim_dropped:
        del kept["dkim"]
    kept = {name: c for name, c in kept.items() if c.get("state") != "info"}
    states = [check.get("state") for check in kept.values()]
    review = states.count("fail") + states.count("warn")
    if "fail" in states:
        state = "danger"
    elif "warn" in states:
        state = "warn"
    elif "unknown" in states:
        state = "unknown"
    else:
        state = "pass"
    answered = len(states) - states.count("unknown")
    value = f"{states.count('pass')} / {answered}" + (
        " · DKIM ?" if dkim_dropped else ""
    )
    if review:
        sub = f"{review} to review"
    elif "unknown" in states:
        sub = "some checks did not run"
    else:
        sub = "graded checks pass"
    return _card("security", label, value, sub, state)


def certificate_card(ssl: dict | None) -> dict:
    """The served certificate: days left, or what is wrong with it."""
    label = "Certificate"
    if not ssl:
        return _card("ssl", label, "none", "no handshake", "info")
    if ssl.get("error"):
        return _card("ssl", label, "?", str(ssl["error"]), "unknown")
    text, tone = viewmodel._ssl_status(ssl)
    state = _SSL_STATES.get(tone, "info")
    _, days_left = viewmodel._cert_expiry(ssl)
    if viewmodel._ssl_problem(ssl):
        value = text
    elif days_left is None:
        value = DASH
    else:
        value = f"{days_left}d left"
    return _card("ssl", label, value, viewmodel._cert_issuer(ssl), state)


def _rpki_state(as_info: dict) -> str | None:
    """The RPKI state of the route's origin that is the card's AS."""
    origins = (as_info.get("route") or {}).get("origins") or []
    for origin in origins:
        if origin.get("asn") == as_info.get("asn"):
            return (origin.get("rpki") or {}).get("state")
    return None


def network_card(
    location: dict | None,
    as_info: dict | None,
    card_id: str = "network",
    label: str = "Network",
) -> dict:
    """The address's AS, its holder, RPKI state and country."""
    location = location or {}
    as_info = as_info or {}
    asn = as_info.get("asn") or location.get("asn_number")
    value = f"AS{asn}" if asn else DASH
    if not as_info:
        state = "info"
    elif as_info.get("announced") is False:
        return _card(card_id, label, value, "not announced", "info")
    else:
        rpki = _rpki_state(as_info)
        state = _RPKI_STATES.get(rpki, "info")
        ris_missing = any(
            entry.get("dataset") in ("ris_v4", "ris_v6")
            for entry in as_info.get("unavailable") or []
        )
        if as_info.get("route") is None and ris_missing:
            state = "unknown"
    name = viewmodel.as_holder(as_info.get("name")) or location.get("asn_name")
    country = location.get("country_code") or as_info.get("country")
    rpki_word = (
        f"RPKI {_rpki_state(as_info)}" if as_info and _rpki_state(as_info) else None
    )
    sub = " · ".join(part for part in (name, rpki_word, country) if part)
    return _card(card_id, label, value, sub, state)


def reputation_card(reputation: dict | None) -> dict | None:
    """The lists' score. Never `pass`: not being listed is not a clean bill."""
    if reputation is None:
        return None
    score = reputation.get("score")
    level = reputation.get("level")
    value = "?" if score is None else f"{score} / 100"
    return _card(
        "reputation",
        "Reputation",
        value,
        viewmodel._level_text(level),
        _REPUTATION_STATES.get(level, "unknown"),
    )


def domain_cards(response: dict) -> list[dict]:
    """The domain page's cards in page order; one with nothing to say is left out."""
    cards = [
        registration_card(response.get("whois"), is_ip=False),
        dns_card(response.get("domain")),
        security_card(response.get("dns_security")),
        certificate_card(response.get("ssl")),
        network_card(response.get("location"), response.get("as_info")),
        reputation_card(response.get("reputation")),
    ]
    return [card for card in cards if card is not None]
