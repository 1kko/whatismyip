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

from typing import Any, NamedTuple

import countrynames
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

# managers.NO_COUNTRY, GeoIP's marker for an address no database places (a
# private one among them), mirrored for the same reason. It is no country.
_NO_COUNTRY = "--"

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
    label = "Registration"
    if viewmodel.whois_pending(whois):
        return _card("whois", label, "loading\u2026", "", "pending")
    whois = whois or {}
    error = whois.get("error")
    if error == viewmodel.NOT_REGISTERED:
        return _card("whois", label, "no record", "not registered", "info")
    if error or not whois:
        return _card("whois", label, "?", "lookup failed", "unknown")
    if whois.get("thin"):
        return _card("whois", label, "no details", "no details over WHOIS", "info")
    if is_ip:
        value = whois.get("network") or whois.get("name") or "record found"
        rir = viewmodel._whois_value("rir", whois.get("rir"))
        updated = viewmodel._whois_value("updated", whois.get("updated"))[:10]
        sub = " · ".join(part for part in (rir, updated) if part != DASH)
        return _card("whois", label, str(value), sub, "info")
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
    """The record sweep: how many records, or why there are none to count.
    No sweep at all (lookup._run_legs leaves `domain` None when it raised) is
    a lookup that failed, never "0 records"."""
    if not domain:
        return _card("dns", "DNS", "?", "lookup failed", "unknown")
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


def _not_checked(dns_security: dict) -> bool:
    """The leg raised: every check is `unknown` and says "not checked"."""
    checks = list(dns_security.values())
    return bool(checks) and all(
        check.get("state") == "unknown"
        and str(check.get("summary", "")).endswith("not checked")
        for check in checks
    )


class _SecurityCounts(NamedTuple):
    """What the security card counts, which the sentence reads too."""

    passes: int
    answered: int
    review: int
    dkim_dropped: bool
    state: str


def _security_counts(dns_security: dict) -> _SecurityCounts:
    """GRADED_CHECKS without the `info` ones and without DKIM not found:
    the passes, the checks that answered, the ones to review (a warning or a
    failure), whether DKIM was left out, and the card's state. With nothing
    answered there is nothing to grade, and the state is `unknown`."""
    kept = {name: dns_security[name] for name in GRADED_CHECKS if name in dns_security}
    dkim_dropped = (kept.get("dkim") or {}).get("summary") == DKIM_NOT_FOUND
    if dkim_dropped:
        del kept["dkim"]
    states = [c.get("state") for c in kept.values() if c.get("state") != "info"]
    answered = len(states) - states.count("unknown")
    if "fail" in states:
        state = "danger"
    elif "warn" in states:
        state = "warn"
    elif "unknown" in states or not answered:
        state = "unknown"
    else:
        state = "pass"
    return _SecurityCounts(
        passes=states.count("pass"),
        answered=answered,
        review=states.count("fail") + states.count("warn"),
        dkim_dropped=dkim_dropped,
        state=state,
    )


def security_card(dns_security: dict | None) -> dict | None:
    """SPF, DMARC, DKIM, CAA and DNSSEC as passes out of answers; "?" when
    none answered."""
    if dns_security is None:
        return None
    label = "DNS security"
    if _not_checked(dns_security):
        return _card("security", label, "?", "not checked", "unknown")
    counts = _security_counts(dns_security)
    value = f"{counts.passes} / {counts.answered}" if counts.answered else "?"
    if counts.review:
        sub = f"{counts.review} to review"
    elif counts.state == "unknown":
        sub = "some checks did not run"
    else:
        sub = "graded checks pass"
    # DKIM left out of the count is said beside it, at the front of the sub
    # line: the value stays the bare fraction, which fits a card at 20px.
    if counts.dkim_dropped:
        sub = f"DKIM ? · {sub}"
    return _card("security", label, value, sub, counts.state)


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


def _rpki(as_info: dict) -> dict:
    """The RPKI answer ({state, reason}) of the route's origin that is the
    card's AS; empty when there is none."""
    origins = (as_info.get("route") or {}).get("origins") or []
    for origin in origins:
        if origin.get("asn") == as_info.get("asn"):
            return origin.get("rpki") or {}
    return {}


def _rpki_state(as_info: dict) -> str | None:
    """The RPKI state of the route's origin that is the card's AS."""
    return _rpki(as_info).get("state")


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
    country = next(
        (
            code
            for code in (location.get("country_code"), as_info.get("country"))
            if code and code != _NO_COUNTRY
        ),
        None,
    )
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


def _country_known(location: dict) -> bool:
    """Whether GeoIP placed the address in a country: a code, and not "--"."""
    code = location.get("country_code")
    return bool(code) and code != _NO_COUNTRY


def location_card(location: dict | None) -> dict:
    """Where GeoIP puts the address: a city only when the fix is city-precise.
    With no country (a private address, or one no database places) the card
    is `unknown` and says nothing under its value."""
    location = location or {}
    country = location.get("country_name") or ""
    city = location.get("city_name")
    if location.get("precision") == "city" and city:
        value = city
    else:
        value = country or "?"
        city = None
    if not _country_known(location):
        return _card("location", "Location", value, "", "unknown")
    accuracy = location.get("accuracy_km")
    if city and accuracy is not None:
        reach = f"\u00b1{accuracy} km"
    elif city:
        reach = None
    else:
        reach = "country-level"
    sub = " \u00b7 ".join(part for part in (country if city else None, reach) if part)
    return _card("location", "Location", value, sub, "info")


_FCRDNS_WORDS = {"confirmed": "confirmed", "unconfirmed": "does not point back"}


def domains_card(
    location: dict | None,
    domain: dict | None,
    reverse_ip: dict | None,
    address: str,
) -> dict:
    """The address's PTR name and, while the feature is on, the listed names."""
    ptr = (location or {}).get("reverse_dns")
    parts = []
    word = _FCRDNS_WORDS.get(viewmodel.fcrdns_state(ptr, domain, address))
    if word:
        parts.append(word)
    total = (reverse_ip or {}).get("total")
    unknown_total = reverse_ip is not None and total is None
    if isinstance(total, int) and not isinstance(total, bool):
        parts.append(f"{total:,} listed names")
    elif unknown_total:
        parts.append("listed names unknown")
    state = "unknown" if not ptr and unknown_total else "info"
    return _card("domains", "Domains", ptr or "no PTR", " \u00b7 ".join(parts), state)


def ip_cards(response: dict) -> list[dict]:
    """The IP and self pages' cards in page order; one with nothing to say is
    left out."""
    location = response.get("location")
    cards = [
        location_card(location),
        network_card(
            location,
            response.get("as_info"),
            card_id="organization",
            label="Organization",
        ),
        domains_card(
            location,
            response.get("domain"),
            response.get("reverse_ip"),
            response.get("address") or "",
        ),
        reputation_card(response.get("reputation")),
        registration_card(response.get("whois"), is_ip=True),
    ]
    return [card for card in cards if card is not None]


_DOMAIN_ORDER = ("whois", "dns", "security", "ssl", "network", "reputation")
_IP_ORDER = ("location", "organization", "domains", "reputation", "whois")


def _chip(text: str, section: str, tone: str) -> dict:
    return {"text": text, "section": section, "tone": tone}


def reputation_chips(reputation: dict | None, is_ip: bool) -> list[dict]:
    """One chip naming the lists an address is on, when the level is low or
    above. A domain keeps only the signals that carry weight, as its hero
    tags do: a datacenter listing says nothing about a website."""
    reputation = reputation or {}
    tone = viewmodel._LEVEL_TONES.get(reputation.get("level"))
    if tone is None:
        return []
    signals = [
        s for s in reputation.get("signals") or [] if is_ip or s.get("weight", 0) > 0
    ]
    if not signals:
        return []
    names = ", ".join(viewmodel._signal_name(s) for s in signals)
    return [_chip(f"on {names}", "reputation", tone)]


def review_chips(response: dict, is_ip: bool) -> list[dict]:
    """The "To review" chips: findings only, ordered by the page's sections.
    An unknown, a failed query, DKIM not found and an `info` check are never
    chips: they are gaps, not findings."""
    chips: list[dict] = []
    if not is_ip:
        for check in (response.get("dns_security") or {}).values():
            tone = {"warn": "warning", "fail": "danger"}.get(check.get("state"))
            if tone:
                chips.append(_chip(str(check.get("summary", "")), "security", tone))
        whois = response.get("whois")
        for tag in viewmodel._status_tags(whois):
            chips.append(_chip(tag["text"], "whois", "danger"))
        if viewmodel._young_domain_tag(whois):
            created, _ = viewmodel.registration_age(whois)
            chips.append(
                _chip(f"registered {viewmodel._ago(created)}", "whois", "warning")
            )
        ssl = response.get("ssl")
        if ssl and not ssl.get("error"):
            _, tone = viewmodel._ssl_status(ssl)
            if tone == "danger":
                chips.append(_chip(f"TLS {viewmodel._ssl_problem(ssl)}", "ssl", tone))
            elif tone == "warning":
                _, days_left = viewmodel._cert_expiry(ssl)
                chips.append(_chip(f"certificate: {days_left}d left", "ssl", tone))
    as_info = response.get("as_info") or {}
    rpki = _rpki(as_info) if as_info.get("announced") is not False else {}
    if rpki.get("state") == "invalid":
        reason = rpki.get("reason")
        text = "RPKI invalid" + (f" ({reason})" if reason else "")
        chips.append(_chip(text, "organization" if is_ip else "network", "danger"))
    chips.extend(reputation_chips(response.get("reputation"), is_ip))
    order = _IP_ORDER if is_ip else _DOMAIN_ORDER
    return sorted(chips, key=lambda c: order.index(c["section"]))


def _seg(text: str, strong: bool = False, tone: str | None = None) -> dict:
    return {"text": text, "strong": strong, "tone": tone}


def _join_segments(clauses: list[list[dict]]) -> list[dict]:
    """Clauses read as a list: "A", "A and B", "A, B, and C"."""
    out: list[dict] = []
    for index, clause in enumerate(clauses):
        if index:
            last = index == len(clauses) - 1
            if not last:
                joiner = ", "
            else:
                joiner = " and " if len(clauses) == 2 else ", and "
            out.append(_seg(joiner))
        out.extend(clause)
    return out


def _organization(response: dict) -> str | None:
    """ "Automattic, Inc (AS2635)": the AS card's holder, else GeoLite2's
    name, with the number when there is one."""
    location = response.get("location") or {}
    as_info = response.get("as_info") or {}
    name = viewmodel.as_holder(as_info.get("name")) or location.get("asn_name")
    asn = as_info.get("asn") or location.get("asn_number")
    if name and asn:
        return f"{name} (AS{asn})"
    if name:
        return str(name)
    return f"AS{asn}" if asn else None


def _country_in_text(location: dict) -> str | None:
    """The country as running English writes it ("the United States",
    countrynames.country_name_in_text); GeoLite2's own name when there is no
    code the table knows, and None for "--"."""
    code = location.get("country_code")
    if code == _NO_COUNTRY:
        return None
    if code and code.upper() in countrynames.COUNTRY_NAMES:
        return countrynames.country_name_in_text(code)
    return location.get("country_name") or None


def _place(location: dict | None, with_country: bool = True) -> str | None:
    location = location or {}
    country = _country_in_text(location)
    city = location.get("city_name")
    if location.get("precision") == "city" and city:
        return f"{city}, {country}" if country and with_country else str(city)
    return country or None


def _registration_sentence(name: str, whois: dict | None) -> list[dict]:
    """ "nasa.gov has been registered through get.gov for 29 years."; empty
    when the record is missing, failed, pending or has no readable date."""
    if not whois or whois.get("error") or whois.get("thin"):
        return []
    created, _ = viewmodel.registration_age(whois)
    if created is None:
        return []
    who = whois.get("registrar") or whois.get("registrant")
    tone = "warning" if viewmodel._young_domain_tag(whois) else None
    through = f" through {who}" if who else ""
    return [
        _seg(name, True),
        _seg(f" has been registered{through} for "),
        _seg(_age_text(created), True, tone),
        _seg("."),
    ]


def _resolve_clause(response: dict) -> list[dict] | None:
    domain = response.get("domain") or {}
    ip = response.get("resolved_ip")
    for key in ("a", "aaaa"):
        if not ip and domain.get(key):
            ip = domain[key][0].get("ip")
    if not ip:
        status = domain.get("status") or {}
        if status.get("a") == "noanswer" and status.get("aaaa") == "noanswer":
            return [_seg("has no address record")]
        return None
    clause = [_seg("resolves to "), _seg(str(ip), True)]
    org = _organization(response)
    place = _place(response.get("location"), with_country=False)
    if org:
        clause.append(_seg(f" at {org}"))
    if place:
        clause.append(_seg(f" in {place}"))
    return clause


def _certificate_clause(ssl: dict | None) -> list[dict] | None:
    if not ssl or ssl.get("error"):
        return None
    problem = viewmodel._ssl_problem(ssl)
    if problem == "expired":
        return [_seg("serves an "), _seg(problem, True, "danger"), _seg(" certificate")]
    if problem:
        # Every other problem is why verification failed (hostname mismatch,
        # untrusted root, ...), a noun phrase, so it goes in brackets.
        return [
            _seg("serves a certificate that fails verification ("),
            _seg(problem, True, "danger"),
            _seg(")"),
        ]
    issuer = viewmodel._cert_issuer(ssl)
    kind = "a valid certificate" if issuer == DASH else f"a valid {issuer} certificate"
    _, days_left = viewmodel._cert_expiry(ssl)
    clause = [_seg(f"serves {kind}")]
    if days_left is not None:
        tone = "warning" if viewmodel._ssl_status(ssl)[1] == "warning" else None
        clause += [_seg(" with "), _seg(viewmodel._days(days_left), True, tone)]
        clause.append(_seg(" left"))
    return clause


def _security_clause(dns_security: dict | None) -> list[dict] | None:
    """ "passes 3 of 5 graded DNS security checks", from the counts the card
    shows; none when the card is absent or `unknown`, since a fraction of the
    checks that answered would read as the whole result."""
    if dns_security is None or _not_checked(dns_security):
        return None
    counts = _security_counts(dns_security)
    if counts.state == "unknown":
        return None
    tone = "warning" if counts.state in ("warn", "danger") else None
    noun = "check" if counts.answered == 1 else "checks"
    return [
        _seg("passes "),
        _seg(f"{counts.passes} of {counts.answered}", True, tone),
        _seg(f" graded DNS security {noun}"),
    ]


def _domain_sentence(response: dict) -> list[dict]:
    domain = response.get("domain") or {}
    name = response.get("address") or domain.get("queried_name") or ""
    if viewmodel.dns_banner(domain):
        return [_seg(name, True), _seg(" does not resolve.")]
    out = _registration_sentence(name, response.get("whois"))
    clauses = [
        _resolve_clause(response),
        _certificate_clause(response.get("ssl")),
        _security_clause(response.get("dns_security")),
    ]
    clauses = [clause for clause in clauses if clause]
    if not clauses:
        return out
    if out:
        out.append(_seg(" "))
        out.append(_seg("It "))
    else:
        out.append(_seg(name, True))
        out.append(_seg(" "))
    return out + _join_segments(clauses) + [_seg(".")]


def _ip_sentence(response: dict) -> list[dict]:
    location = response.get("location") or {}
    out = [_seg(str(response.get("address") or ""), True), _seg(" is an address")]
    org = _organization(response)
    # No place for an address GeoIP put in no country: its Location card is
    # `unknown`, and "in Private network" is not a place.
    place = _place(location) if _country_known(location) else None
    if org:
        out.append(_seg(f" of {org}"))
    if place:
        out.append(_seg(f" in {place}"))
    out.append(_seg("."))
    ptr = location.get("reverse_dns")
    total = (response.get("reverse_ip") or {}).get("total")
    listed = isinstance(total, int) and not isinstance(total, bool) and total > 0
    if ptr:
        # Without the root dot a PTR answer ends with: the sentence's own
        # full stop follows the name.
        name = str(ptr).rstrip(".") or str(ptr)
        out += [_seg(" Its reverse DNS name is "), _seg(name, True)]
    if listed:
        noun = "name" if total == 1 else "names"
        verb = "points" if total == 1 else "point"
        out += [
            _seg(" and " if ptr else " "),
            _seg(f"{total:,} {noun}", True),
            _seg(f" on public top lists {verb} to it"),
        ]
    if ptr or listed:
        out.append(_seg("."))
    return out


def sentence(response: dict, is_ip: bool) -> list[dict]:
    """The page's summary sentence as segments {text, strong, tone}; the
    template joins the texts and wraps the strong ones. A clause whose data is
    missing or failed is left out rather than written as a gap, and a failing
    check never gets a positive verb."""
    return _ip_sentence(response) if is_ip else _domain_sentence(response)


# The sections that have no card. Subdomains and Raw JSON hold nothing until
# the visitor asks; "Your browser" measures nothing until "Measure" is pressed.
# static/js/fingerprint.js turns the browser's dots to `info` once measured,
# and static/js/app.js the other two once their data is shown.
_REQUEST_SECTIONS = frozenset({"subdomains", "raw", "browser"})


def section_state(
    section_id: str, states: dict[str, str], response: dict | None = None
) -> str:
    """A section's dot: its card's state, else `request` for a section that
    is fetched or measured on request, else `info`. The Subdomains section of
    a page that carries the list (?subdomains=include) is data, `info`, or
    `unknown` when neither crt.sh nor the top lists answered."""
    if section_id in states:
        return states[section_id]
    subdomains = (response or {}).get("subdomains")
    if section_id == "subdomains" and subdomains:
        found = viewmodel.subdomain_found_count(subdomains)
        return "unknown" if found is None else "info"
    return "request" if section_id in _REQUEST_SECTIONS else "info"


def build(response: dict) -> dict:
    """Everything the overview block renders: sentence, chips, cards and each
    card's state by id."""
    is_ip = viewmodel._is_ip(response.get("address") or "")
    cards = ip_cards(response) if is_ip else domain_cards(response)
    return {
        "sentence": sentence(response, is_ip),
        "chips": review_chips(response, is_ip),
        "cards": cards,
        "states": {card["id"]: card["state"] for card in cards},
    }
