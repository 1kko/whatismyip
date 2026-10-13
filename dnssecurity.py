"""A domain's DNS security posture: SPF, DMARC, DKIM, CAA, DNSSEC, MTA-STS,
TLS-RPT and BIMI, each graded pass, warn, fail, info or unknown.

fetch() asks the public resolvers what the record sweep
(DomainManager.get_records) does not; evaluate() is pure and grades fetch()'s
answers together with the sweep's SPF and DMARC records, so nothing is asked
twice. A query that failed makes a check unknown, never fail: "could not find
out" is not "not set up".

Must not import lookup or main (lookup imports this).
"""

import base64
import binascii
import re

from cryptography.hazmat.primitives.serialization import load_der_public_key

from managers import DNS_FAILURES
from viewmodel import _parse_dmarc, dmarc_policy

CHECKS = ("spf", "dmarc", "dkim", "caa", "dnssec", "mta_sts", "tls_rpt", "bimi")
LABELS = {
    "spf": "SPF",
    "dmarc": "DMARC",
    "dkim": "DKIM",
    "caa": "CAA",
    "dnssec": "DNSSEC",
    "mta_sts": "MTA-STS",
    "tls_rpt": "TLS-RPT",
    "bimi": "BIMI",
}
# The TXT records fetch() reads for the three optional mail checks: where, and
# the version tag a record there must open with.
OPTIONAL_TXT = {
    "mta_sts": ("_mta-sts", "v=STSv1"),
    "tls_rpt": ("_smtp._tls", "v=TLSRPTv1"),
    "bimi": ("default._bimi", "v=BIMI1"),
}
_SEVERITY = ("fail", "warn")
_ALL = re.compile(r"^([+\-~?]?)all$", re.IGNORECASE)


def _check(state: str, summary: str, findings=(), **extra) -> dict:
    return {
        "state": state,
        "summary": summary,
        "findings": [{"severity": s, "text": t} for s, t in findings],
        **extra,
    }


def _graded(summary: str, findings: list, **extra) -> dict:
    """pass, or the worst finding's severity."""
    severities = {s for s, _ in findings}
    state = next((s for s in _SEVERITY if s in severities), "pass")
    return _check(state, summary, findings, **extra)


def _unknown(label: str, status: str) -> dict:
    return _check("unknown", f"{label}: query failed ({status})")


def _spf(domain: dict | None) -> dict:
    if domain is None:
        return _check("unknown", "SPF: not checked")
    status = (domain.get("status") or {}).get("spf")
    records = [r["text"] for r in domain.get("spf") or []]
    if not records:
        if status in DNS_FAILURES:
            return _unknown("SPF", status)
        return _check(
            "fail",
            "SPF: no record",
            [("fail", "No v=spf1 record: any server can send mail as this domain.")],
        )
    # get_records() appends the zone's SPF after the name's own, so below the
    # apex a second record is the zone's, not a duplicate.
    at_apex = domain.get("queried_name") == domain.get("zone")
    if at_apex and len(records) > 1:
        return _check(
            "fail",
            f"SPF: {len(records)} records",
            [
                (
                    "fail",
                    "More than one v=spf1 record is a permerror: "
                    "receivers ignore all of them.",
                )
            ],
        )
    text = records[0]
    terms = text.split()[1:]
    findings = []
    all_term = next((t for t in reversed(terms) if _ALL.match(t)), None)
    redirect = any(t.lower().startswith("redirect=") for t in terms)
    if all_term is not None:
        qualifier = _ALL.match(all_term).group(1) or "+"
        if qualifier == "+":
            findings.append(("fail", "+all lets any server send mail as this domain."))
        elif qualifier == "?":
            findings.append(
                ("warn", "?all is neutral: unlisted senders are not rejected.")
            )
        elif qualifier == "~":
            findings.append(
                ("info", "~all soft-fails unlisted senders; -all rejects them.")
            )
    elif not redirect:
        findings.append(("warn", "No all mechanism: unlisted senders are neutral."))
    if any(t.lstrip("+-~?").lower().split(":")[0] == "ptr" for t in terms):
        findings.append(("warn", "The ptr mechanism is deprecated (RFC 7208 §5.5)."))
    summary = (
        f"SPF: {all_term}"
        if all_term
        else ("SPF: redirect" if redirect else "SPF: no all")
    )
    return _graded(summary, findings, record=text)


def _dmarc(domain: dict | None) -> dict:
    if domain is None:
        return _check("unknown", "DMARC: not checked")
    status = (domain.get("status") or {}).get("dmarc")
    records = domain.get("dmarc") or []
    if not records:
        if status in DNS_FAILURES:
            return _unknown("DMARC", status)
        return _check(
            "fail",
            "DMARC: no record",
            [
                (
                    "fail",
                    "No DMARC record: receivers have no policy for "
                    "mail that fails SPF and DKIM.",
                )
            ],
        )
    if len(records) > 1:
        return _check(
            "fail",
            f"DMARC: {len(records)} records",
            [
                (
                    "fail",
                    "More than one DMARC record: receivers ignore "
                    "all of them (RFC 7489 §6.6.3).",
                )
            ],
        )
    policy = dmarc_policy(domain) or {}
    tags = _parse_dmarc(records[0].get("text", ""))
    findings = []
    value = policy.get("policy")
    if value is None:
        findings.append(("warn", "No valid p= tag: receivers treat it as p=none."))
    elif value == "none":
        findings.append(
            (
                "warn",
                f"{policy['tag']}=none asks for reports only: "
                f"failing mail is still delivered.",
            )
        )
    if policy.get("pct"):
        findings.append(
            (
                "warn",
                f"pct={policy['pct']} applies the policy to only part of the mail.",
            )
        )
    if "rua" not in tags:
        findings.append(("warn", "No rua= tag: nobody receives aggregate reports."))
    if policy.get("inherited_from"):
        findings.append(("info", f"Inherited from {policy['inherited_from']}."))
    summary = f"DMARC: {policy['tag']}={value}" if value else "DMARC: no policy"
    if policy.get("inherited_from"):
        summary += f" ({policy['inherited_from']})"
    return _graded(summary, findings, record=records[0].get("text"))


def _dkim_tags(text: str) -> dict[str, str]:
    tags = {}
    for part in text.split(";"):
        name, sep, value = part.partition("=")
        if sep:
            tags.setdefault(name.strip().lower(), value.strip())
    return tags


def _dkim_key(text: str) -> tuple[str, int | None]:
    """("rsa" | "ed25519", bits), ("revoked", None) or ("invalid", None)."""
    tags = _dkim_tags(text)
    if "p" not in tags:
        return "invalid", None
    p = "".join(tags["p"].split())
    if not p:
        return "revoked", None
    try:
        der = base64.b64decode(p, validate=True)
    except (binascii.Error, ValueError):
        return "invalid", None
    if tags.get("k", "rsa").lower() == "ed25519":
        return ("ed25519", 256) if len(der) == 32 else ("invalid", None)
    try:
        key = load_der_public_key(der)
    except (ValueError, TypeError):
        return "invalid", None
    bits = getattr(key, "key_size", None)
    return ("rsa", bits) if bits else ("invalid", None)


def _grade_dkim(raw: dict | None) -> dict:
    if raw is None:
        return _check("unknown", "DKIM: not checked")
    found = raw.get("keys") or []
    if not found:
        status = raw.get("status")
        if status in DNS_FAILURES:
            return _unknown("DKIM", status)
        return _check(
            "unknown",
            "DKIM: not found at the common selectors",
            [
                (
                    "info",
                    "DNS cannot list selectors: a key under another "
                    "selector would not be seen.",
                )
            ],
        )
    keys, findings = [], []
    for entry in found:
        selector = entry["selector"]
        kind, bits = _dkim_key(entry["text"])
        keys.append({"selector": selector, "kind": kind, "bits": bits})
        if kind == "invalid":
            findings.append(("warn", f"{selector}: the key could not be read."))
        elif kind == "rsa" and bits < 1024:
            findings.append(
                ("fail", f"{selector}: {bits}-bit RSA key is too short to trust.")
            )
        elif kind == "rsa" and bits < 2048:
            findings.append(
                ("warn", f"{selector}: {bits}-bit RSA key; 2048 bits is recommended.")
            )
    usable = [k for k in keys if k["kind"] in ("rsa", "ed25519")]
    if not usable and any(k["kind"] == "revoked" for k in keys):
        findings.append(("warn", "Only revoked keys (empty p=) were found."))
    shown = ", ".join(
        f"{k['selector']} ({k['bits']}-bit)"
        if k["kind"] == "rsa"
        else f"{k['selector']} ({k['kind']})"
        for k in keys
    )
    return _graded(f"DKIM: found at {shown}", findings, keys=keys)


def _grade_caa(raw: dict | None) -> dict:
    if raw is None:
        return _check("unknown", "CAA: not checked")
    status = raw.get("status")
    records = raw.get("records") or []
    if status in DNS_FAILURES:
        return _unknown("CAA", status)
    if not records:
        return _check(
            "warn",
            "CAA: none",
            [
                (
                    "warn",
                    "No CAA record: any certificate authority may issue for this name.",
                )
            ],
        )
    issuers = []
    for record in records:
        if record["tag"].lower() in ("issue", "issuewild"):
            issuer = record["value"].split(";")[0].strip()
            if issuer and issuer not in issuers:
                issuers.append(issuer)
    summary = f"CAA: {', '.join(issuers)}" if issuers else "CAA: no CA may issue"
    findings = []
    if raw.get("queried_name"):
        findings.append(("info", f"Published at {raw['queried_name']}."))
    return _graded(
        summary, findings, issuers=issuers, queried_name=raw.get("queried_name")
    )


def _dnssec(raw: dict | None) -> dict:
    if raw is None:
        return _check("unknown", "DNSSEC: not checked")
    zone, ds, dnskey = raw.get("zone"), raw.get("ds"), raw.get("dnskey")
    failed = next((s for s in (ds, dnskey) if s in DNS_FAILURES), None)
    if failed:
        return _check(
            "unknown",
            f"DNSSEC: query failed ({failed})",
            [
                (
                    "info",
                    "A SERVFAIL from a validating resolver can "
                    "mean a broken DNSSEC chain.",
                )
            ]
            if failed == "servfail"
            else [],
        )
    if ds != "ok":
        return _check(
            "warn",
            "DNSSEC: unsigned",
            [
                (
                    "warn",
                    f"No DS record for {zone} at its parent: "
                    f"answers can be forged in transit.",
                )
            ],
            zone=zone,
        )
    if not raw.get("validated"):
        return _check(
            "warn",
            "DNSSEC: signed, not validated",
            [
                (
                    "warn",
                    f"{zone} has a DS record but the resolver "
                    f"did not validate its keys.",
                )
            ],
            zone=zone,
        )
    return _check("pass", "DNSSEC: signed and validated", zone=zone)


def _optional_txt(check: str, raw: dict | None) -> dict:
    label = LABELS[check]
    if raw is None:
        return _check("unknown", f"{label}: not checked")
    prefix = OPTIONAL_TXT[check][1]
    records = [r for r in raw.get("records") or [] if r.split(";")[0].strip() == prefix]
    if records:
        return _check("pass", f"{label}: {records[0]}", record=records[0])
    status = raw.get("status")
    if status in DNS_FAILURES:
        return _unknown(label, status)
    return _check("info", f"{label}: not published")


def evaluate(domain: dict | None, raw: dict | None) -> dict[str, dict]:
    """Every check's verdict, in CHECKS order. `domain` is the record sweep's
    answer (its spf, dmarc and status); `raw` is fetch()'s. Either may be None
    (not run, or broken), and the checks it feeds are then unknown."""
    raw_or = (lambda key: None) if raw is None else raw.get
    return {
        "spf": _spf(domain),
        "dmarc": _dmarc(domain),
        "dkim": _grade_dkim(raw_or("dkim")),
        "caa": _grade_caa(raw_or("caa")),
        "dnssec": _dnssec(raw_or("dnssec")),
        **{check: _optional_txt(check, raw_or(check)) for check in OPTIONAL_TXT},
    }
