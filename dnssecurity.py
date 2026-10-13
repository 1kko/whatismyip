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
from concurrent.futures import ThreadPoolExecutor

import dns.flags
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

import managers
from config import DKIM_SELECTORS
from managers import DNS_FAILURES, dns_status
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
    status = domain.get("status") or {}
    entries = domain.get("spf") or []
    # SPF is checked for the exact MAIL FROM / HELO name (RFC 7208 §4): the
    # zone's record, which get_records() appends marked from_zone, says
    # nothing about mail from a name below it.
    records = [r["text"] for r in entries if not r.get("from_zone")]
    zone_has_spf = any(r.get("from_zone") for r in entries)
    if not records:
        # The name's own TXT query; "spf" for a sweep that has no "txt".
        own_status = status.get("txt", status.get("spf"))
        if own_status in DNS_FAILURES:
            return _unknown("SPF", own_status)
        zone = domain.get("zone")
        below_apex = zone and domain.get("queried_name") != zone
        own_mx = any(not m.get("from_zone") for m in domain.get("mx") or [])
        if below_apex and not own_mx:
            # A host that receives no mail of its own (www, api) is rarely
            # used as a sender either: worth knowing, not a failure.
            note = (
                f"No v=spf1 record for this name; {zone} has one, but SPF is "
                "not inherited."
                if zone_has_spf
                else "No v=spf1 record for this name."
            )
            return _check("info", "SPF: none for this name", [("info", note)])
        return _check(
            "fail",
            "SPF: no record",
            [("fail", "No v=spf1 record: any server can send mail as this domain.")],
        )
    if len(records) > 1:
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
    # DKIM signs with RSA or Ed25519 only (RFC 6376, RFC 8463): an EC or DSA
    # key is unusable, not a short RSA key.
    if not isinstance(key, rsa.RSAPublicKey):
        return "invalid", None
    return "rsa", key.key_size


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
    if raw.get("truncated") and not records:
        return _check(
            "unknown",
            "CAA: name too deep to check",
            [("info", f"Only the nearest {CAA_MAX_NAMES} names were asked.")],
        )
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
    # issue governs every name, issuewild only wildcard ones (RFC 8659 §4):
    # a set with no issue property, iodef or issuewild alone, leaves a plain
    # name open to any CA.
    issuers, wildcard = [], []
    has_issue = False
    for record in records:
        tag = record["tag"].lower()
        if tag not in ("issue", "issuewild"):
            continue
        has_issue |= tag == "issue"
        issuer = record["value"].split(";")[0].strip()
        target = issuers if tag == "issue" else wildcard
        if issuer and issuer not in target:
            target.append(issuer)
    findings = []
    if raw.get("queried_name"):
        findings.append(("info", f"Published at {raw['queried_name']}."))
    extra = {"issuers": issuers, "queried_name": raw.get("queried_name")}
    if not has_issue:
        findings.append(
            ("warn", "No issue property: any certificate authority may issue.")
        )
        return _graded("CAA: no issue property", findings, **extra)
    summary = f"CAA: {', '.join(issuers)}" if issuers else "CAA: no CA may issue"
    if wildcard:
        summary += f"; wildcard: {', '.join(wildcard)}"
    return _graded(summary, findings, **extra)


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


# The CAA climb asks one name per label, and a wildcard zone answers any depth,
# so the climb stops here: past it the set is unknown, never open.
CAA_MAX_NAMES = 8

# One thread per query: about 17 for a typical name (10 DKIM selectors, CAA up
# the labels, DS, DNSKEY, three TXT). This call's own pool, never the caller's.
_FETCH_WORKERS = 20


def _validating_resolver():
    """The public resolvers, asked with DO and AD set: both validate DNSSEC,
    and the AD bit in the answer says they did."""
    resolver = managers._recursive_resolver()
    resolver.use_edns(0, dns.flags.DO, 1232)
    resolver.flags = dns.flags.RD | dns.flags.AD
    return resolver


def _query(name: str, rdtype: str, resolver_factory=None):
    try:
        factory = resolver_factory or managers._recursive_resolver
        return factory().resolve(name, rdtype), "ok"
    except Exception as exc:
        return None, dns_status(exc)


def _txt(answer) -> list[str]:
    if answer is None:
        return []
    # Joined with no separator: a string over 255 bytes arrives split.
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


def caa_names(name: str, registrable: str | None) -> list[str]:
    """The names RFC 8659 §3 climbs for CAA: the name, then each parent, down
    to the registrable domain (never a public suffix)."""
    names = [name]
    while registrable and name != registrable and name.endswith("." + registrable):
        name = name.split(".", 1)[1]
        names.append(name)
    return names


def _caa(results: list[tuple[str, object, str]]) -> dict:
    """The first non-empty CAA set, nearest the name first. A failure before
    it means the relevant set is unknown."""
    for name, answer, status in results:
        if status in DNS_FAILURES:
            return {"records": [], "queried_name": None, "status": status}
        if answer is not None:
            records = [
                {
                    "flags": r.flags,
                    "tag": r.tag.decode("ascii", "replace"),
                    "value": r.value.decode("utf-8", "replace"),
                }
                for r in answer
            ]
            return {"records": records, "queried_name": name, "status": "ok"}
    return {"records": [], "queried_name": None, "status": "noanswer"}


def _dkim(results: list[tuple[str, object, str]]) -> dict:
    keys = []
    statuses = []
    for selector, answer, status in results:
        statuses.append(status)
        for text in _txt(answer):
            tags = _dkim_tags(text)
            if tags.get("v", "DKIM1") == "DKIM1" and "p" in tags:
                keys.append({"selector": selector, "text": text})
    if keys:
        return {"keys": keys, "status": "ok"}
    # Every selector failed: unknown. One definite answer is enough to say
    # "not found" rather than "could not ask".
    definite = [s for s in statuses if s not in DNS_FAILURES]
    return {
        "keys": [],
        "status": "noanswer" if definite or not statuses else statuses[0],
    }


def fetch(name: str, zone: str, registrable: str | None) -> dict:
    """Every answer evaluate() needs beyond the record sweep's, for `name`,
    whose DNS zone is `zone` and registrable domain `registrable`."""
    with ThreadPoolExecutor(max_workers=_FETCH_WORKERS) as pool:
        climb = caa_names(name, registrable)
        caa = [(n, pool.submit(_query, n, "CAA")) for n in climb[:CAA_MAX_NAMES]]
        dkim = [
            (s, pool.submit(_query, f"{s}._domainkey.{name}", "TXT"))
            for s in DKIM_SELECTORS
        ]
        ds = pool.submit(_query, zone, "DS", _validating_resolver)
        dnskey = pool.submit(_query, zone, "DNSKEY", _validating_resolver)
        optional = {
            check: pool.submit(_query, f"{label}.{name}", "TXT")
            for check, (label, _) in OPTIONAL_TXT.items()
        }

        ds_answer, ds_status = ds.result()
        dnskey_answer, dnskey_status = dnskey.result()
        response = getattr(dnskey_answer, "response", None)
        caa_set = _caa([(n, *f.result()) for n, f in caa])
        if len(climb) > CAA_MAX_NAMES and caa_set["status"] == "noanswer":
            caa_set["truncated"] = True
        return {
            "caa": caa_set,
            "dnssec": {
                "zone": zone,
                "ds": ds_status,
                "dnskey": dnskey_status,
                "validated": bool(
                    response is not None and response.flags & dns.flags.AD
                ),
            },
            "dkim": _dkim([(s, *f.result()) for s, f in dkim]),
            **{
                check: {"records": _txt(answer), "status": status}
                for check, (answer, status) in (
                    (check, f.result()) for check, f in optional.items()
                )
            },
        }
