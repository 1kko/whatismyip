"""EPP status codes: one spelling for a registration's `status`, and what each
code means.

A domain's registry status reaches the page in two vocabularies. RDAP answers
with RFC 8056's words ("client transfer prohibited"), and python-whois hands
back the port-43 line, which under ICANN's format is the EPP code with its
explanatory URL ("clientTransferProhibited https://icann.org/epp#..."); some
ccTLD registries print the camelCase code alone. epp_code() folds all three to
the EPP code, and STATUS_MEANINGS says in one line what the code means, with a
tone for the page. A value no table knows (DENIC's "connect", KRNIC's and
Nominet's own words) passes through verbatim, so a registry's vocabulary is
shown rather than guessed at.

Standard library only: viewmodel.py imports this, and must stay importable
without whoisit (see its NOT_REGISTERED note). rdap.py keeps `status` as each
source gave it; the fold happens where a status is rendered or explained.
"""

from __future__ import annotations

import re
from typing import Any

# RFC 8056, section 2: the EPP status code and the RDAP status it maps to. Two
# pairs differ in more than spacing: EPP "ok" is RDAP "active", EPP "linked" is
# RDAP "associated".
RFC8056: dict[str, str] = {
    "addPeriod": "add period",
    "autoRenewPeriod": "auto renew period",
    "clientDeleteProhibited": "client delete prohibited",
    "clientHold": "client hold",
    "clientRenewProhibited": "client renew prohibited",
    "clientTransferProhibited": "client transfer prohibited",
    "clientUpdateProhibited": "client update prohibited",
    "inactive": "inactive",
    "linked": "associated",
    "ok": "active",
    "pendingCreate": "pending create",
    "pendingDelete": "pending delete",
    "pendingRenew": "pending renew",
    "pendingRestore": "pending restore",
    "pendingTransfer": "pending transfer",
    "pendingUpdate": "pending update",
    "redemptionPeriod": "redemption period",
    "renewPeriod": "renew period",
    "serverDeleteProhibited": "server delete prohibited",
    "serverHold": "server hold",
    "serverRenewProhibited": "server renew prohibited",
    "serverTransferProhibited": "server transfer prohibited",
    "serverUpdateProhibited": "server update prohibited",
    "transferPeriod": "transfer period",
}

# What each code means, and the tone the page gives it. Descriptive, never a
# verdict: a lock is "a common setting", not "safe"; a hold says the name does
# not resolve, not that anything is wrong with it. `danger` is kept to the four
# codes under which the name is out of the DNS or about to be dropped;
# `inactive` (no delegation) is a warning; a lock is reassuring (`success`);
# the grace periods and pending operations are plain.
STATUS_MEANINGS: dict[str, tuple[str, str]] = {
    "ok": ("no locks and no pending operations", "default"),
    "linked": ("referenced by another registry object", "default"),
    "addPeriod": ("newly registered: within the add grace period", "default"),
    "autoRenewPeriod": (
        "renewed automatically by the registry at expiry: the registrar can "
        "still cancel the renewal within this grace period",
        "default",
    ),
    "renewPeriod": (
        "renewed by the registrar: within the renew grace period",
        "default",
    ),
    "transferPeriod": (
        "transferred to a new registrar: within the transfer grace period",
        "default",
    ),
    "pendingCreate": ("registration requested, not yet completed", "default"),
    "pendingRenew": ("renewal requested, not yet completed", "default"),
    "pendingRestore": (
        "restore from redemption requested: the registrar has to confirm it",
        "default",
    ),
    "pendingTransfer": ("a transfer to another registrar is in progress", "default"),
    "pendingUpdate": ("an update is in progress", "default"),
    "inactive": ("no name servers delegated, so the name does not resolve", "warning"),
    "clientHold": (
        "taken out of the DNS by the registrar: the name does not resolve",
        "danger",
    ),
    "serverHold": (
        "taken out of the DNS by the registry: the name does not resolve",
        "danger",
    ),
    "pendingDelete": (
        "being deleted by the registry: released to the public in a few days",
        "danger",
    ),
    "redemptionPeriod": (
        "deleted by the registrar: the holder can still restore it, for a fee, "
        "until the redemption window closes",
        "danger",
    ),
    "clientDeleteProhibited": (
        "delete lock set by the registrar (a common setting)",
        "success",
    ),
    "clientRenewProhibited": ("renewal lock set by the registrar", "success"),
    "clientTransferProhibited": (
        "transfer lock set by the registrar (a common setting)",
        "success",
    ),
    "clientUpdateProhibited": (
        "update lock set by the registrar (a common setting)",
        "success",
    ),
    "serverDeleteProhibited": ("delete lock set by the registry", "success"),
    "serverRenewProhibited": ("renewal lock set by the registry", "success"),
    "serverTransferProhibited": ("transfer lock set by the registry", "success"),
    "serverUpdateProhibited": ("update lock set by the registry", "success"),
}

# Both spellings of every code, lower-cased with the spaces out, so one lookup
# serves "clientTransferProhibited", "client transfer prohibited" and "CLIENT
# TRANSFER PROHIBITED" alike, and "active" lands on "ok".
_BY_KEY: dict[str, str] = {code.lower(): code for code in RFC8056}
_BY_KEY.update({words.replace(" ", ""): code for code, words in RFC8056.items()})

# ICANN's port-43 format puts the explanatory URL after the code, bare or in
# parentheses, with or without "www.". It is never part of the status.
_EPP_URL = re.compile(r"\s*\(?https?://(?:www\.)?icann\.org/epp#\S*\)?", re.I)
_KEY_CHARS = re.compile(r"[^a-z0-9]")


def epp_code(text: Any) -> str:
    """The EPP code for one status value, in any of the three spellings a
    registry uses; a value outside RFC 8056 comes back as it was given (minus
    an icann.org/epp URL), so an unknown registry word is shown, not guessed."""
    raw = str(text).strip()
    bare = _EPP_URL.sub("", raw).strip() or raw
    return _BY_KEY.get(_KEY_CHARS.sub("", bare.lower()), bare)


def explain_status(statuses: Any) -> list[dict[str, Any]]:
    """One entry per distinct code, in the order given: the code, its meaning
    and the tone as `severity` (`default`, `success`, `warning` or `danger`).
    A code outside the table keeps `meaning` and `severity` null: the model is
    told the registry's word, and that this server has no gloss for it. Takes
    the canonical record's list, a bare string, or None."""
    if statuses is None or statuses == "":
        return []
    if isinstance(statuses, str):
        statuses = [statuses]
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in statuses:
        if value is None or value == "":
            continue
        code = epp_code(value)
        if code in seen:
            continue
        seen.add(code)
        meaning, tone = STATUS_MEANINGS.get(code, (None, None))
        out.append({"code": code, "meaning": meaning, "severity": tone})
    return out
