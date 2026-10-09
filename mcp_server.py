"""The public MCP server mounted at /mcp.

Tools are thin shells over lookup.gather(): they reshape its output for an LLM
context and never raise, because a JSON-RPC transport fault tells the model far
less than {"error": "..."} does.

Response shaping is the whole point of this module. The HTTP API returns tile
URLs, projected polylines, and a full certificate dump because a browser paints
them; none of that helps a model, and all of it costs context.
"""

import asyncio
import datetime
import logging
from contextvars import ContextVar
from typing import Any

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from config import (
    MCP_ALLOWED_HOSTS,
    MCP_ALLOWED_ORIGINS,
    RDAP_TIMEOUT_SECONDS,
    SUBDOMAIN_ENABLED,
    SUBDOMAIN_MCP_DEFAULT_LIMIT,
    SUBDOMAIN_MCP_MAX_LIMIT,
    WHOIS_TIMEOUT_SECONDS,
)
from lookup import (
    InvalidTargetError,
    PrivateAddressError,
    gather,
    lookup_location,
    sanitize_log_input,
)
from managers import DNS_FAILURES
from rdap import NOT_REGISTERED
from security import client_ip_from_scope
from subdomains import get_subdomains, invalid_target_reason

# Certificate parsing already exists in viewmodel.py, which is pure and
# stdlib-only, so there is no cycle and no reason to restate it here.
from viewmodel import (
    _cert_expiry,
    _cert_issuer,
    _cert_san,
    _cert_subject_cn,
    _cert_validation,
)

mcp = MCPServer("whatismyip")


def _iso(value: Any) -> str | None:
    """RDAP hands back datetimes; WHOIS hands back strings. JSON needs one."""
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    return str(value)


def compact_location(loc: dict) -> dict:
    return {
        "country_code": loc.get("country_code"),
        "country_name": loc.get("country_name"),
        "city": loc.get("city_name") or None,
        "subdivision": loc.get("subdivision_name") or None,
        "lat": loc.get("lat"),
        "lon": loc.get("lon"),
        "accuracy_km": loc.get("accuracy_km"),
        "time_zone": loc.get("time_zone"),
    }


def compact_network(loc: dict) -> dict:
    return {
        "asn_number": loc.get("asn_number"),
        "asn_name": loc.get("asn_name"),
        "cidr": loc.get("asn_cidr") or loc.get("cidr"),
    }


def compact_registration(whois: dict | None) -> dict:
    whois = whois or {}
    error = whois.get("error")
    # "not registered" is an answer, not a failure, and the distinction matters
    # more to a model than to a person: told `error`, it reports that the lookup
    # broke and the user should try again; told `registered: false`, it can say
    # the name has no registration -- which is simply what a subdomain looks
    # like. Same reasoning as dns_records refusing to return {} for a record
    # type this server never queried.
    if error == NOT_REGISTERED:
        return {"registered": False, "name": whois.get("name")}
    if error:
        return {"error": error}
    return {
        "source": whois.get("source"),
        "name": whois.get("name"),
        "registrar": whois.get("registrar"),
        "registrant": whois.get("registrant"),
        "registrant_country": whois.get("country"),
        "abuse_email": whois.get("abuse_email"),
        "created": _iso(whois.get("created")),
        "updated": _iso(whois.get("updated")),
        "expires": _iso(whois.get("expires")),
        "status": list(whois.get("status") or []),
        "rir": whois.get("rir"),
    }


def _tls_failure(ssl_data: dict) -> str:
    """'port 443 unreachable (connection refused)': no certificate was read."""
    reason = ssl_data.get("reason")
    return f"{ssl_data['error']} ({reason})" if reason else ssl_data["error"]


def compact_ssl(ssl_data: dict | None) -> dict | None:
    """Issuer plus the expiry clock — the two things anyone actually asks —
    and whether the certificate is trusted at all."""
    if not ssl_data:
        return None
    if ssl_data.get("error"):
        return {"error": _tls_failure(ssl_data)}
    expires, days_left = _cert_expiry(ssl_data)
    return {
        "issuer": _cert_issuer(ssl_data),
        "subject": _cert_subject_cn(ssl_data),
        "expires": expires,
        "days_remaining": days_left,
        "protocol": ssl_data.get("protocol"),
        # An untrusted certificate is still an answer, and a model told only
        # the issuer and expiry would vouch for an expired or self-signed one.
        "trusted": ssl_data.get("trusted"),
        "hostname_match": ssl_data.get("hostname_match"),
        "verify_error": ssl_data.get("verify_error"),
    }


# Every MCP tool call runs gather()'s full pipeline on the same executor the
# HTML site uses, and /mcp has no auto-ban escalation (see main.py's
# security_middleware) to shed a sustained attacker the way the browser path
# does. Two amplifiers make an unbounded call here worse than the equivalent
# GET /{domain}: `_whois_fallback` (lookup.py) documents that `wait_for`
# cannot actually cancel its worker thread on timeout, so a blackholing WHOIS
# server holds a thread for the OS TCP timeout (~2 min) rather than the 15s
# budget; and `DomainManager.get_records()` (managers.py) opens nested thread
# pools of its own — no longer sized by the zone's record count, but still up
# to 7 + 2 x DNS_HOST_RESOLVE_WORKERS threads per call. A semaphore
# caps how many gather() calls run at once; wait_for gives the whole call a
# hard wall-clock ceiling so a stuck one can't hold its slot forever.
_GATHER_CONCURRENCY = asyncio.Semaphore(8)
_GATHER_TIMEOUT_SECONDS = RDAP_TIMEOUT_SECONDS + WHOIS_TIMEOUT_SECONDS + 5


async def _bounded_gather(target: str) -> dict:
    async with _GATHER_CONCURRENCY:
        return await asyncio.wait_for(gather(target), timeout=_GATHER_TIMEOUT_SECONDS)


@mcp.tool()
async def lookup(target: str) -> dict[str, Any]:
    """Look up everything known about a domain name or IP address: its
    geolocation, network/ASN owner, registration (RDAP/WHOIS) details, and a
    summary of its TLS certificate. Accepts "example.com", "8.8.8.8", or a
    pasted URL. Use this first; the other tools go deeper on one aspect.
    Private and reserved addresses are refused, and IPv6 addresses are not
    supported yet.
    """
    try:
        data = await _bounded_gather(target)
    except PrivateAddressError:
        return {"error": "Private or reserved addresses are not allowed"}
    except InvalidTargetError as exc:
        return {"error": exc.message}
    except TimeoutError:
        return {"error": "Lookup timed out"}
    except Exception:
        logging.exception("MCP lookup failed for %s", sanitize_log_input(target))
        return {"error": "Lookup failed"}

    loc = data["location"] or {}
    return {
        "target": data["address"],
        "ip": data["resolved_ip"],
        "reverse_dns": data["reverse_dns"] or loc.get("reverse_dns"),
        "geo": compact_location(loc),
        "network": compact_network(loc),
        "registration": compact_registration(data["whois"]),
        "tls": compact_ssl(data["ssl"]),
    }


# No AAAA: DomainManager.get_records() never queries it, so advertising it here
# would return {} for a domain that does have IPv6 — indistinguishable, to a
# model relaying the answer, from "this domain has no AAAA records".
_RECORD_TYPES = ("a", "mx", "ns", "cname", "txt", "spf", "ptr")


@mcp.tool()
async def dns_records(domain: str, types: list[str] | None = None) -> dict[str, Any]:
    """DNS records for a domain: A, MX, NS, CNAME, TXT, SPF, PTR — the exact
    set this server queries. Pass `types` (lowercase, a subset of those) to
    narrow the sweep; omit it for everything. Use this for mail-routing and
    SPF/DMARC questions, where the summary from `lookup` is not enough.
    NS come from `zone`, the DNS zone serving the name. MX rows marked
    `from_zone` belong to that zone, not the name: it has no MX of its own.
    A type whose query failed is {"error": "timeout" | "servfail" | "error"}:
    unknown, not empty. An empty list means the name has none of that type.
    `resolution` is how the name reached `resolved_ip`: "ok", "nxdomain" (the
    name does not exist), "noanswer" (no A record), "timeout", "servfail" or
    "error"; "literal" when the target is itself an IP.
    """
    # `is not None`, not truthiness: types=[] means "narrow to nothing", which is
    # a different request from omitting the argument, and must not silently
    # widen back to the full sweep.
    if types is not None:
        wanted = [t.lower() for t in types]
        # A type this server never queries (a stale "aaaa", a typo, "caa") must
        # not come back indistinguishable from {} on a genuinely empty answer —
        # that reads as a confident "no records of this type" when the truth is
        # "this tool never asked". Reject it and name what is actually queried.
        unsupported = sorted(set(wanted) - set(_RECORD_TYPES))
        if unsupported:
            return {
                "error": (
                    f"unsupported record types: {', '.join(unsupported)} — "
                    f"this server queries only {', '.join(_RECORD_TYPES)}"
                )
            }
    else:
        wanted = list(_RECORD_TYPES)

    try:
        data = await _bounded_gather(domain)
    except PrivateAddressError:
        return {"error": "Private or reserved addresses are not allowed"}
    except InvalidTargetError as exc:
        return {"error": exc.message}
    except TimeoutError:
        return {"error": "Lookup timed out"}
    except Exception:
        logging.exception("MCP dns_records failed for %s", sanitize_log_input(domain))
        return {"error": "DNS lookup failed"}

    records = data["domain"] or {}
    status = records.get("status") or {}
    return {
        "domain": data["address"],
        "resolved_ip": data["resolved_ip"],
        "resolution": data.get("resolution"),
        # The name the records were asked of (an IP's PTR name, for an IP) and
        # the zone its NS and inherited MX/SPF came from.
        "queried_name": records.get("queried_name"),
        "zone": records.get("zone"),
        # A failed query must not come back as the [] it left behind: a model
        # states [] as "this name has none", the same trap the subdomains tool
        # and the unsupported-type check above avoid.
        "records": {
            k: {"error": status[k]} if status.get(k) in DNS_FAILURES else v
            for k, v in records.items()
            if k in wanted
        },
    }


@mcp.tool()
async def ssl_certificate(domain: str) -> dict[str, Any]:
    """The TLS certificate a domain serves on port 443: issuer, subject,
    every SAN, the validity window, and how many days remain before it
    expires. Use this for "when does this certificate expire?" and "does this
    certificate cover this hostname?". A certificate that fails verification
    (expired, self-signed, wrong host, incomplete chain) is still returned,
    with `trusted: false` and `verify_error` saying why; `error` means no
    certificate could be read at all, such as port 443 being unreachable.
    """
    try:
        data = await _bounded_gather(domain)
    except PrivateAddressError:
        return {"error": "Private or reserved addresses are not allowed"}
    except InvalidTargetError as exc:
        return {"error": exc.message}
    except TimeoutError:
        return {"error": "Lookup timed out"}
    except Exception:
        logging.exception(
            "MCP ssl_certificate failed for %s", sanitize_log_input(domain)
        )
        return {"error": "TLS lookup failed"}

    cert = data["ssl"]
    if not cert:
        # Almost always no handshake was attempted, which is not the same as
        # a host serving no certificate.
        if not data["resolved_ip"]:
            return {"error": f"TLS not checked for {data['address']}: no A record"}
        if data["resolved_ip"] == data["address"]:
            return {"error": "TLS is checked for domain names only, not IP addresses"}
        return {"error": f"No TLS certificate served by {data['address']} on port 443"}
    if cert.get("error"):
        return {"error": f"{_tls_failure(cert)} for {data['address']}"}

    summary = compact_ssl(cert)
    return {
        **summary,
        "domain": data["address"],
        "san": _cert_san(cert),
        "validation": _cert_validation(cert),
        "not_before": cert.get("notBefore"),
        "serial_number": cert.get("serialNumber"),
        "cipher": cert.get("cipher"),
    }


async def subdomains(
    domain: str, limit: int = SUBDOMAIN_MCP_DEFAULT_LIMIT
) -> dict[str, Any]:
    """Subdomains of a domain, as seen in public Certificate Transparency logs.
    This is a passive lookup of certificate records — nothing is sent to the
    domain itself, and it finds only names that appear in a published
    certificate, so it is evidence of existence and never a complete inventory.
    Use it for "what else is under this domain?". `limit` caps how many names
    come back; `count` always reports the true total. Pass a registered domain
    or a name under one: an IP address or a bare public suffix (com, co.uk,
    github.io) is refused.
    """
    if limit < 1:
        return {"error": "limit must be at least 1"}
    limit = min(limit, SUBDOMAIN_MCP_MAX_LIMIT)

    # The same gate the HTTP route applies. get_subdomains() refuses these too,
    # but only as a backstop; neither surface should rely on the other's check.
    reason = invalid_target_reason(domain)
    if reason:
        return {"domain": domain, "error": reason}

    try:
        data = await get_subdomains(domain)
    except Exception:
        logging.exception("MCP subdomains failed for %s", sanitize_log_input(domain))
        return {"error": "Subdomain lookup failed"}

    # An empty list must never stand in for a failure. dns_records rejects a
    # record type this server does not query for the same reason: a model
    # reading {} or [] states it as fact, and "we could not ask" would reach the
    # user as "there are none".
    if data.get("error"):
        return {"domain": domain, "error": data["error"]}

    names = data.get("names") or []
    shown = names[:limit]
    return {
        "domain": domain,
        "names": shown,
        "count": data.get("count", len(names)),
        "truncated": data.get("count", len(names)) > len(shown),
        "source": data.get("source"),
        "fetched_at": data.get("fetched_at"),
        "stale": data.get("stale", False),
    }


# Registered conditionally so that with SUBDOMAIN_ENABLED=false an agent sees a
# server that does not offer this, rather than one that offers it and always
# fails. The decorator form cannot express that.
if SUBDOMAIN_ENABLED:
    mcp.tool()(subdomains)


_caller_ip: ContextVar[str] = ContextVar("mcp_caller_ip", default="unknown")


class CallerIPMiddleware:
    """Record the verified peer address for whoami_caller.

    A tool cannot read the peer itself: the SDK hands it request headers,
    which a caller can set to whatever it likes. The address here comes from
    `client_ip_from_scope()` instead — the same trusted-proxy logic
    `security.get_client_ip` applies on the HTML path: the raw TCP peer,
    unless that peer is itself on the trusted-proxy allowlist (or, absent an
    allowlist, a private-range address — the normal shape of a Docker/K8s
    sidecar), in which case `x-real-ip`/`x-forwarded-for` is taken instead. A
    client that isn't behind a trusted proxy cannot spoof this by setting
    those headers on its own request.

    The ContextVar survives the hops between here and the tool body because
    contextvars are copied at task *creation*: a value set before any spawn
    propagates into every task created afterwards in the same chain. That
    includes the MCP SDK's own spawn — under stateless_http the transport runs
    the tool via task_group.start() — so the set below still reaches it.

    Pure ASGI rather than BaseHTTPMiddleware for simplicity, not because
    BaseHTTPMiddleware would break this direction (it would not; its documented
    contextvars pitfall is the reverse one, where state set *inside* call_next
    is invisible to the middleware afterwards). A plain wrapper introduces no
    task hop of its own and needs no reasoning about which direction is safe.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            _caller_ip.set(client_ip_from_scope(scope))
        await self.app(scope, receive, send)


@mcp.tool()
async def whoami_caller() -> dict[str, Any]:
    """The IP address and location of whatever opened this MCP connection.

    Whose address that is depends on where the client runs, and the difference
    matters. A local client (Claude Code, Cursor, Claude Desktop) connects from
    the user's own machine, so this IS the user's address. A hosted client
    (claude.ai, ChatGPT) connects from the provider's servers, so this is a
    datacenter and tells you nothing about the user.

    Either way, report it as the origin of this connection rather than as "your
    IP address" — you cannot tell from here which case you are in. If the user
    needs certainty, have them open https://ip.1kko.com in a browser.
    """
    ip = _caller_ip.get()
    if ip == "unknown":
        return {"error": "Caller address unavailable"}
    try:
        loc = await lookup_location(ip)
    except Exception:
        logging.exception("MCP whoami_caller failed")
        return {"error": "Location lookup failed"}
    return {
        "ip": ip,
        "geo": compact_location(loc),
        "network": compact_network(loc),
        "note": (
            "This is the address that opened this MCP connection. Where that is "
            "depends on the client: a local one (Claude Code, Cursor, Claude "
            "Desktop) connects from the user's own machine, so this is their "
            "address; a hosted one (claude.ai, ChatGPT) connects from the "
            "provider's servers, so this is a datacenter. This server cannot "
            "tell which. Open https://ip.1kko.com in a browser to be certain."
        ),
    }


def build_mcp():
    """Return (asgi_app, mcp) for main.py to mount and drive.

    `mcp.session_manager` does not exist until streamable_http_app() has been
    called, which is why the app is built here at import time and the manager is
    only entered inside the host app's lifespan.
    """
    asgi_app = mcp.streamable_http_app(
        # The mount prefix supplies the whole public path, so the transport's
        # own path is the root of the sub-app.
        streamable_http_path="/",
        # Governs the POST response shape only — it does not touch GET, which
        # the SDK would otherwise turn into a standalone SSE stream that
        # stateless mode never tears down. This server has no server-initiated
        # messages to stream, so GET (and every other non-POST method) is
        # rejected outright by _reject_non_post below, before it ever reaches
        # this app.
        json_response=True,
        # Only affects clients on spec 2025-11-25 and earlier; 2026-07-28 is
        # sessionless by construction. Without it a legacy client's session
        # lives in one worker's memory, and neither /app/data nor a single
        # replica is guaranteed here.
        stateless_http=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=MCP_ALLOWED_HOSTS,
            allowed_origins=MCP_ALLOWED_ORIGINS,
        ),
    )
    return CallerIPMiddleware(asgi_app), mcp


# --- Transport plumbing for main.py's mount -------------------------------
#
# These two classes are MCP transport mechanics (how a request reaches the
# app `build_mcp()` returns), not app wiring, so they live here rather than
# in main.py; main.py only imports and wires them.


async def _reject_non_post(send) -> None:
    """Answer with a prompt 405 instead of forwarding into the SDK.

    A GET here would reach `_handle_get_request`
    (mcp/server/streamable_http.py), which checks nothing but whether `Accept`
    contains `text/event-stream` and then opens a standalone SSE stream that
    `stateless_http=True` never tears down — each one pins a file descriptor,
    a transport object, and anyio tasks that never return, and `/mcp` cannot
    auto-ban (see main.py's security_middleware) to shed a caller doing this
    on purpose. This server never sends a server-initiated message, so the
    stream has zero utility; the MCP spec explicitly permits 405 for a server
    that doesn't offer it, so no compliant client breaks. Same reasoning
    covers PUT/DELETE/etc: nothing here needs any method but POST.
    """
    await send(
        {
            "type": "http.response.start",
            "status": 405,
            "headers": [
                (b"content-type", b"application/json"),
                (b"allow", b"POST"),
            ],
        }
    )
    await send(
        {"type": "http.response.body", "body": b'{"error": "Method Not Allowed"}'}
    )


class McpDispatch:
    """ASGI indirection to whichever MCP sub-app is currently live.

    A `StreamableHTTPSessionManager.run()` may only be entered once per
    instance — the SDK's own hard rule (see
    mcp/server/streamable_http_manager.py): "cannot be reused after its run()
    context has completed. If you need to restart the manager, create a new
    instance." The FastAPI app's lifespan starts and stops that manager once
    per process in production, but each `with TestClient(app) as client:` in
    the test suite is its own start/stop cycle against the same imported
    `app`. A fixed reference captured once at mount time would work for
    exactly the first cycle and raise on every one after it. main.py wires
    its Route/Mount to this one mutable indirection at module scope (so mount
    ordering still holds), and updates `.asgi_app` inside its lifespan by
    calling `build_mcp()` fresh on every start — cheap, since that only
    re-runs `streamable_http_app()` on the already-registered `mcp`
    singleton above, not the `@mcp.tool()` registration.
    """

    def __init__(self):
        self.asgi_app = None

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["method"] != "POST":
            await _reject_non_post(send)
            return
        await self.asgi_app(scope, receive, send)


mcp_dispatch = McpDispatch()


class McpBarePathRoute:
    """Answer the bare "/mcp" path (any method) by forwarding straight into
    the mounted MCP sub-app, presenting it a scope as though the request had
    arrived at its own root ("/").

    Starlette's `Mount` can only match paths that start with the mount prefix
    *plus* a trailing slash — `Mount.__init__` compiles its regex from
    `self.path + "/{path:path}"`, so `Mount("/mcp", ...)` is
    `^/mcp/(?P<path>.*)$` and structurally cannot match the bare prefix
    itself. `app.mount("/mcp", ...)` alone therefore answers "/mcp/" but not
    "/mcp". An MCP client configured with the literal "https://ip.1kko.com/mcp"
    URL (the normal way to hand out an MCP server) sends exactly that bare
    path; main.py registers this ahead of its `/{domain_ip}` catch-all so it
    wins outright instead of falling through to that catch-all's own 405
    (right path, wrong method).

    Only `path` is rewritten to "/" — `root_path` is left exactly as it
    arrived. `Starlette._utils.get_route_path` derives the path routes are
    matched against as `path` with `root_path` stripped off the front; with
    `path` already rewritten to "/", it can never start with a non-empty
    `root_path` (mirroring `root_path` the way `Mount` would, i.e.
    `root_path + "/mcp"`, breaks this: `path` and `root_path` would then both
    be "/mcp", and get_route_path's `path == root_path` case returns "",
    which matches nothing). Leaving `root_path` untouched also avoids
    corrupting it for URL generation behind a reverse proxy that sets one.
    """

    def __init__(self, asgi_app):
        self._asgi_app = asgi_app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["method"] != "POST":
            await _reject_non_post(send)
            return
        inner_scope = {**scope, "path": "/"}
        await self._asgi_app(inner_scope, receive, send)


class McpDisabled:
    """Answer every `/mcp` request with 404 when `MCP_ENABLED=false`.

    Without this, main.py mounts nothing at `/mcp` and the request falls
    through to the `/{domain_ip}` catch-all, which serves it as a lookup of
    the literal string "mcp" — a confusing 200 where a 404 ("this endpoint
    doesn't exist right now") is what `MCP_ENABLED=false` actually means.
    """

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return
        await send(
            {
                "type": "http.response.start",
                "status": 404,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": b'{"error": "Not Found"}'})
