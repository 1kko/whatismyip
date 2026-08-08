"""The public MCP server mounted at /mcp.

Tools are thin shells over lookup.gather(): they reshape its output for an LLM
context and never raise, because a JSON-RPC transport fault tells the model far
less than {"error": "..."} does.

Response shaping is the whole point of this module. The HTTP API returns tile
URLs, projected polylines, and a full certificate dump because a browser paints
them; none of that helps a model, and all of it costs context.
"""

import datetime
import logging
from typing import Any

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from config import MCP_ALLOWED_HOSTS
from lookup import PrivateAddressError, gather, sanitize_log_input

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
    if whois.get("error"):
        return {"error": whois["error"]}
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


def compact_ssl(ssl_data: dict | None) -> dict | None:
    """Issuer plus the expiry clock — the two things anyone actually asks."""
    if not ssl_data:
        return None
    expires, days_left = _cert_expiry(ssl_data)
    return {
        "issuer": _cert_issuer(ssl_data),
        "subject": _cert_subject_cn(ssl_data),
        "expires": expires,
        "days_remaining": days_left,
        "protocol": ssl_data.get("protocol"),
    }


@mcp.tool()
async def lookup(target: str) -> dict[str, Any]:
    """Look up everything known about a domain name or IP address: its
    geolocation, network/ASN owner, registration (RDAP/WHOIS) details, and a
    summary of its TLS certificate. Accepts "example.com", "8.8.8.8", or a
    pasted URL. Use this first; the other tools go deeper on one aspect.
    Private and reserved addresses are refused.
    """
    try:
        data = await gather(target)
    except PrivateAddressError:
        return {"error": "Private or reserved addresses are not allowed"}
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


_RECORD_TYPES = ("a", "aaaa", "mx", "ns", "cname", "txt", "spf", "ptr")


@mcp.tool()
async def dns_records(domain: str, types: list[str] | None = None) -> dict[str, Any]:
    """Every DNS record for a domain: A, AAAA, MX, NS, CNAME, TXT, SPF, PTR.
    Pass `types` (lowercase, e.g. ["mx", "txt"]) to fetch a subset; omit it for
    everything. Use this for mail-routing and SPF/DMARC questions, where the
    summary from `lookup` is not enough.
    """
    try:
        data = await gather(domain)
    except PrivateAddressError:
        return {"error": "Private or reserved addresses are not allowed"}
    except Exception:
        logging.exception("MCP dns_records failed for %s", sanitize_log_input(domain))
        return {"error": "DNS lookup failed"}

    records = data["domain"] or {}
    wanted = [t.lower() for t in types] if types else list(_RECORD_TYPES)
    return {
        "domain": data["address"],
        "resolved_ip": data["resolved_ip"],
        "records": {k: v for k, v in records.items() if k in wanted},
    }


@mcp.tool()
async def ssl_certificate(domain: str) -> dict[str, Any]:
    """The TLS certificate a domain serves on port 443: issuer, subject,
    every SAN, the validity window, and how many days remain before it
    expires. Use this for "when does this certificate expire?" and "does this
    certificate cover this hostname?".
    """
    try:
        data = await gather(domain)
    except PrivateAddressError:
        return {"error": "Private or reserved addresses are not allowed"}
    except Exception:
        logging.exception(
            "MCP ssl_certificate failed for %s", sanitize_log_input(domain)
        )
        return {"error": "TLS lookup failed"}

    cert = data["ssl"]
    if not cert:
        return {"error": f"No TLS certificate served by {data['address']} on port 443"}

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
        # Plain JSON instead of SSE: nothing here streams, and it keeps the
        # reverse proxy out of the picture.
        json_response=True,
        # Only affects clients on spec 2025-11-25 and earlier; 2026-07-28 is
        # sessionless by construction. Without it a legacy client's session
        # lives in one worker's memory, and neither /app/data nor a single
        # replica is guaranteed here.
        stateless_http=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=MCP_ALLOWED_HOSTS,
        ),
    )
    return asgi_app, mcp


# --- Transport plumbing for main.py's mount -------------------------------
#
# These two classes are MCP transport mechanics (how a request reaches the
# app `build_mcp()` returns), not app wiring, so they live here rather than
# in main.py; main.py only imports and wires them.


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
    wins outright instead of falling through to a 405.

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
        inner_scope = {**scope, "path": "/"}
        await self._asgi_app(inner_scope, receive, send)
