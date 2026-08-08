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
from viewmodel import _cert_expiry, _cert_issuer, _cert_subject_cn

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
