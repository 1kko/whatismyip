# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

A FastAPI-based web service that provides WHOIS, GeoIP, DNS records, and SSL certificate information for IP addresses and domain names. The service features automatic GeoIP database updates and serves browser (HTML) and API (JSON) responses from the same URL, chosen by `?format=`, the `Accept` header, or failing both the user-agent.

## Development Commands

### Environment Setup
```bash
# Activate virtual environment and install dependencies
poetry shell
poetry install
```

### Building
```bash
# Build Docker image (preferred)
make build
# or
make  # default target builds image
```

### Running the Application

**Docker (recommended for production):**
```bash
# Run in detached mode with auto-restart
make serve

# Run interactively (foreground)
make run

# View logs
make logs

# Stop the service
make stop
```

**Direct Python execution (development):**
```bash
# Start FastAPI with auto-reload
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Or run directly
python main.py
```

### Testing
```bash
# The whole suite runs on FastAPI's TestClient with external lookups mocked —
# no running service, no network.
pytest

# Run a single file or test
pytest tests/test_rdap.py
pytest tests/test_basic.py::TestBasic::test_get_domain_info

# Run with verbose output
pytest -v
```

**Note:** No live server is required — every test file uses `TestClient`.

### Code Quality
```bash
# Lint with ruff
poetry run ruff check .

# Format with ruff
poetry run ruff format .
```

## Architecture

### Core Components

**Modules:**
- `config.py`: every environment-driven constant (timeouts, cache TTLs, file paths, rate-limit/ban settings, geo-block defaults, trusted proxies, map canvases). Pure values — imported by everything, imports nothing app-local, which keeps the tree cycle-free.
- `managers.py` — data-gathering managers, one thin wrapper per source:
  - `GeoIpManager`: GeoLite2-City (country, city, coordinates) and GeoLite2-ASN (carrier) lookups over memory-mapped mmdb files, refreshed every 3 days via APScheduler, with geoip2fast's bundled country snapshot as the fallback until the first download
  - `DomainManager`: DNS (A, MX, NS, CNAME, TXT), reverse DNS, domain validation
  - `SSLManager`: SSL certificate retrieval for HTTPS endpoints
  - `HeaderManager`: strips proxy/forwarding headers
- `security.py` — request-security subsystem: `IPBanManager`, `RateLimiter`, `SuspiciousPatternDetector`, `WhitelistManager`, `GeoBlockManager`
- `rdap.py`: RDAP lookups (whoisit) with a port-43 WHOIS fallback, both normalised to one canonical dict
- `models.py`: Pydantic models (`WhoisResponse`, `GeoRulesUpdate`)
- `lookup.py`: transport-agnostic lookup pipeline (`gather()`), shared by the
  HTTP routes and the MCP tools. Raises `PrivateAddressError` and
  `InvalidTargetError` rather than `HTTPException` so it stays free of FastAPI.
  `gather(legs=)` runs only the named legs; the default (None) runs them all,
  and the page, the full JSON and MCP all use the default.
- `textfmt.py`: `?format=text` and `?fields=`. The field table (names are
  `mcp_server`'s compact_* shapes, flattened; each field lists the `gather()`
  legs it needs and the target kinds it applies to) and the text/flat-JSON
  rendering. Pure: `main.py` runs the lookup. `-` is "no value", `?` is "the
  lookup failed".
- `mcp_server.py`: the public MCP server mounted at `/mcp` (official `mcp` SDK,
  Streamable HTTP). Four tools, all thin shells over `lookup.gather()` that
  reshape its output for an LLM context.
- `main.py`: FastAPI app + middleware + routes + page rendering; wires the managers/security singletons and the scheduler. `negotiate()` (HTML-vs-JSON: `?format=`, then `Accept`, then the user-agent via `BrowserDetector`) lives here.

**API Endpoints**:
- `GET /` - Returns client's own IP information (detects client IP from x-real-ip header or request.client.host)
- `GET /{domain_ip}` - Returns information for specified domain or IP address

### Response Flow

1. **Format Negotiation**: `negotiate()` picks the response format: `?format=html|json|text` first (unknown value -> 400), then an `Accept` header that names `text/html`/`application/json`/`text/plain` (q-values honoured), and only when `Accept` is absent or `*/*` the user-agent (`BrowserDetector`: browsers get HTML; PowerShell, despite its `Mozilla/5.0`, gets JSON). `text` is `textfmt.py`'s: the bare client IP on `/`, a `key: value` block on `/{domain_ip}`; `?fields=` (either route; JSON unless text was negotiated) runs only the `gather(legs=)` the named fields need. Both lookup routes send `Vary: Accept, User-Agent` and `Cache-Control: no-store`, errors included
2. **IP Resolution**: Domains are resolved to IP addresses via DNS A records
3. **Data Gathering**: Parallel collection of WHOIS, GeoIP, DNS records, and SSL certificate data
4. **Response Assembly**: All data combined into unified response structure (WhoisResponse model)
5. **Logging**: All requests logged with client IP and lookup target

### Key Technical Details

**DNS Resolution** (main.py:153-230):
- Uses public DNS servers (8.8.8.8, 1.1.1.1) to avoid Docker DNS issues
- Attempts to use domain's authoritative nameservers when available
- NS, the zone's SPF, and MX for a name with none of its own come from the zone
  apex (`DomainManager.zone_apex`: an SOA lookup, never a label count — that
  turned naver.co.kr into co.kr), floored at the registrable domain. Zone MX
  rows carry `from_zone`; the response names `queried_name` and `zone`

**GeoIP Databases** (`GeoIpManager` in managers.py):
- `data/GeoLite2-City.mmdb` answers country, city, coordinates and the matched
  block; `data/GeoLite2-ASN.mmdb` the carrier. Both are memory-mapped by
  `maxminddb`, fetched at boot when they do not open (missing or truncated), and
  refreshed every 3 days (MaxMind's licensed endpoint when `MAXMIND_ACCOUNT_ID`
  and `MAXMIND_LICENSE_KEY` are set, free jsdelivr mirrors otherwise)
- Geo-blocking judges the City database's `country_code` (falling back to the
  block's `registered_country`, as geoip2fast's builder did)
- `geoip2fast` survives only as a fallback: its bundled country-only snapshot
  (`geoip2fast-ipv6.dat.gz`, a 2024 build inside the package) is loaded only when
  no City database opened, so a fresh volume still has a country. It is never
  downloaded or refreshed. Loaded, it costs ~50 MB of heap until the next restart
  (its data lives in module globals); the city+ASN geoip2fast build it replaced
  cost ~900 MB, and `/healthz` reports `databases.geoip2fast.source` as
  `bundled` while it answers, `unused` otherwise. `city_overlay` and
  `asn_overlay` keep their historical names
- An address no database places gets `country_code: "--"`, geoip2fast's old
  marker, so geo-blocking and the JSON API see what they always have

**Error Handling**:
- WHOIS failures return `{"error": "..."}` in response rather than 500 errors
- A DNS query that fails is never an empty list: each record type's outcome is
  in `domain.status` (`ok|noanswer|nxdomain|timeout|servfail|error`, from
  `managers.dns_status`), next to the unchanged record keys. The page prints
  `(timed out)`-style text and an NXDOMAIN banner; MCP `dns_records` returns
  `{"error": status}` for a failed type. The MX status is the zone's when the
  name fell back to the zone's MX
- An untrusted TLS certificate is still returned, with `trusted: false` and `verify_error`; an unreachable port 443 or failed handshake is `{"error", "reason"}`; `None` only when no handshake was attempted

**Logging** (main.py:32-51):
- Console and file logging (service.log)
- TimedRotatingFileHandler: Daily rotation, 7-day retention
- Request format: `client={client_ip} lookup={target}`

**MCP endpoint** (`mcp_server.py`):
- Mounted at `/mcp` **before** the `/{domain_ip}` catch-all, which would
  otherwise swallow it — the same ordering constraint as `/healthz`.
- `transport_security=` is mandatory. Without a Host allowlist the SDK arms
  DNS-rebinding protection for localhost only and answers every production
  request with `421 Misdirected Request`, logging one warning and telling the
  client nothing useful.
- The host app's lifespan must enter `mcp.session_manager.run()`; a mounted
  sub-app's own lifespan never runs.
- Starlette's `Mount("/mcp")` cannot match a bare `/mcp` — it compiles
  `path + "/{path:path}"`, so only `/mcp/...` ever matches — hence the
  separate bare-path route registered ahead of the Mount.
- `StreamableHTTPSessionManager.run()` is once-per-instance; calling it twice
  on the same instance raises. The lifespan rebuilds the MCP app on every
  startup so repeated start/stop cycles (as in tests) each get a fresh one.
- Tool return annotations need `dict[str, Any]`, not a bare `dict` — the SDK
  can't build an output schema from a bare `dict`, so the response never gets
  `structuredContent`.
- `/mcp` is exempt from geo-blocking, the suspicious-path detector, and
  automatic bans — every hosted-AI user shares a few provider egress IPs, so a
  ban would take all of them offline at once. It gets its own rate bucket and
  returns `429` with no escalation.
- MCP tests must use `with TestClient(app) as client:`; the rest of the suite
  uses a module-level client, which never runs the lifespan.
- Prefix matching on request paths is dangerous here because `/{domain_ip}` is
  a catch-all: `startswith("/mcp")` also matches the reachable page
  `/mcpfoo.com`. Always match the exact surface (`path == "/mcp" or
  path.startswith("/mcp/")`).

### Project Structure
```
whatismyip/
├── main.py              # FastAPI app: routes, middleware, page rendering, wiring
├── config.py            # all env-driven constants (no I/O, no cycles)
├── managers.py          # GeoIp / Domain / SSL / Header managers
├── security.py          # IP bans, rate limit, suspicious paths, geo-blocking
├── rdap.py              # RDAP-first registration lookups + WHOIS fallback
├── models.py            # Pydantic models (WhoisResponse, GeoRulesUpdate)
├── lookup.py            # transport-agnostic lookup pipeline (gather())
├── textfmt.py           # ?format=text and ?fields=: field table, rendering (pure)
├── mcp_server.py        # public MCP server mounted at /mcp
├── geo.py               # Gazetteer lookup + haversine distance
├── mapgeom.py           # Web Mercator tiles, antimeridian wrap, great-circle arcs
├── viewmodel.py         # response_data -> template view (pure, no I/O)
├── scripts/
│   ├── build_gazetteer.py  # regenerates static/geo/*.json from GeoNames
│   └── fetch_fonts.sh      # vendors Inter + JetBrains Mono into static/fonts/
├── templates/
│   ├── browser.html     # server-rendered page (no client-side templating)
│   ├── error.html       # 400/403/429 page for browsers, same status as the JSON
│   └── _search.html     # search box included by both (app.js finds it by id)
├── static/
│   ├── css/whatismyip.css  # design tokens + layout (dark only)
│   ├── js/app.js           # search, copy, accordions, lazy JSONEditor
│   ├── js/map.js           # paints the server's map payload
│   ├── fonts/              # self-hosted woff2 (CSP blocks font CDNs)
│   └── geo/                # cities.json, countries.json (generated, committed)
├── tests/
│   ├── test_geo.py      # gazetteer + distance (unit)
│   ├── test_mapgeom.py  # projection, tiles, arcs (unit)
│   ├── test_viewmodel.py# view model + WHOIS/SSL rendering (unit)
│   ├── test_rdap.py     # RDAP/WHOIS normalisation + fallback routing (unit)
│   ├── test_page.py     # API + HTML via TestClient
│   ├── test_basic.py    # endpoint smoke tests via TestClient (mocked I/O)
│   └── test_security.py # security subsystem via TestClient (mocked I/O)
├── data/                # Volume mount for persistent data (Docker)
├── Dockerfile           # Multi-stage build with poetry + uv
├── Makefile             # Docker workflow automation
└── pyproject.toml       # Poetry dependencies and project metadata
```

### Map subsystem

**Coordinates**: from GeoLite2-City's `location`. When it has none (or only the
geoip2fast country fallback is loaded), `static/geo/cities.json` (GeoNames cities15000)
matches the city name, with a population-weighted country centroid as the last
resort. Private IPs get no map.

**Projection**: all map math is server-side and unit-tested (`tests/test_mapgeom.py`).
The server emits tile URLs with pixel offsets plus a projected great-circle polyline for
two fixed canvases (desktop band 1440×300, mobile card 350×170); `static/js/map.js` only
paints them.

**Antimeridian**: Seoul → California crosses the Pacific. The map centers on the
shortest-path midpoint longitude and wraps tile x by 2^zoom; a naive Mercator straight
line would run the wrong way across Europe. `fit_zoom()` frames the whole sampled arc,
not just the endpoints, because the great circle bulges far north of both cities.

**Tiles**: fetched by the browser straight from `tile.openstreetmap.org` (no API key).
CSP allows exactly that one host in `img-src`. Tiles are requested one zoom level out and
painted at 2× so a page view costs ~4 requests, and inverted in CSS to turn OSM's light
basemap dark. **Attribution is mandatory** and appears on the map and in the footer.

### Dependencies

**Core:**
- FastAPI + uvicorn: Web framework and ASGI server
- python-whois: WHOIS protocol client
- maxminddb: memory-mapped GeoLite2 City/ASN readers
- geoip2fast: only its bundled country snapshot, the fallback before the first
  GeoLite2 download
- dnspython: DNS resolution and record queries
- APScheduler: Background task scheduling for database updates

**Development:**
- ruff: Linting and formatting
- pytest + requests: Integration testing

### Docker Build Process

The Dockerfile uses a two-stage approach:
1. Export dependencies from Poetry to requirements.txt
2. Install via `uv pip` (faster than pip) with `--system` flag (no virtualenv in container)
3. Copy source files, templates, and static assets
4. Expose port 8000 with uvicorn --reload for development

### Testing Strategy

Every test runs against FastAPI's `TestClient` with the external lookups
(RDAP/WHOIS, GeoIP, DNS, reverse DNS) mocked, so `pytest` needs no running
service and no network. Coverage spans:
- Pure units: gazetteer/distance, map projection, the view model, RDAP/WHOIS normalisation
- Endpoint behaviour and HTML rendering via `TestClient`
- The security subsystem: proxy-header trust, SSRF guards, bans, rate limiting, geo-blocking

```bash
pytest
```

## Commit Conventions
- Never include Codex session URLs or metadata in commit messages.
- Do not add "Co-Authored-By" lines.

