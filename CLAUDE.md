# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A FastAPI-based web service that provides WHOIS, GeoIP, DNS records, and SSL certificate information for IP addresses and domain names. The service features automatic GeoIP database updates and supports both browser (HTML) and API (JSON) responses based on user-agent detection.

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
  - `GeoIpManager`: GeoIP database updates (every 3 days via APScheduler) + geoip2fast lookups with a GeoLite2-City coordinate overlay
  - `DomainManager`: DNS (A, MX, NS, CNAME, TXT), reverse DNS, domain validation
  - `SSLManager`: SSL certificate retrieval for HTTPS endpoints
  - `HeaderManager`: strips proxy/forwarding headers
- `security.py` — request-security subsystem: `IPBanManager`, `RateLimiter`, `SuspiciousPatternDetector`, `WhitelistManager`, `GeoBlockManager`
- `rdap.py`: RDAP lookups (whoisit) with a port-43 WHOIS fallback, both normalised to one canonical dict
- `models.py`: Pydantic models (`WhoisResponse`, `GeoRulesUpdate`)
- `main.py`: FastAPI app + middleware + routes + page rendering; wires the managers/security singletons and the scheduler. `BrowserDetector` (HTML-vs-JSON by user-agent) lives here.

**API Endpoints**:
- `GET /` - Returns client's own IP information (detects client IP from x-real-ip header or request.client.host)
- `GET /{domain_ip}` - Returns information for specified domain or IP address

### Response Flow

1. **Client Detection**: User-agent determines response format (HTML template for browsers, JSON for API clients)
2. **IP Resolution**: Domains are resolved to IP addresses via DNS A records
3. **Data Gathering**: Parallel collection of WHOIS, GeoIP, DNS records, and SSL certificate data
4. **Response Assembly**: All data combined into unified response structure (WhoisResponse model)
5. **Logging**: All requests logged with client IP and lookup target

### Key Technical Details

**DNS Resolution** (main.py:153-230):
- Uses public DNS servers (8.8.8.8, 1.1.1.1) to avoid Docker DNS issues
- Attempts to use domain's authoritative nameservers when available
- Handles subdomain removal for NS/MX record lookups (uses base domain only)

**GeoIP Database** (main.py:120-132):
- Auto-updates from geoip2fast CDN every 3 days via background scheduler
- Database file: `geoip2fast-city-asn-ipv6.dat.gz`
- Includes city, ASN, and IPv6 support

**Error Handling**:
- WHOIS failures return `{"error": "..."}` in response rather than 500 errors
- DNS resolution failures logged and handled gracefully with empty records
- SSL certificate failures return `None` without breaking response

**Logging** (main.py:32-51):
- Console and file logging (service.log)
- TimedRotatingFileHandler: Daily rotation, 7-day retention
- Request format: `client={client_ip} lookup={target}`

### Project Structure
```
whatismyip/
├── main.py              # FastAPI app: routes, middleware, page rendering, wiring
├── config.py            # all env-driven constants (no I/O, no cycles)
├── managers.py          # GeoIp / Domain / SSL / Header managers
├── security.py          # IP bans, rate limit, suspicious paths, geo-blocking
├── rdap.py              # RDAP-first registration lookups + WHOIS fallback
├── models.py            # Pydantic models (WhoisResponse, GeoRulesUpdate)
├── geo.py               # Gazetteer lookup + haversine distance
├── mapgeom.py           # Web Mercator tiles, antimeridian wrap, great-circle arcs
├── viewmodel.py         # response_data -> template view (pure, no I/O)
├── scripts/
│   ├── build_gazetteer.py  # regenerates static/geo/*.json from GeoNames
│   └── fetch_fonts.sh      # vendors Inter + JetBrains Mono into static/fonts/
├── templates/
│   └── browser.html     # server-rendered page (no client-side templating)
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

**Coordinates**: geoip2fast returns city names but `latitude`/`longitude` are ALWAYS
`null`. Coordinates come from `static/geo/cities.json` (GeoNames cities15000), with a
population-weighted country centroid as fallback. Private IPs get no map.

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
- geoip2fast: Lightweight GeoIP lookup library
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
- Never include Claude session URLs or metadata in commit messages.
- Do not add "Co-Authored-By" lines.

