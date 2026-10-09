# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A FastAPI-based web service that provides WHOIS, GeoIP, DNS records, and SSL certificate information for IP addresses and domain names, plus opt-in subdomain discovery via Certificate Transparency logs. The service features automatic GeoIP database updates and serves browser (HTML) and API (JSON) responses from the same URL, chosen by `?format=`, the `Accept` header, or failing both the user-agent.

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
  - `GeoIpManager`: GeoLite2-City (country, city, coordinates) and GeoLite2-ASN (carrier) lookups over memory-mapped mmdb files, refreshed every 3 days via APScheduler (failed refreshes retried hourly), with geoip2fast's bundled country snapshot as the fallback until the first download; `GET /healthz` reports which DBs are actually loaded
  - `DomainManager`: DNS (A, AAAA, MX, NS, CNAME, TXT), reverse DNS, domain validation
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
- `concurrency.py`: the lookup gate and the slow-leg thread pools. At most
  `LOOKUP_CONCURRENCY` lookups run at once: `gather()` holds a slot for its
  legs and the self page for its own. MCP tool calls first take a slot at a
  smaller gate of their own, so they never hold more than
  `MCP_LOOKUP_CONCURRENCY` of the global slots. A full gate is `LookupBusy` —
  a `503` with `Retry-After` over HTTP, never a ban. RDAP/WHOIS (`registration_pool`) and crt.sh
  (`subdomain_pool`) run on their own pools, not the default executor; GeoIP
  runs inline. Imports only `config`, so `subdomains.py` may use it.
- `textfmt.py`: `?format=text` and `?fields=`. The field table (names are
  `mcp_server`'s compact_* shapes, flattened; each field lists the `gather()`
  legs it needs and the target kinds it applies to) and the text/flat-JSON
  rendering. Pure: `main.py` runs the lookup. `-` is "no value", `?` is "the
  lookup failed".
- `subdomains.py`: subdomain discovery from Certificate Transparency (crt.sh),
  opt-in per request. Owns normalization, single-flight, and a global outbound
  budget. Must not import `lookup` or `main` — importing `lookup` builds the
  GeoIP/TLD/Domain managers at module scope, which would drag the GeoIP
  database into every test that touches subdomain code.
- `subdomain_store.py`: SQLite cache for the above, at `data/subdomains.sqlite3`
  (gitignored, along with its WAL sidecars). No network; every operation
  degrades to a miss rather than raising.
- `reputation.py`: IP reputation from key-free public lists (Spamhaus DROP and
  ASN-DROP, Tor exits, X4BNet VPN/datacenter). `ReputationManager` keeps them in
  `data/reputation/` (gitignored) the way `TldNamesManager` keeps the suffix
  list, and answers `check(ip, asn)` from sorted intervals in memory. Imports
  only `config` and the standard library; `lookup.py` builds the singleton.
- `mcp_server.py`: the public MCP server mounted at `/mcp` (official `mcp` SDK,
  Streamable HTTP). Five tools, all thin shells over `lookup.gather()` (or, for
  `subdomains`, over `subdomains.get_subdomains()`) that reshape output for an
  LLM context.
- `main.py`: FastAPI app + middleware + routes + page rendering; wires the managers/security singletons and the scheduler. `negotiate()` (HTML-vs-JSON: `?format=`, then `Accept`, then the user-agent via `BrowserDetector`) lives here.

**API Endpoints**:
- `GET /` - Returns client's own IP information (detects client IP from x-real-ip header or request.client.host)
- `GET /?whois=only` - the caller's own registration, JSON only: the self page
  waits `SELF_WHOIS_SOFT_DEADLINE_SECONDS` (1.5) for WHOIS, then goes out with
  the panel loading, and `app.js` fills it from here. It joins the lookup the
  page left running (`_self_whois_tasks` in `main.py`, which also keeps that
  task alive and its gate slot held) or reads the cache; it starts and gates a
  lookup of its own only when there is neither. JSON/text/`?fields=` on `/`
  still wait for the record
- `GET /{domain_ip}` - Returns information for specified domain or IP address
- `GET /{domain_ip}?subdomains=include|only` - opt-in Certificate Transparency
  subdomain list; see [Subdomain lookup](#subdomain-lookup)

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

**Link previews** (`templates/browser.html` `<head>`, `build_view()` `title` /
`description` / `canonical_path`):
- og:/twitter: tags and `<link rel=canonical>` hang off `public_base_url()`, so
  `PUBLIC_BASE_URL` sets their host and scheme. og:image is the existing
  512×512 `static/image/logo.png`.
- The self page's `<title>` and og: tags are fixed text. A shared link to `/`
  is expanded by a bot whose own IP would otherwise land in someone else's
  chat, so the visitor's address is the `<h1>` and never anywhere in `<head>`.
- Preview bots (Slackbot, Twitterbot, facebookexternalhit, kakaotalk-scrap,
  TelegramBot, WhatsApp, Discordbot, LinkedInBot) are in
  `BrowserDetector.browser_patterns`, i.e. only negotiate()'s user-agent step:
  `?format=` and `Accept` still win.

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
- A call that failed outright returns `_fail()`: a `CallToolResult` with
  `isError` set and `{"error": ...}` as `structuredContent`. The annotation
  stays `dict[str, Any]` anyway: the SDK refuses `dict | CallToolResult`, and
  skips output validation for an isError result. A gap inside an answer (one
  DNS type, the registration leg, `registered: false`, `stale: true`) stays a
  normal result. The SDK's OTel middleware counts only isError results as
  `error.type=tool_error`, so this split is what SigNoz's tool error rate sees.
- `/mcp` is exempt from geo-blocking, the suspicious-path detector, and
  automatic bans — every hosted-AI user shares a few provider egress IPs, so a
  ban would take all of them offline at once. It gets its own rate bucket and
  returns `429` with no escalation. An automatic ban earned on the lookup
  paths doesn't carry over either: `/mcp` checks
  `is_banned(ip, reason="manual")`, so only an admin ban applies there.
- MCP tests must use `with TestClient(app) as client:`; the rest of the suite
  uses a module-level client, which never runs the lifespan.
- Prefix matching on request paths is dangerous here because `/{domain_ip}` is
  a catch-all: `startswith("/mcp")` also matches the reachable page
  `/mcpfoo.com`. Always match the exact surface (`path == "/mcp" or
  path.startswith("/mcp/")`).
- Never type tool names into `templates/browser.html`. The `mcp-tools` meta
  tag and the Raw JSON panel's tool list render `registered_tool_names()`, so
  they follow `tools/list`, including `subdomains` dropping out under
  `SUBDOMAIN_ENABLED=false`.
- `server.json` is the official MCP Registry entry, published by hand through
  `.github/workflows/mcp-publish.yml` with GitHub OIDC. Never switch it to
  `mcp-publisher login http`: the registry would fetch
  `/.well-known/mcp-registry-auth`, which the suspicious-path detector bans
  for 24 hours.

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
├── concurrency.py       # lookup gate (503 when full) + RDAP/WHOIS and crt.sh pools
├── textfmt.py           # ?format=text and ?fields=: field table, rendering (pure)
├── subdomains.py        # crt.sh adapter, normalization, cache-fill orchestration
├── subdomain_store.py   # SQLite cache for subdomains.py (data/subdomains.sqlite3)
├── reputation.py        # IP reputation lists (data/reputation/), bisect lookups
├── mcp_server.py        # public MCP server mounted at /mcp
├── geo.py               # Gazetteer lookup + haversine distance
├── mapgeom.py           # Web Mercator tiles, antimeridian wrap, great-circle arcs
├── viewmodel.py         # response_data -> template view (pure, no I/O)
├── scripts/
│   ├── build_gazetteer.py  # regenerates static/geo/*.json from GeoNames
│   └── fetch_fonts.sh      # vendors Inter + JetBrains Mono into static/fonts/
├── templates/
│   ├── browser.html     # server-rendered page (no client-side templating)
│   ├── error.html       # 400/403/429/503 page for browsers, same status as the JSON
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
│   ├── test_subdomains.py       # crt.sh adapter, normalization, single-flight (unit)
│   ├── test_subdomain_store.py  # SQLite cache, degrades to a miss on failure (unit)
│   ├── test_reputation.py       # list parsers, intervals, grade, download guard, surfaces
│   ├── test_page.py     # API + HTML via TestClient
│   ├── test_basic.py    # endpoint smoke tests via TestClient (mocked I/O)
│   ├── test_concurrency_gate.py # gate 503s, what takes no slot, pool isolation
│   └── test_security.py # security subsystem via TestClient (mocked I/O)
├── data/                # Volume mount for persistent data (Docker); also holds
│                         # subdomains.sqlite3 (gitignored, created on first use)
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
CSP allows exactly that one host in `img-src`. Tile `<img>`s must send a Referer:
OSM blocks referer-less web traffic with a 403 "Access blocked" tile, so map.js
sets `referrerPolicy = "strict-origin"` on them, overriding the page-wide
`no-referrer` without leaking the lookup path. Tiles are requested one zoom level out and
painted at 2× so a page view costs ~4 requests, and inverted in CSS to turn OSM's light
basemap dark. **Attribution is mandatory** and appears on the map and in the footer.

### Subdomain lookup

**Opt-in by query parameter, not by route.** `?subdomains=include|only` on the
existing `/{domain_ip}` route. The security middleware reads `request.url.path`
(`main.py:508`, `main.py:689`), which excludes the query string, so the path
stays `/{domain}` and `WhitelistManager` classifies it exactly as before — no
security policy was widened to add this. A route like `/api/certs/{domain}`
would need `lookup_patterns` widened — it matches a single path segment — and
without that change, a target matching a detector rule (`\.config$`, `\.log$`
and friends use `search()`) would ban a legitimate visitor for 24 hours.

**crt.sh constraints, measured against the live service on 2026-09-28/29.**
crt.sh publishes no bulk dump — its `certwatch` database is the entire CT
ecosystem, billions of certificates. Its Postgres endpoint times out on every
query form tried (21-57s), so deduplication happens on our side, at ingest. Its
HTTP endpoint offers no server-side dedup either: `&deduplicate=Y` hangs, and
`&exclude=expired` is *slower* for only a 23% size reduction. Latency varied
2.6s-13.5s for the *same* query within one hour — that unpredictability is why
a cached lookup must not depend on it. One response is also mostly redundant:
1,224 rows reduce to 58 names for 1kko.com; nasa.gov's 3,531 rows give 2,585
names.

**Names containing `@` are discarded.** crt.sh's `name_value` carries
`rfc822Name` entries from S/MIME certificates — real people's email addresses,
551 of them in nasa.gov's data alone. This is a privacy rule with its own test
(`normalize_names` in `subdomains.py`), not a formatting nicety.

**A target that would widen the query is refused.** crt.sh is queried as
`%.{domain}`, so the target *is* the query: `com`, `co.uk` or `github.io` asks
for every subdomain under a public suffix, and a `%` (or a `_` in the
registered name) is a wildcard of the caller's choosing. Either could get the
service IP blocked. `subdomains.invalid_target_reason()` is the one check — the
`?subdomains=` gate in `main.py`, the MCP `subdomains` tool, and
`get_subdomains()` itself as a backstop all call it. `is_valid_domain` is no
substitute: it asks only whether a public suffix is present, and `com` has one.

**No scheduler job**, unlike GeoIP and the public suffix list. Those are read
by every request, so pre-refreshing always pays. This store is filled and read
on demand, so a periodic sweep would re-fetch domains nobody asked about again.
`get_subdomains()` instead does stale-while-revalidate on read: a stale entry
is served immediately, with a refresh kicked off in the background.

**A failure is never an empty list.** Both the accordion panel and the MCP
`subdomains` tool distinguish "no subdomains" from "could not ask" — an empty
list reads to a model, and to a person, as a confident fact, so a failed fetch
returns `{"error": "..."}` instead.

**`subdomains.py` must not import `lookup` or `main`.** Importing `lookup`
builds `GeoIpManager()`, `TldNamesManager()` and `DomainManager()` at module
scope, which would load the GeoIP database into every test that so much as
touches subdomain code. `subdomain_store.py` owns durability (SQLite at
`data/subdomains.sqlite3`, gitignored along with its WAL sidecars) and knows
nothing about crt.sh; `subdomains.py` owns the source and knows nothing about
SQL. Every store operation degrades to a miss rather than raising, so a
read-only volume or a full disk costs the cache, not the request.

### IP reputation

**Downloaded by the scheduler, read from memory.** The `refresh-reputation` job
fetches each list into `data/reputation/` once its copy is a day old (at boot
only what is missing or stale); `check()` is a bisect over merged integer
ranges, so a lookup makes no outbound request and adds no SSRF surface.
`lookup.ip_reputation()` is the one entry point for `gather()`, the self page
and `whoami_caller`; it takes the AS number for ASN-DROP from GeoLite2-ASN.

**Spamhaus allows one download a day, and that is enforced in code.** Each
file's request time is written to `<file>.requested` before the request is sent,
so a failed request and a restart both count. Do not make that gap
configurable. Spamhaus also asks for credit: its notice travels in
`reputation.attribution`, the page card and `/privacy`.

**"None" is not "safe".** `level` is null when no list could be checked; a
stale (over `REPUTATION_MAX_AGE_HOURS`), missing or family-mismatched list is in
`unavailable` with its reason, never silently dropped. The page, the MCP tool
descriptions and `?fields=risk_level` (which stays out of the text block) all
keep that distinction. The service's own ban list is never a signal.

**Tests.** `tests/conftest.py` sets `REPUTATION_ENABLED=false`, so importing
`main` schedules no download and every other test sees the responses it always
did. `tests/test_reputation.py` builds enabled managers over synthetic lists and
monkeypatches `lookup.reputation_manager` (and `main.reputation_manager` for
`/healthz`).

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
- Subdomain discovery: crt.sh adapter normalisation/dedup (including the `@`
  discard rule), single-flight, the outbound budget, and the SQLite cache's
  degrade-to-a-miss behaviour
- Endpoint behaviour and HTML rendering via `TestClient`
- The security subsystem: proxy-header trust, SSRF guards, bans, rate limiting, geo-blocking

```bash
pytest
```

## Commit Conventions
- Never include Claude session URLs or metadata in commit messages.
- Do not add "Co-Authored-By" lines.

