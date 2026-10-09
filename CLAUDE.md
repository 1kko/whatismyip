# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) and other coding
agents when working with code in this repository. AGENTS.md only points here,
so this is the one copy to keep current.

Code is referred to by symbol (`main.security_middleware`,
`managers.DomainManager.get_records`), never by line number: grep for the name.

## Project Overview

A FastAPI service that reports registration (RDAP, with port-43 WHOIS as a
fallback for domains), GeoIP, DNS records, the TLS certificate and IP reputation
for an IP address or a domain name, plus opt-in subdomain discovery from
Certificate Transparency logs. One URL serves a server-rendered page to
browsers, JSON to API clients and plain text to shells, chosen by `?format=`,
then the `Accept` header, then the user-agent. An MCP server at `/mcp` exposes
the same lookups to AI agents. The GeoIP databases, the public suffix list and
the reputation lists are downloaded into `data/` and refreshed by a background
scheduler, so a lookup reads them locally.

## Development Commands

### Environment Setup
```bash
poetry install   # then prefix commands with `poetry run`
```

### Building
```bash
make build   # docker build -t whatismyip . (after pruning dangling images)
make         # same
```

### Running the Application

**Docker:**
```bash
make serve   # detached, --restart unless-stopped, data/ mounted at /app/data
make run     # foreground
make logs    # follow the container's logs
make stop
```

Production does not use these. Once CI passes on `main`,
`.github/workflows/deploy.yml` has Coolify build and deploy the image, then polls
`/healthz` until its `version` is the merged commit.

**Directly (development):**
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
python main.py   # the same app on port 8000, without --reload
```

Either way the boot work runs in the app lifespan before the port is bound
(see [Boot and the scheduler](#boot-and-the-scheduler)): on an empty `data/`,
the first start downloads GeoLite2-City and GeoLite2-ASN (tens of MB) and the
public suffix list, and then the reputation lists in the background.

### Testing
```bash
poetry run pytest                      # the whole suite; no running server
poetry run pytest tests/test_rdap.py   # one file
poetry run pytest tests/test_basic.py::TestBasic::test_get_domain_info
poetry run pytest -v
```

Every test uses FastAPI's `TestClient`. The suite is not fully offline: see
[Testing Strategy](#testing-strategy) for what still reaches the network.

### Code Quality
```bash
poetry run ruff check .          # E, F and S (Bandit) rules
poetry run ruff format .         # CI runs `ruff format --check .`
```

## Architecture

### Core Components

**Modules:**
- `config.py`: the environment-driven constants (timeouts, cache TTLs, file
  paths, rate-limit/ban settings, geo-block defaults, trusted proxies, map
  canvases, feature switches). It calls `load_dotenv()` and imports nothing
  app-local, so every module can import it without a cycle. Two settings are
  read elsewhere: `ADMIN_API_KEY` in `main.py`, and `GEO_CITIES_FILE` /
  `GEO_COUNTRIES_FILE` in `geo.py`.
- `managers.py` — one wrapper per data source:
  - `GeoIpManager`: GeoLite2-City (country, city, coordinates) and GeoLite2-ASN
    (carrier) lookups over memory-mapped mmdb files, refreshed every 3 days
    (`update_city_database`, `update_asn_database`), with geoip2fast's bundled
    country snapshot as the fallback until the first download.
    `database_status()` and `build_ages()` feed `/healthz`
  - `TldNamesManager`: the Public Suffix List that `tld` parses, kept in
    `data/tld/`. Constructed before `DomainManager` (see `lookup.py`), because
    it repoints `tld` at the data volume
  - `DomainManager`: `is_valid_domain` (does the target have a public suffix),
    `zone_apex`, `get_records` (the record sweep) and `perform_reverse_lookup`
    (PTR)
  - `SSLManager.get_ssl_info`: the certificate, read from a verified IP
  - `HeaderManager`: strips proxy/forwarding headers from the echoed headers
  - module functions: `_recursive_resolver` (every DNS query goes through it),
    `dns_status`, `_with_host_ips`
- `security.py` — the request-security subsystem: `IPBanManager`,
  `IpRuleManager` (hand-written `data/ip_rules.json`), `RateLimiter`,
  `SuspiciousPatternDetector`, `WhitelistManager`, `GeoBlockManager`, and
  `get_client_ip` / `client_ip_from_scope` (proxy headers are trusted only from
  `TRUSTED_PROXIES`, or from private, loopback and link-local peers when that is
  unset). `main.security_middleware` applies them.
- `rdap.py`: `lookup_rdap` (whoisit) and `normalize_whois` (python-whois's
  port-43 output) both produce one canonical dict (`CANONICAL_FIELDS`).
  `rdap_breaker` (a `CircuitBreaker`) skips an RDAP host after repeated
  failures; `refresh_rdap_bootstrap` keeps IANA's bootstrap registry current.
- `models.py`: one Pydantic model, `GeoRulesUpdate`, the body of
  `PUT /admin/geo/rules`. Responses are plain dicts with no response model.
- `lookup.py`: the transport-agnostic lookup pipeline, `gather()`, shared by
  `GET /{domain_ip}` and the MCP tools. Also `classify_target`, `is_safe_ip`,
  `lookup_whois` (RDAP first, port-43 only for a domain, cached in
  `_whois_cache`), `lookup_location` and `ip_reputation`. Raises
  `PrivateAddressError` and `InvalidTargetError` rather than `HTTPException`
  so it stays free of FastAPI. `gather(legs=)` runs only the named legs
  (`LEGS`); the default (None) runs them all, and the page, the full JSON and
  MCP all use the default. Builds the manager singletons (`geo_ip_manager`,
  `tld_names_manager`, `domain_manager`, `reputation_manager`) at import, which
  reads `data/` but makes no network call. The self page (`GET /`) does not use
  `gather()`: `main._self_lookup` runs its legs.
- `concurrency.py`: the lookup gate and the slow-leg thread pools. At most
  `LOOKUP_CONCURRENCY` lookups run at once: `gather()` holds a slot for its
  legs and the self page for its own. MCP tool calls first take a slot at a
  smaller gate of their own, so they never hold more than
  `MCP_LOOKUP_CONCURRENCY` of the global slots. A full gate is `LookupBusy` —
  a `503` with `Retry-After` over HTTP, never a ban. RDAP/WHOIS
  (`registration_pool`) and crt.sh (`subdomain_pool`) run on their own pools,
  not the default executor; GeoIP runs inline. Imports only `config`, so
  `subdomains.py` may use it.
- `textfmt.py`: `?format=text` and `?fields=`. The field table (names are
  `mcp_server`'s compact_* shapes, flattened; each field lists the `gather()`
  legs it needs and the target kinds it applies to) and the text/flat-JSON
  rendering. Pure: `main.py` runs the lookup. `-` is "no value", `?` is "the
  lookup failed".
- `subdomains.py`: subdomain discovery from Certificate Transparency (crt.sh),
  opt-in per request. `get_subdomains()` owns normalization, single-flight, and
  a global outbound budget; `invalid_target_reason()` decides which targets may
  be sent at all. Must not import `lookup` or `main` — importing `lookup` builds
  the GeoIP/TLD/Domain managers at module scope, which would drag the GeoIP
  database into every test that touches subdomain code.
- `subdomain_store.py`: `SubdomainStore`, the SQLite cache for the above, at
  `data/subdomains.sqlite3` (gitignored, along with its WAL sidecars). No
  network; every operation degrades to a miss rather than raising.
- `reputation.py`: IP reputation from key-free public lists (Spamhaus DROP and
  ASN-DROP, Tor exits, X4BNet VPN/datacenter). `ReputationManager` keeps them in
  `data/reputation/` (gitignored) the way `TldNamesManager` keeps the suffix
  list, and answers `check(ip, asn)` from sorted intervals in memory. Imports
  only `config` and the standard library; `lookup.py` builds the singleton.
- `mcp_server.py`: the public MCP server mounted at `/mcp` (official `mcp` SDK,
  Streamable HTTP, stateless). Five tools: `lookup`, `dns_records` and
  `ssl_certificate` over `lookup.gather()`, `subdomains` over
  `subdomains.get_subdomains()` (registered only under `SUBDOMAIN_ENABLED`),
  and `whoami_caller` over `lookup.lookup_location()` and
  `lookup.ip_reputation()`. Each reshapes its data for an LLM context (the
  `compact_*` functions). `build_mcp`, `McpDispatch`, `McpBarePathRoute` and
  `McpDisabled` are the mount plumbing `main.py` wires.
- `viewmodel.py`: `build_view()` turns a response dict into what
  `templates/browser.html` renders. Pure, with no I/O, and it imports only
  `config`, `reputation.grade` and the standard library, so `mcp_server.py`
  reuses its certificate helpers without a cycle.
- `geo.py`: `Gazetteer` (coordinates from `static/geo/*.json`) and
  `haversine_km`.
- `mapgeom.py`: `build_canvas()` and the Web Mercator, antimeridian and
  great-circle math behind it.
- `healthcheck.py`: the Docker `HEALTHCHECK`: exit 0 when `/healthz` answers
  200, whatever its `status`.
- `main.py`: the FastAPI app, middleware, routes and page rendering; wires the
  manager and security singletons and the scheduler. The symbols to know:
  `lifespan` and `start_background_work` (boot work), `scheduler` and
  `_refresh_with_retry`, `security_middleware` and
  `security_headers_middleware`, `negotiate()` (HTML/JSON/text: `?format=`,
  then `Accept`, then the user-agent via `BrowserDetector`), `health_reasons()`
  and `healthz`, `build_map_payload`, `render_page`, `render_error` and
  `render_refused_target`, `_self_lookup`, and the routes `get_self_info`,
  `get_ip_info` and `head_lookup`.

**Endpoints** (single-segment fixed routes are declared before the
`/{domain_ip}` catch-all, which would otherwise swallow them):
- `GET /` - the caller's own address (`security.get_client_ip`), looked up by
  `main._self_lookup`. `?format=text` answers the bare address with no lookup
- `GET /?whois=only` - the caller's own registration, JSON only: the self page
  waits `SELF_WHOIS_SOFT_DEADLINE_SECONDS` (1.5) for WHOIS, then goes out with
  the panel loading, and `app.js` fills it from here. It joins the lookup the
  page left running (`_self_whois_tasks` in `main.py`, which also keeps that
  task alive and its gate slot held) or reads the cache; it starts and gates a
  lookup of its own only when there is neither. JSON/text/`?fields=` on `/`
  still wait for the record
- `GET /{domain_ip}` - a domain or an IP address (IPv4 or IPv6), through
  `lookup.gather()`
- `GET /{domain_ip}?subdomains=include|only` - opt-in Certificate Transparency
  subdomain list; see [Subdomain lookup](#subdomain-lookup)
- `?format=html|json|text` and `?fields=` on both lookup routes
- `HEAD /`, `HEAD /{domain_ip}` - `main.head_lookup`: `200` with the
  Content-Type a GET would negotiate, and no lookup
- `GET /healthz` - `ok` or `degraded` with `reasons` (`main.health_reasons`,
  no network calls), the deployed `version`, and which datasets are loaded
- `GET /robots.txt`, `GET /favicon.ico` (a `301` to `/static/favicon.ico`),
  `GET /privacy` - fixed answers, exempt from the rate limit like `/static/`
- `POST /mcp` - the MCP endpoint; every other method is a `405`
- `/admin/*` - bans, per-IP rules, geo rules and stats, behind the `api-key`
  header (`ADMIN_API_KEY`); a missing or wrong key is a `404`

### Response Flow

1. **Format Negotiation**: `negotiate()` picks the response format: `?format=html|json|text` first (unknown value -> 400), then an `Accept` header that names `text/html`/`application/json`/`text/plain` (q-values honoured), and only when `Accept` is absent or `*/*` the user-agent (`BrowserDetector`: browsers get HTML; PowerShell, despite its `Mozilla/5.0`, gets JSON). `text` is `textfmt.py`'s: the bare client IP on `/`, a `key: value` block on `/{domain_ip}`; `?fields=` (either route; JSON unless text was negotiated) runs only the `gather(legs=)` the named fields need. Both lookup routes send `Vary: Accept, User-Agent` and `Cache-Control: no-store`, errors included
2. **Classification**: `lookup.classify_target` calls the target a domain,
   `ipv4`, `ipv6` or `invalid` before any network work; an invalid target is a
   `400` (`InvalidTargetError`), and so is a private or reserved address
   (`PrivateAddressError`, from `is_safe_ip`). A browser gets
   `main.render_refused_target`'s error page instead of the JSON
3. **IP Resolution**: a domain's A record, or its AAAA record when it has no A
   (an IPv6-only host), from the public resolvers; the address must pass
   `is_safe_ip` too
4. **Data Gathering** (`lookup._run_legs`, holding a `lookup_gate` slot): the
   registration lookup runs alongside everything else; a domain's DNS sweep and
   TLS handshake run concurrently; an IP gets its PTR, then a sweep of the PTR
   name. GeoIP is read inline, and reputation from the lists in memory
5. **Response Assembly**: `main.get_ip_info` builds a plain dict (`address`,
   `resolved_ip`, `resolution`, `datetime`, `domain`, `location`, `whois`,
   `ssl`, `headers`, `map`, `distance_km`, `origin`, `elapsed_ms`, plus
   `reputation` and `subdomains` when present) and returns it as JSON or
   renders it through `render_page` and `viewmodel.build_view()`
6. **Logging**: every lookup is logged as `client={client_ip} lookup={target}`

### Key Technical Details

#### Boot and the scheduler

`main.lifespan`, `main.start_background_work`:
- Importing `main` makes no network call and leaves the scheduler stopped
  (`tests/test_boot.py` checks both in a fresh interpreter). It builds the
  managers, which read `data/`, and registers the scheduler's jobs.
- The lifespan, which uvicorn enters once per process before binding the port,
  runs `start_background_work()`: it starts the `BackgroundScheduler`, then
  refreshes the public suffix list if it has aged out (a fresh volume holds only
  the bundled seed, stamped expired) and fetches each GeoLite2 database that did
  not open (`_fetch_unloaded_geoip_dbs`). Startup waits for those fetches, so
  the first request finds the databases. The lifespan then starts the MCP
  session manager, and on shutdown stops the scheduler without waiting for a
  refresh in flight (each one writes a temp file and `os.replace()`s it).
- `BACKGROUND_REFRESH_ENABLED=false` skips the scheduler and the boot fetches.
  Only `tests/conftest.py` sets it; in production nothing would ever refresh,
  and `/healthz` would report `scheduler_stopped`.
- Jobs: GeoLite2-City and -ASN every 3 days; the public suffix list daily
  (re-fetched once older than `TLD_MAX_AGE_DAYS`); the RDAP bootstrap daily;
  the reputation lists every `REPUTATION_CHECK_INTERVAL_SECONDS` (first run at
  start); expired-ban cleanup; and cleanup of both rate-limiter buckets.
  `_refresh_with_retry` retries a failed GeoLite2 or suffix-list refresh on a
  one-shot timer and counts consecutive failures for `/healthz`
  (`_refresh_failures`).
- A `BackgroundScheduler` that has been shut down cannot run jobs again (its
  executor pool is gone), so a test that drives the lifespan swaps in a fresh
  scheduler.

#### DNS Resolution

`managers._recursive_resolver`, `managers.DomainManager.get_records`,
`managers.DomainManager.zone_apex`:
- Every query — the gating A/AAAA in `lookup._run_legs`, the sweep, NS/MX host
  addresses, PTR — goes to `config.PUBLIC_RESOLVERS` (8.8.8.8, 1.1.1.1) with
  `DNS_QUERY_TIMEOUT` / `DNS_QUERY_LIFETIME`. Never the system resolver
  (Docker's 127.0.0.11) and never a domain's own nameservers:
  `get_records`'s `ns_servers` argument is accepted and ignored.
- The sweep asks A, AAAA, MX, NS, CNAME, TXT (and SPF from it) and PTR
  concurrently. NS and MX host addresses go through `_with_host_ips`, capped at
  `DNS_HOST_RESOLVE_LIMIT`; rows past the cap carry `ip_skipped`. A TXT string
  over 255 bytes arrives split and is joined with no separator (RFC 7208).
- NS, the zone's SPF, and MX for a name with none of its own come from the zone
  apex (`DomainManager.zone_apex`: an SOA lookup, never a label count — that
  turned naver.co.kr into co.kr), floored at the registrable domain. Zone MX
  rows carry `from_zone`; the response names `queried_name` and `zone`
- `zone_apex`'s floor comes from `tld.get_fld(..., search_private=False)`,
  which reads `tld`'s separate public-only list
  (`data/tld/res/effective_tld_names_public_only.dat.txt`). `TldNamesManager`
  keeps it as a byte copy of the full list, at boot (`_mirror_public_only`)
  and on every refresh: `tld`'s public-only parser stops at
  `===BEGIN PRIVATE DOMAINS===`, so the full list parses to the ICANN-only
  one. Without that copy `tld` downloads `?publiconly` itself, inside the
  request and with no timeout, and offline `get_fld` raises `TypeError` even
  with `fail_silently`.

#### GeoIP Databases

`managers.GeoIpManager`:
- `data/GeoLite2-City.mmdb` answers country, city, coordinates and the matched
  block; `data/GeoLite2-ASN.mmdb` the carrier. Both are memory-mapped by
  `maxminddb`, fetched by the boot work when they do not open (missing or
  truncated), and refreshed every 3 days (MaxMind's licensed endpoint when
  `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY` are set, falling back to the
  free jsdelivr mirrors, which are the only source otherwise)
- Geo-blocking judges the City database's `country_code` (falling back to the
  block's `registered_country`, as geoip2fast's builder did)
- `geoip2fast` survives only as a fallback: its bundled country-only snapshot
  (`geoip2fast-ipv6.dat.gz`, a 2024 build inside the package,
  `managers.GEOIP_FALLBACK_FILE`) is loaded only when no City database opened,
  so a fresh volume still has a country. It is never downloaded or refreshed.
  Loaded, it costs ~50 MB of heap until the next restart (its data lives in
  module globals); the city+ASN geoip2fast build it replaced cost ~900 MB, and
  `/healthz` reports `databases.geoip2fast.source` as `bundled` while it
  answers, `unused` otherwise. `city_overlay` and `asn_overlay` keep their
  historical names
- An address no database places gets `country_code: "--"`
  (`managers.NO_COUNTRY`), geoip2fast's old marker, so geo-blocking and the
  JSON API see what they always have

#### Registration (RDAP and WHOIS)

`lookup.lookup_whois` runs `rdap.lookup_rdap` on `registration_pool` within
`RDAP_TIMEOUT_SECONDS`. A domain RDAP cannot answer falls back to port-43 WHOIS
(`lookup._whois_fallback`); an IP never does, because python-whois answers an
IP with the registration of its PTR name's domain, so it gets
`{"error": RIR_RDAP_UNAVAILABLE}`. Answers are cached for `WHOIS_CACHE_TTL`
(6 h), failures for `WHOIS_CACHE_ERROR_TTL` (5 min).

#### Error Handling

- A registration failure is `{"error": "..."}` in the response, never a 500
- A DNS query that fails is never an empty list: each record type's outcome is
  in `domain.status` (`ok|noanswer|nxdomain|timeout|servfail|error`, from
  `managers.dns_status`), next to the unchanged record keys. The page prints
  `(timed out)`-style text and an NXDOMAIN banner; MCP `dns_records` returns
  `{"error": status}` for a failed type. The MX status is the zone's when the
  name fell back to the zone's MX
- An untrusted TLS certificate is still returned, with `trusted: false` and `verify_error`; an unreachable port 443 or failed handshake is `{"error", "reason"}`; `None` only when no handshake was attempted
- A browser gets `templates/error.html` for a 400, 403, 429 or 503, with the
  same status as the JSON (`main.render_error`); every other client gets the
  JSON

#### Logging

Configured at `main` module scope:
- Console and file logging (`service.log`, in the working directory)
- `TimedRotatingFileHandler`: daily rotation, `LOG_RETENTION_DAYS` (7) kept;
  `/privacy` reads the same constant
- Request format: `client={client_ip} lookup={target}`

#### Link previews

`templates/browser.html` `<head>`, `build_view()` `title` / `description` /
`canonical_path`:
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

#### MCP endpoint

`mcp_server.py`:
- Mounted at `/mcp` **before** the `/{domain_ip}` catch-all, which would
  otherwise swallow it — the same ordering constraint as `/healthz`.
- `transport_security=` is mandatory. Without a Host allowlist the SDK arms
  DNS-rebinding protection for localhost only and answers every production
  request with `421 Misdirected Request`, logging one warning and telling the
  client nothing useful. The allowlist is `MCP_ALLOWED_HOSTS`.
- The host app's lifespan must enter `mcp.session_manager.run()`; a mounted
  sub-app's own lifespan never runs. `MCP_ENABLED=false` mounts
  `McpDisabled` (a `404`) instead, and the lifespan skips it.
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
  ban would take all of them offline at once. It gets its own rate bucket
  (`mcp_rate_limiter`) and returns `429` with no escalation. An automatic ban
  earned on the lookup paths doesn't carry over either: `/mcp` checks
  `is_banned(ip, reason="manual")`, so only an admin ban applies there.
- The SDK buffers a request body with no cap of its own, so
  `security_middleware` refuses a POST to `/mcp` over `MCP_MAX_BODY_BYTES`, or
  without a numeric `Content-Length`, with a `413` before the body is read.
- MCP tests must use `with TestClient(app) as client:`; the rest of the suite
  uses a module-level client, which never runs the lifespan. Under the suite's
  `BACKGROUND_REFRESH_ENABLED=false` that lifespan starts only the MCP session
  manager.
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
  for 24 hours. `docs/ops/mcp-directories.md` covers the other directories.

### Project Structure
```
whatismyip/
├── main.py              # FastAPI app: lifespan, middleware, routes, page rendering, wiring
├── config.py            # env-driven constants (reads .env; imports nothing app-local)
├── managers.py          # GeoIp / TldNames / Domain / SSL / Header managers
├── security.py          # IP bans, per-IP rules, rate limit, suspicious paths, geo-blocking
├── rdap.py              # RDAP-first registration lookups + WHOIS normalisation, breaker
├── models.py            # GeoRulesUpdate, the one Pydantic model
├── lookup.py            # transport-agnostic lookup pipeline (gather()), manager singletons
├── concurrency.py       # lookup gate (503 when full) + RDAP/WHOIS and crt.sh pools
├── textfmt.py           # ?format=text and ?fields=: field table, rendering (pure)
├── subdomains.py        # crt.sh adapter, normalization, cache-fill orchestration
├── subdomain_store.py   # SQLite cache for subdomains.py (data/subdomains.sqlite3)
├── reputation.py        # IP reputation lists (data/reputation/), bisect lookups
├── mcp_server.py        # public MCP server mounted at /mcp
├── geo.py               # Gazetteer lookup + haversine distance
├── mapgeom.py           # Web Mercator tiles, antimeridian wrap, great-circle arcs
├── viewmodel.py         # response_data -> template view (pure, no I/O)
├── healthcheck.py       # Docker HEALTHCHECK: /healthz answers 200 or not
├── server.json          # official MCP Registry entry (see mcp-publish.yml)
├── scripts/
│   ├── build_gazetteer.py  # regenerates static/geo/*.json from GeoNames
│   └── fetch_fonts.sh      # vendors Inter + JetBrains Mono into static/fonts/
├── templates/
│   ├── browser.html     # server-rendered lookup page (no client-side templating)
│   ├── error.html       # 400/403/429/503 page for browsers, same status as the JSON
│   ├── privacy.html     # /privacy, filled from the constants the code runs on
│   ├── _search.html     # search box included by browser.html and error.html (app.js finds it by id)
│   └── _footer.html     # footer included by all three pages
├── static/
│   ├── css/whatismyip.css  # design tokens + layout (dark only); jsoneditor.css is vendored
│   ├── js/app.js           # search, copy, accordions, WHOIS fill-in, subdomain panel, lazy JSONEditor
│   ├── js/map.js           # paints the server's map payload, with the attribution
│   ├── js/fingerprint.js   # self page's browser fingerprint, computed and kept client-side
│   ├── js/webrtc.js        # opt-in WebRTC leak test (one STUN request from the browser)
│   ├── js/jsoneditor.min.js # vendored, loaded only when the Raw JSON panel opens
│   ├── fonts/              # self-hosted woff2 (CSP blocks font CDNs)
│   ├── image/, favicons    # logo (also og:image), icons, web manifest
│   └── geo/                # cities.json, countries.json (generated, committed)
├── tests/                  # see Testing Strategy for each file
│   ├── conftest.py         # env switches set before main is imported; per-test security reset
│   └── fixtures/           # MaxMind's GeoLite2 test mmdbs, the MCP server.json schema
├── docs/
│   ├── images/          # README screenshots
│   └── ops/             # alerts.md (healthz probe, SigNoz alerts), mcp-directories.md
├── .github/
│   ├── dependabot.yml   # weekly: GitHub Actions, pip, Docker
│   └── workflows/       # ci, deploy, healthz-probe, mcp-publish, security-audit
├── data/                # Volume mount for persistent data (Docker); gitignored contents:
│                        # GeoLite2 mmdbs, tld/, reputation/, subdomains.sqlite3, bans/rules
├── Dockerfile           # single stage: poetry export + uv pip, non-root, OTel entrypoint
├── Makefile             # Docker workflow automation
└── pyproject.toml       # Poetry dependencies and ruff/pytest config
```

### Map subsystem

**Coordinates**: from GeoLite2-City's `location`. When it has none (or only the
geoip2fast country fallback is loaded), `static/geo/cities.json` (GeoNames cities15000)
matches the city name, with a population-weighted country centroid as the last
resort (`geo.Gazetteer.resolve`). Private IPs get no map.

**Projection**: all map math is server-side and unit-tested (`tests/test_mapgeom.py`).
`main.build_map_payload` has `mapgeom.build_canvas` emit tile URLs with pixel
offsets plus a projected great-circle polyline for two fixed canvases,
`config.DESKTOP_CANVAS` (a 1440-wide band) and `config.MOBILE_CANVAS` (a
350-wide card); `static/js/map.js` only paints them.

**Antimeridian**: Seoul → California crosses the Pacific. The map centers on the
shortest-path midpoint longitude and wraps tile x by 2^zoom; a naive Mercator straight
line would run the wrong way across Europe. `fit_zoom()` frames the whole sampled arc,
not just the endpoints, because the great circle bulges far north of both cities.

**Tiles**: fetched by the browser straight from `tile.openstreetmap.org` (no API key).
CSP allows exactly that one host in `img-src`. Tile `<img>`s must send a Referer:
OSM blocks referer-less web traffic with a 403 "Access blocked" tile, so map.js
sets `referrerPolicy = "strict-origin"` on them, overriding the page-wide
`no-referrer` without leaking the lookup path. Both canvases fetch tiles at
their native zoom (`build_canvas`'s `tile_zoom_offset` is 0) so roads and place
names stay legible, which costs ~15 tile requests on desktop and ~6 on mobile;
CSS inverts them to turn OSM's light basemap dark. **Attribution is mandatory**:
map.js's `attribution()` draws "© OpenStreetMap contributors · GeoLite2 by
MaxMind" on the map itself.

### Subdomain lookup

**Opt-in by query parameter, not by route.** `?subdomains=include|only` on the
existing `/{domain_ip}` route. `main.security_middleware` classifies requests by
`request.url.path`, which excludes the query string, so the path stays
`/{domain}` and `WhitelistManager.is_lookup` classifies it exactly as before —
no security policy was widened to add this. A route like `/api/certs/{domain}`
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
`?subdomains=` gate in `main.get_ip_info`, the MCP `subdomains` tool, and
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
fetches each list into `data/reputation/` once its copy is a day old (its first
run, at start, fetches only what is missing or stale); `check()` is a bisect
over merged integer ranges, so a lookup makes no outbound request and adds no
SSRF surface. `lookup.ip_reputation()` is the one entry point for `gather()`,
the self page and `whoami_caller`; it takes the AS number for ASN-DROP from
GeoLite2-ASN.

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

**Tests.** `tests/conftest.py` sets `REPUTATION_ENABLED=false`, so no test can
make a Spamhaus download (even one that starts a real scheduler) and every other
test sees the responses it always did. `tests/test_reputation.py` builds enabled
managers over synthetic lists and monkeypatches `lookup.reputation_manager` (and
`main.reputation_manager` for `/healthz`).

### Dependencies

**Runtime** (`pyproject.toml`):
- FastAPI (`fastapi[all]`, which brings Jinja2) + uvicorn: web framework and ASGI server
- whoisit: RDAP, the primary registration source; requests is its HTTP client
- python-whois: the port-43 WHOIS fallback for domains
- maxminddb: memory-mapped GeoLite2 City/ASN readers
- geoip2fast: only its bundled country snapshot, the fallback before the first
  GeoLite2 download
- dnspython: every DNS query
- tld: Public Suffix List parsing (`is_valid_domain`, `zone_apex`, subdomain
  target checks)
- cryptography: parsing the certificate of a handshake that failed verification
- mcp: the official MCP SDK (Streamable HTTP)
- APScheduler: the background refresh and cleanup jobs
- python-dotenv: `.env` loading
- opentelemetry-*: traces, metrics and logs via `opentelemetry-instrument`,
  which the Docker entrypoint wraps uvicorn in

**Development:**
- ruff: linting (with Bandit's S rules) and formatting
- pytest + pytest-asyncio (`asyncio_mode = "auto"`): the suite
- pip-audit: the dependency audit CI runs

### Docker Build Process

A single stage on `python:3.12-slim`, pinned by digest:
1. `pip install uv poetry`, then `poetry export` the lock to `requirements.txt`
2. `uv pip install --system --require-hashes` (no virtualenv in the container)
3. Copy `*.py`, `templates/` and `static/` into `/app`, create `/app/data`, and
   drop to the non-root `appuser`. A new top-level module ships on its own; a
   new top-level directory needs its own `COPY`
4. `SOURCE_COMMIT` (build arg or Coolify's runtime env) becomes `/healthz`
   `version` and OTel `service.version`
5. `HEALTHCHECK` runs `healthcheck.py`; the entrypoint is
   `opentelemetry-instrument uvicorn main:app --host 0.0.0.0 --port 8000
   --no-server-header`, with no `--reload`

### CI and deploy

- `ci.yml`: ruff check, ruff format --check, pytest, and pip-audit on every
  push to `main` and every pull request against it
- `deploy.yml`: after CI passes on `main` (or by manual dispatch), the
  self-hosted runner on the Coolify host triggers the deploy and waits for
  `/healthz` `version` to read the commit
- `healthz-probe.yml`: checks production's `/healthz` from outside every 15
  minutes; `degraded` fails it too (`docs/ops/alerts.md`)
- `mcp-publish.yml`: publishes `server.json` to the MCP Registry, by hand only
- `security-audit.yml`: a weekly pip-audit that opens or updates a
  `security-audit` issue when it finds something

### Testing Strategy

Every test runs on FastAPI's `TestClient`; most use one module-level client,
which never runs the lifespan, and the MCP tests use `with TestClient(app)`,
which does. `tests/conftest.py` sets the environment before any test module
imports `main`: `BACKGROUND_REFRESH_ENABLED=false` (no lifespan starts the
scheduler or downloads anything), `REPUTATION_ENABLED=false`, the admin key, the
trusted proxies, and ban/geo-rule files under `/tmp`. Its autouse fixture clears
the rate limiter and ban list around every test.

The external lookups each test checks (RDAP/WHOIS, GeoIP, DNS, TLS) are mocked,
and importing `main` makes no network call. The suite is still not fully
offline:
- A few tests in `test_basic.py`, `test_page.py` and `test_security.py` leave
  reverse DNS, the zone SOA lookup or the RDAP bootstrap unmocked, so they send
  real queries to 8.8.8.8/1.1.1.1 and data.iana.org. Offline those fail inside
  the app and the tests still pass, only slower.
- `test_webrtc_leak.py` runs `static/js/webrtc.js` in node and skips those
  tests when `node` is not installed.

Test files:
- Units: `test_geo.py` (gazetteer, distance), `test_mapgeom.py` (projection,
  tiles, arcs), `test_viewmodel.py` (view model, WHOIS/SSL rendering),
  `test_rdap.py` (RDAP/WHOIS normalisation, fallback routing),
  `test_managers.py` (GeoLite2 lookups, the country fallback, database
  sources and status, `TldNamesManager`, `is_valid_domain`), `test_lookup.py`
  (target normalisation, `is_safe_ip`, `gather()`), `test_subdomains.py`
  (crt.sh adapter, normalisation and the `@` rule, single-flight, budget),
  `test_subdomain_store.py` (the SQLite cache degrades to a miss)
- Boot: `test_boot.py` (importing `main` touches no network; the lifespan
  starts and stops the scheduler)
- Endpoints and pages: `test_basic.py` (smoke tests, `/healthz`, refresh
  retries, boot fetch), `test_page.py` (API + HTML, map payload, DNS rows,
  security headers, fingerprint panel, `?subdomains=`), `test_negotiation.py`
  (`?format=`/Accept/user-agent), `test_text_format.py` (`?format=text`,
  `?fields=`), `test_error_pages.py` (`error.html` for browsers),
  `test_open_graph.py` (link previews), `test_privacy_page.py` (`/privacy`),
  `test_robots_head.py` (`/robots.txt`, `/favicon.ico`, HEAD),
  `test_self_first_paint.py` (self page before WHOIS, `/?whois=only`),
  `test_ip_whois_column.py` (an IP's WHOIS column), `test_subdomain_panel.py`
  (the subdomain panel), `test_webrtc_leak.py` (the WebRTC leak test)
- Lookup behaviour: `test_classify_target.py` (refused before any network
  work), `test_ipv6.py` (IPv6 literals, AAAA), `test_dns_status.py` (a failed
  query is never "no records"), `test_zone_apex.py` (NS/MX/SPF from the zone
  apex), `test_psl_public_only.py` (the ICANN-only suffix list `zone_apex`
  floors on, kept offline), `test_dns_fanout.py` (NS/MX host cap), `test_txt_join.py` (TXT over
  255 bytes), `test_resolver_unification.py` (one resolver set and budget),
  `test_tls_reasons.py` (why a certificate fails), `test_rdap_budget.py`
  (RDAP/WHOIS cost, no port-43 for an IP), `test_concurrency_gate.py` (gate
  503s, what takes no slot, pool isolation), `test_subdomain_targets.py`
  (which targets may reach crt.sh), `test_reputation.py` (list parsers,
  intervals, grade, download guard, surfaces)
- Security: `test_security.py` (proxy-header trust, SSRF and TLS-rebinding
  guards, the admin key, bans, rate limiting, geo-blocking, the probe detector
  and whitelist, per-IP rules, response headers, log injection), `test_ssrf.py`
  (only global unicast becomes a connection target)
- MCP: `test_mcp.py` (handshake, tools, transport limits, rate bucket),
  `test_mcp_iserror.py` (`isError` on outright failures),
  `test_mcp_manual_ban.py` (only a manual ban applies), `test_mcp_registry.py`
  (`server.json`, its publish workflow, the page's tool list)
- Ops: `test_healthz_degraded.py` (`degraded` and its reasons,
  `healthcheck.py`), `test_deploy_version.py` (`/healthz` `version`)

## Commit Conventions
- Never include Claude session URLs or metadata in commit messages.
- Do not add "Co-Authored-By" lines.
