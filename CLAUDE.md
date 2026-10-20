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

Every test uses FastAPI's `TestClient`, and the suite runs offline: a test that
tries to reach the network fails. See [Testing Strategy](#testing-strategy).

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
  canvases, the young-domain tag's threshold, feature switches). It calls
  `load_dotenv()` and imports nothing app-local, so every module can import it
  without a cycle. Two settings are read elsewhere: `ADMIN_API_KEY` in
  `main.py`, and `GEO_CITIES_FILE` / `GEO_COUNTRIES_FILE` in `geo.py`.
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
    `zone_apex`, `registrable_domain` (the ICANN-section floor `zone_apex`,
    the registration lookup and the DMARC fallback share), `get_records` (the
    record sweep; `dmarc=True` adds the name's DMARC record) and
    `perform_reverse_lookup` (PTR)
  - `SSLManager.get_ssl_info`: the certificate, read from a verified IP.
    `_connect` gives the TCP connect `TLS_CONNECT_TIMEOUT_SECONDS` (3 s) and
    then sets `TIMEOUT_SECONDS` (5 s) for the handshake before returning, since
    `SSLSocket` copies the socket's timeout at `wrap_socket` time; a port that
    drops the SYN is `{"error": "port 443 unreachable", "reason": "timed out"}`
    after the connect budget. `_untrusted` reuses `_connect`
  - `HeaderManager`: strips proxy/forwarding headers from the echoed headers
  - module functions: `_recursive_resolver` (every DNS query goes through it),
    `dns_status`, `_with_host_ips`
- `security.py` — the request-security subsystem: `IPBanManager`,
  `IpRuleManager` (hand-written `data/ip_rules.json`), `RateLimiter`,
  `SuspiciousPatternDetector`, `WhitelistManager`, `GeoBlockManager`, and
  `get_client_ip` / `client_ip_from_scope` (proxy headers are trusted only from
  `TRUSTED_PROXIES`, or from private, loopback and link-local peers when that is
  unset). `main.security_middleware` applies them, and
  `main._suspicious_path_is_ordinary` spares a path a detector rule matched
  only when its target has a public suffix or is an IPv4 address; a
  `/<host>:<digits>` path is judged by its host (the lookup drops the port),
  a path with an `@` never is. `WhitelistManager.lookup_patterns` and the
  detector rules stay as they are. `BlockedBanLog` (`blocked_ban_log`) is the
  per-(channel, address) window `main._log_blocked_ban` uses for the three ban
  warnings.
- `rdap.py`: `lookup_rdap` (whoisit) and `normalize_whois` (python-whois's
  port-43 output) both produce one canonical dict (`CANONICAL_FIELDS`).
  `bootstrap_rdap` loads IANA's registry with whoisit's bundled override table
  enabled for RDAP servers IANA omits, including .ch/.li/.de/.io/.me/.us.
  `_jscontact_name` reads registrar and registrant names from JSContact cards
  in raw responses from registries such as KRNIC.
  `rdap_breaker` (a `CircuitBreaker`) skips an RDAP host after repeated
  failures. `refresh_rdap_bootstrap` saves and clears a week-old registry so
  whoisit actually fetches again, restores the saved copy on failure, and
  holds `_bootstrap_lock` while using the configured no-retry session.
- `eppstatus.py`: the EPP status vocabulary, standard library only. `epp_code`
  folds the three spellings a registry uses (RFC 8056's "client transfer
  prohibited" from RDAP, ICANN's port-43 line "clientTransferProhibited
  https://icann.org/epp#…" from python-whois, the bare camelCase code) to one
  EPP code and passes anything else ("connect") through verbatim;
  `STATUS_MEANINGS` is code → (one-line meaning, tone), with `danger` kept to
  `clientHold`, `serverHold`, `pendingDelete` and `redemptionPeriod`;
  `explain_status` is the `[{code, meaning, severity}]` list. `rdap.py` keeps
  `status` raw; the fold happens where a status is rendered or explained.
- `dnssecurity.py`: a domain's DNS security posture. `fetch(name, zone,
  registrable)` asks the public resolvers what the record sweep does not —
  CAA (climbing to the registrable domain, RFC 8659), DS and DNSKEY at the
  zone with DO/AD set (`_validating_resolver`), TXT at
  `<selector>._domainkey.<name>` for each of `config.DKIM_SELECTORS`, and
  `_mta-sts`, `_smtp._tls`, `default._bimi` TXT — on a pool of its own.
  `evaluate(domain, raw)` is pure and grades `CHECKS` (`spf, dmarc, dkim,
  caa, dnssec, mta_sts, tls_rpt, bimi`) from that and the sweep's SPF and
  DMARC: each `{state, summary, findings}`, state `pass | warn | fail | info
  | unknown`. Imports `config`, `managers`, `viewmodel` and `cryptography`;
  must not import `lookup` or `main`.
- `models.py`: one Pydantic model, `GeoRulesUpdate`, the body of
  `PUT /admin/geo/rules`. Responses are plain dicts with no response model.
- `lookup.py`: the transport-agnostic lookup pipeline, `gather()`, shared by
  `GET /{domain_ip}` and the MCP tools. Also `classify_target`,
  `special_use_suffix`, `is_safe_ip`, `lookup_whois` (RDAP first, port-43
  only for a domain; a hostname is looked up and cached as its registrable
  domain and the answer carries both names), `lookup_location` and
  `ip_reputation`. Raises
  `PrivateAddressError` and `InvalidTargetError` rather than `HTTPException`
  so it stays free of FastAPI; both carry `code` and `message`.
  `refused_address(target, address)` builds a `PrivateAddressError` from
  `special_purpose(address)`, the IANA special-purpose block table
  (`_SPECIAL_PURPOSE`: `private`, `cgnat`, `loopback`, `link_local`,
  `documentation`, `benchmarking`, `multicast`, `this_network`,
  `ietf_protocol`, `broadcast`, `reserved`, `ula`, `site_local`, `6to4`,
  `teredo`, `nat64`), which labels an address only after `is_safe_ip`
  refused it and is never a second allowlist (`tests/test_ssrf.py` ties
  every row to `is_safe_ip`); an address in no row is `reserved`.
  `gather(legs=)` runs only the named legs
  (`LEGS`); the default (None) runs them all, and the page, the full JSON and
  the MCP `lookup` tool use the default. MCP `dns_records` and
  `ssl_certificate` pass `mcp_server._DNS_LEGS` (`{"resolve", "dns"}`) and
  `_TLS_LEGS` (`{"resolve", "tls"}`; `_DNS_LEGS` is
  `{"resolve", "dns", "security"}`), so neither spends a registration
  lookup, the other's leg or an AbuseIPDB request; `?fields=` narrows the
  same way through `textfmt.legs_for()`. Builds the manager singletons
  (`geo_ip_manager`, `tld_names_manager`, `domain_manager`,
  `reputation_manager`, `abuseipdb_client`) at import, which reads `data/` but
  makes no network call.
  `canonical_hostname` lower-cases, normalizes IDNA dot separators, encodes
  each non-ASCII label with the direct `idna` dependency's UTS 46 processing,
  validates every label, and removes one trailing root dot. ASCII service
  labels such as `_dmarc` bypass the encoder. `normalize_lookup_target`
  applies it after cutting a pasted URL to its host, so DNS, TLS SNI,
  registration, the cache and echoed address all see one spelling.
  `abuse_report` asks AbuseIPDB, from `_run_legs` and only for an IP target.
  The `asinfo` leg (in `LEGS`) reads `address_as_info(ip, location)`, the
  route and AS card of an address from `asinfo_manager`; `as_info_for_asn(asn,
  full=)` is the card of a number. `classify_target` also answers `"asn"`
  (`parse_asn`: `as` plus 1 to 10 digits, 0 to 4294967295, any case; a bare
  number stays `invalid`). `special_asn(n)` reads `_SPECIAL_ASN`, the
  special-purpose ASN table beside `_SPECIAL_PURPOSE`, and is `None` for an
  ordinary number. `gather()` refuses an `asn` target with
  `InvalidTargetError(code="asn_target")`, since it would treat it as an IP. The self page (`GET /`) does not use
  `gather()`: `main._self_lookup` runs its legs.
- `concurrency.py`: the lookup gate and the slow-leg thread pools. At most
  `LOOKUP_CONCURRENCY` lookups run at once: `gather()` holds a slot for its
  legs and the self page for its own. MCP tool calls first take a slot at a
  smaller gate of their own, so they never hold more than
  `MCP_LOOKUP_CONCURRENCY` of the global slots. A full gate is `LookupBusy` —
  a `503` with `Retry-After` over HTTP, never a ban. RDAP/WHOIS
  (`registration_pool`), crt.sh (`subdomain_pool`) and AbuseIPDB
  (`abuseipdb_pool`) and the DNS security leg (`dns_security_pool`) run on
  their own pools, not the default executor; GeoIP
  runs inline. Imports only `config`, so
  `subdomains.py` may use it.
- `textfmt.py`: `?format=text` and `?fields=`. The field table (names are
  `mcp_server`'s compact_* shapes, flattened; each field lists the `gather()`
  legs it needs and the target kinds it applies to) and the text/flat-JSON
  rendering. Pure: `main.py` runs the lookup. `dmarc_policy` reads
  `viewmodel.dmarc_policy()`, so the field and the page's Mail row agree.
  `as_block` is the `/AS<n>` text block (the card's scalars and its
  upstreams); `route_prefix`, `route_origin` and `rpki_state` are address
  fields, in the text block because the data is local, but only while AS
  information is on (`block_fields(kind, as_info=)`, which `main` passes
  `asinfo_manager.enabled`): off, a `-` there would read as "not announced",
  so they read `-` only when asked for by name. `-` is "no value", `?` is "the
  lookup failed": `field_values` marks the registration fields for a broken
  RDAP/WHOIS lookup, every field read from the address (chosen by leg, so a
  new field follows; `_NAME_LEGS`, whois and the dns sweep, ask about the
  name and keep their own status) when the gating A query's `resolution` is
  in `managers.DNS_FAILURES`, and the `tls` fields when the TLS leg came back
  `{"error"}`; `nxdomain`/`noanswer` stay `-`. `resolution` is a name-only
  domain field (never in the text block) that says how the A query ended.
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
  list, and answers `check(ip, asn)` from sorted intervals in memory.
  `risk_score` (`SCORE_MAX = 100`) is the sum of signal weights capped at 100,
  and 100 is the most dangerous. `asn_listed(asn)` is the ASN-DROP read the AS
  card uses: `None` when that list could not be read by `check()`'s own rule.
  Imports only `config` and the standard
  library; `lookup.py` builds the singleton.
- `abuseipdb.py`: AbuseIPDB's abuse confidence score and report counts for an
  address, the one reputation source asked per lookup (`AbuseIPDBClient`, with
  a per-address cache and the daily quota), and `merge()`, which adds its
  answer to a `check()` result. Off without `ABUSEIPDB_API_KEY`. Imports
  `config`, `reputation` and the standard library; `lookup.py` builds the
  client.
- `asinfo.py`: the AS information database (see [AS information](#as-information)).
  `AsInfoManager` owns the seven datasets (`default_datasets()`), their
  downloads (`refresh()`: due check, `.requested` stamp, streamed copy,
  `min_rows`, build, `os.replace()`), the SQLite file they are built into, and
  the reads: `for_address(ip, geolite_asn)` (longest-prefix route, RPKI state
  per origin, then the card of the route's origin AS, else GeoLite2's) and
  `for_asn(asn, full=)`. Also `status()`, `stale_datasets()`, `hosts()` (for
  `/privacy`; it lists the hosts whether or not the manager is enabled, so
  the caller checks `enabled`), the dataset parsers (`parse_asnames` and the like) and the answer shape
  (`ANSWER_KEYS`). Imports `config` and the standard library only; must not
  import `lookup` or `main`, for `subdomains.py`'s reason.
- `mcp_server.py`: the public MCP server mounted at `/mcp` (official `mcp` SDK,
  Streamable HTTP, stateless). Five tools, six with `ASINFO_ENABLED`: `lookup` over `lookup.gather()`,
  `dns_records` and `ssl_certificate` over `gather(legs=)` narrowed to their
  own legs (`_DNS_LEGS`, `_TLS_LEGS`), `subdomains` over
  `subdomains.get_subdomains()` (registered only under `SUBDOMAIN_ENABLED`),
  and `whoami_caller` over `lookup.lookup_location()` and
  `lookup.ip_reputation()`, and `as_info` over `lookup.as_info_for_asn()`
  (registered only under `ASINFO_ENABLED`, as `subdomains` is under
  `SUBDOMAIN_ENABLED`; it takes `"AS4766"`, `"as4766"` or `4766`). Each reshapes
  its data for an LLM context (the `compact_*` functions, `compact_as_info`
  among them; `lookup` and `whoami_caller` carry a compact `as_info`). `compact_registration` adds `status_explained`
  (`eppstatus.explain_status`: `[{code, meaning, severity}]`) beside a domain's
  raw `status`; an IP allocation, an error and `registered: false` carry none.
  A new output key is not a listing change, so `server.json` is not bumped for
  it. `build_mcp`, `McpDispatch`, `McpBarePathRoute` and `McpDisabled` are the
  mount plumbing `main.py` wires.
- `viewmodel.py`: `build_view()` turns a response dict into what
  `templates/browser.html` renders (`as_view` is the "AS" accordion's rows,
  hint and credits; `as_page_view` the `/AS<n>` page's). Pure, with no I/O, and it imports only
  `config`, `eppstatus`, `reputation.grade` and the standard library, so
  `mcp_server.py` reuses its certificate helpers without a cycle. The one
  decision that needs `lookup` — which values link to their own lookup —
  comes in as the `link_for` argument (`main.lookup_href`); the default
  `None` links nothing. `dmarc_policy()` is the one reading of a name's
  DMARC record (the Mail row in the DNS column): exactly one record, and an
  inherited one's `sp=` for a subdomain.
- `geo.py`: `Gazetteer` (coordinates from `static/geo/*.json`), `haversine_km`,
  and `coordinate_precision`, the one `city`/`country` rule for a fix.
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
  `render_refused_target`, `lookup_href` and `_dns_rows` (the page's lookup
  links), `_self_lookup`, and the routes `get_self_info`, `get_ip_info` and
  `head_lookup`; for AS numbers `_as_lookup` (the `/AS<n>` handler),
  `render_as_page` (`templates/as.html`, with `templates/_raw_json.html`, the
  Raw JSON panel it shares with `browser.html`) and `_script_json`, which
  escapes `<`, `>` and `&` in the JSON a page embeds in a `<script>`, since
  third-party text (an AS name) reaches it.

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
  still wait for the record; a registration field in `?fields=` (`_self_fields`)
  joins, reads the cache and gates the same way
- `GET /{domain_ip}` - a domain or an IP address (IPv4 or IPv6), through
  `lookup.gather()`
- `GET /{domain_ip}?subdomains=include|only` - opt-in Certificate Transparency
  subdomain list; see [Subdomain lookup](#subdomain-lookup)
- `GET /AS<n>` (`AS4766`, `as4766`; `lookup.parse_asn`) - an autonomous
  system, from the local AS database through `main._as_lookup`, which takes no
  `lookup_gate` slot. A special-purpose number is a `200` that says what it is
  for. `?fields=` and `?subdomains=` are `400`s on it. `HEAD` answers as for any
  target. With `ASINFO_ENABLED=false` every number is a `400` with the code
  `asinfo_disabled`
- `?format=html|json|text` and `?fields=` on both lookup routes
- `HEAD /`, `HEAD /{domain_ip}` - `main.head_lookup`: `200` with the
  Content-Type GET would answer with (JSON for the `?whois=only` and
  `?subdomains=only` modes, whatever was negotiated), GET's `400` for a bad
  query parameter, and no lookup
- `GET /healthz` - `ok` or `degraded` with `reasons` (`main.health_reasons`,
  no network calls), the deployed `version`, and which datasets are loaded
- `GET /robots.txt`, `GET /favicon.ico` (a `301` to `/static/favicon.ico`),
  `GET /privacy` - fixed answers, exempt from the rate limit like `/static/`
- `POST /mcp` - the MCP endpoint; every other method is a `405`
- `/admin/*` - bans, per-IP rules, geo rules and stats, behind the `api-key`
  header (`ADMIN_API_KEY`); a missing or wrong key is a `404`

### Response Flow

1. **Format Negotiation**: `negotiate()` picks the response format: `?format=html|json|text` first (unknown value -> 400), then an `Accept` header that names `text/html`/`application/json`/`text/plain` (q-values honoured), and only when `Accept` is absent or `*/*` the user-agent (`BrowserDetector`: browsers get HTML; PowerShell, despite its `Mozilla/5.0`, gets JSON). `text` is `textfmt.py`'s: the bare client IP on `/`, a `key: value` block on `/{domain_ip}`; `?fields=` (either route; JSON unless text was negotiated) runs only the `gather(legs=)` the named fields need. Both lookup routes send `Vary: Accept, User-Agent` and `Cache-Control: no-store`, errors included
2. **Classification**: `lookup.normalize_lookup_target` cuts a pasted URL to
   its host (the scheme, everything from `/`, `?` or `#`, and a port:
   `example.com:443`, `[2001:db8::1]:8443`; one colon only, so never a bare
   IPv6 address's last group) and gives a name its canonical spelling (lower case, no trailing
   root dot, UTS 46 A-labels); `lookup.classify_target` then calls it a domain,
   `ipv4`, `ipv6`, `asn` or `invalid` before any network work (an `asn` target
   goes to `main._as_lookup` and never to `gather()`); an invalid target is a
   `400` (`InvalidTargetError`), and so is a private or reserved address
   (`PrivateAddressError`, from `is_safe_ip`): its JSON keeps `detail`
   unchanged and adds `error` and `code`, the IANA block from
   `lookup.special_purpose` (`main._refused_json`), and text answers the
   `error` sentence. A hostname under
   `config.SPECIAL_USE_SUFFIXES` (`onion`, `home.arpa`: on the PSL, so
   `is_valid_domain` says yes) is `invalid` too, and `gather()` raises
   `InvalidTargetError(code="special_use_name")` with the reason from
   `config.SPECIAL_USE_NAMES` (`lookup.special_use_suffix`, matched on the
   IDNA 2003 name dnspython queries, not only the raw text); never the rest
   of `.arpa`, which PTR names live in. The check is not in
   `is_valid_domain`, which `main._suspicious_path_is_ordinary` reads: the
   probe verdict for these paths must not change.
   A target with an `@` in it (an email address, a URL's `user:password@`)
   keeps the code `invalid_target`, with `lookup.EMAIL_LIKE_TARGET` as its
   message, which `static/js/app.js` copies word for word. A browser gets
   `main.render_refused_target`'s error page instead of the JSON, with copy
   chosen by `code` for `cgnat`, `documentation`/`benchmarking` and
   `6to4`/`teredo`/`nat64` (`_carried_ipv4` names the IPv4 address inside,
   offered as the next lookup only when `is_safe_ip` passes it); a hostname
   keeps its own sentence whatever block it resolved into, the other
   `_LOCAL_NETWORKS` blocks keep the local-network sentence, and
   `static/js/app.js`'s `isLocalAddress` mirrors that list unchanged
3. **IP Resolution**: a domain's A record, or its AAAA record when it has no A
   (an IPv6-only host), from the public resolvers; the address must pass
   `is_safe_ip` too
4. **Data Gathering** (`lookup._run_legs`, holding a `lookup_gate` slot): the
   registration lookup runs alongside everything else; a domain's DNS sweep
   (its DMARC record included) and TLS handshake run concurrently; an IP gets
   its PTR, then a sweep of the PTR name, without DMARC. A domain's
   `security` leg (`dnssecurity.fetch`) runs beside its sweep, unless the A
   query was `nxdomain`. GeoIP is read inline,
   and reputation from the lists in memory; an IP
   target is also sent to AbuseIPDB, alongside the rest
5. **Response Assembly**: `main.get_ip_info` builds a plain dict (`address`,
   `resolved_ip`, `resolution`, `datetime`, `domain`, `location`, `whois`,
   `ssl`, `headers`, `map`, `distance_km`, `origin`, `elapsed_ms`, plus
   `reputation`, `dns_security` and `subdomains` when present) and returns it as JSON or
   renders it through `render_page` and `viewmodel.build_view()`
6. **Logging**: every lookup is logged as `client={client_ip} lookup={target}`,
   with `<email-like>` in place of a target that has an `@` in it
   (`lookup.loggable_target`)

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
  start); `refresh-asinfo` every `ASINFO_CHECK_INTERVAL_SECONDS` (first run at
  start, in the background: a fresh volume serves lookups with the AS card
  unavailable until the first build; like the reputation job it is not in
  `_refresh_with_retry` and adds nothing to `_refresh_failures`); expired-ban cleanup; and cleanup of both rate-limiter buckets.
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
  concurrently, and DMARC when asked: `get_records(dmarc=True)` comes from
  `lookup._run_legs` for a domain target only, so the self page's and an IP
  target's PTR-name sweeps make no `_dmarc` query. NS and MX host addresses go
  through `_with_host_ips`, capped at `DNS_HOST_RESOLVE_LIMIT`; rows past the
  cap carry `ip_skipped`. A TXT string
  over 255 bytes arrives split and is joined with no separator (RFC 7208).
- NS, the zone's SPF (marked `from_zone`, like a zone MX row), and MX for a
  name with none of its own come from the zone apex (`DomainManager.zone_apex`: an SOA lookup, never a label count — that
  turned naver.co.kr into co.kr), floored at the registrable domain. Zone MX
  rows carry `from_zone`; the response names `queried_name` and `zone`, and,
  read off the A answer (the AAAA answer when the A query raised) at no query
  of its own, `cname_chain` (each hop's `name`, `target` and `ttl`, in the
  order the resolver followed them, the TTLs being what its cache had left)
  and `canonical_name` (the name the hops end at, lowercase and without the
  trailing dot like `queried_name`, and `queried_name` itself when there is
  no hop; `null` with an empty chain when neither query answered, and
  `status.a` says why). `cname` stays the first hop, from its own query
- `main._dns_rows` draws one CNAME row per hop (the hop's owner name without
  its trailing dot, its target, its TTL) in place of the single `cname` row,
  and `viewmodel.geoip_rows(location, domain)` ends with a 'Resolves via
  `<canonical_name>` — the location and ASN above are its' row when it
  differs from `queried_name`. `build_view()` passes `domain` for a domain
  target only: an IP's sweep is of its PTR name, and its location is its own.
  Only that the names differ is known, so nothing says 'CDN'
- The page's DNS table (`main._dns_rows`, `main._zone_of`,
  `viewmodel.dns_names`) names the other rows by the name each was asked of:
  `queried_name` (an IP target's PTR name; the address when the response has
  none), or the zone for NS rows and `from_zone` MX rows, a failed NS row
  included (a failed MX row stays on `queried_name`: the response cannot say
  which of the two MX queries raised). A zone row whose zone differs from
  `queried_name` carries `from_zone: True`; no other row has the key. The
  page draws it as a `(zone)` marker at the end of VALUE, and the table's
  `<caption>` names `queried_name` and, when it differs, the zone. Under
  900px the NAME column is hidden, so the caption is the only place the name
  is printed and the marker is what keeps a zone row recognisable at every
  width. A CNAME hop row whose owner is not `queried_name` carries `hop_of`,
  drawn as `(of <owner>)` the same way. The NAME `<td>` stays attribute-free
  (tests match it as a bare `<td>`). JSON, MCP `dns_records` and
  `?format=text` are unchanged
- `zone_apex`'s floor, `DomainManager.registrable_domain()`, comes from
  `tld.get_fld(..., search_private=False)`, which reads `tld`'s separate
  public-only list
  (`data/tld/res/effective_tld_names_public_only.dat.txt`). `TldNamesManager`
  keeps it as a byte copy of the full list, at boot (`_mirror_public_only`)
  and on every refresh: `tld`'s public-only parser stops at
  `===BEGIN PRIVATE DOMAINS===`, so the full list parses to the ICANN-only
  one. Without that copy `tld` downloads `?publiconly` itself, inside the
  request and with no timeout, and offline `get_fld` raises `TypeError` even
  with `fail_silently`.
- DMARC follows RFC 7489 §6.6.3: TXT at `_dmarc.<name>`, kept when it opens
  with `v=DMARC1` (joined like SPF), and only when the name holds no policy
  record, `_dmarc.<registrable_domain()>` once — the public suffix list's
  answer, never the SOA zone. A failed first query never falls back, a failed
  fallback is the status, and each record's `queried_name` says which name
  answered. The page's DNS table lists each record under that name
  (`main._dmarc_rows`); an inherited one carries `inherited_from` and ends
  VALUE with that domain in parentheses, as a zone row ends with `(zone)`,
  since NAME is hidden under 900px.

#### DNS security

`dnssecurity.py`, `lookup._security_raw`, `viewmodel.dns_security_view`:
- A domain target only: an IP's sweep is of its PTR name, the self page
  checks nothing, and a name whose A query was `nxdomain` gets no
  `dns_security` key (the page already says it does not exist). The leg runs
  beside the sweep and the TLS handshake (about 17 queries, in parallel), on
  `concurrency.dns_security_pool`, never the default executor; a
  leg that raised is logged and grades its six checks `unknown`.
- A query that failed (`DNS_FAILURES`) makes a check `unknown`, never `fail`.
  DKIM with no key at any of `DKIM_SELECTORS` (env `DKIM_SELECTORS`) is
  `unknown`, "not found at the common selectors": DNS cannot list selectors,
  so it is never "no DKIM".
- SPF and DMARC are graded from the sweep's records, never re-fetched. SPF
  is graded on the name's own records only: the sweep appends the zone's
  marked `from_zone`, and SPF is not inherited (RFC 7208). None of its own,
  two or more, or `+all` fail; `?all`, no `all` without `redirect=`, or `ptr`
  warn. A name below the apex with no SPF and no MX of its own (`www`, `api`)
  is `info`, not `fail`. DMARC: none or two records fail;
  `p=none`, `pct` < 100 or no `rua` warn; `viewmodel.dmarc_policy` reads the
  policy, `sp=` for an inherited one. DKIM: an RSA key under 1024 bits fails,
  under 2048 warns, Ed25519 passes; a key that does not parse, or is EC or
  DSA, warns. CAA: none, or a set with no `issue` property (iodef or
  `issuewild` alone, RFC 8659 §4), warns; the climb stops after
  `CAA_MAX_NAMES` (8) names, and a deeper name with no answer in them is
  `unknown`. DNSSEC: DS present and the DNSKEY answer's AD bit set passes;
  no DS, or DS without AD, warns; a failed query is `unknown` (a SERVFAIL may
  be a broken chain). MTA-STS, TLS-RPT and BIMI: present passes, absent is
  `info`. No overall score.
- Surfaces: the JSON's `dns_security`; the page's "DNS security" accordion
  after "DNS records" (hint: the state counts); MCP `lookup` and
  `dns_records` (`compact_dns_security`, records dropped); `?fields=`
  `spf_state` ... `bimi_state`, out of the text block, `?` with the summary
  as the reason for `unknown`.

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
- `location["country_source"]` says which key `_apply_city` took, `located` or
  `registered` (1.1.1.1 carries only `registered_country`, and no location),
  and is None when no country was found or the geoip2fast fallback answered;
  `country_code` is substituted either way, so geo-blocking is unchanged.
  `lookup.lookup_location` grades the coordinates as `location["precision"]`
  (`geo.coordinate_precision`: `city` within `MAX_CITY_ACCURACY_KM`, `country`
  beyond it or with no radius, None without coordinates), so `gather()`, the
  self page and MCP all carry it. The page overwrites it with the gazetteer's
  grade for the coordinates it draws (`main._apply_resolved_target`)
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

A domain is asked about as its registrable domain through
`lookup.registration_target` and `DomainManager.registrable_domain`, using the
same ICANN-view public suffix floor as `zone_apex`. This makes `www.` and
`api.` variants share one cached record. Domain answers carry `queried_name`
and `registrable_domain`; IP answers carry neither. `NOT_REGISTERED` therefore
means the registrable domain itself has no record. If the suffix list cannot
be read, the lookup asks about the supplied name instead of failing.

A port-43 record with nothing beyond `source` and `name` gets `thin: True`.
The page says `no details`, MCP adds `thin` and a note, and flat registration
fields stay `-`. Thin records are cached for `WHOIS_CACHE_ERROR_TTL` (5 min)
so a registry can be retried; full records retain the 6-hour TTL.

A record's `status` stays the registry's own words; the page folds them with
`eppstatus.explain_status` (`viewmodel._status_text`, `viewmodel._status_tags`).
A domain's codes render as `clientTransferProhibited — transfer lock set by the
registrar (a common setting)`, several joined with `; `, a code outside RFC 8056
(`connect`) as itself, and a `danger` code (`clientHold`, `serverHold`,
`pendingDelete`, `redemptionPeriod`) earns one red hero tag named for the code
(`clientHold · pendingDelete` when there are two). A record without a
`registrar` key is an IP allocation, whose RDAP words (`active`) are not EPP
codes and are shown as they are. The tag is not a reputation signal:
`reputation.grade` never sees it, and `_summary()` (link previews) reads only
the TLS tags.

A registration's age is derived, never fetched: `viewmodel.registration_age`
(days since `created` and since `updated`) and `viewmodel.cert_age` (days since
the certificate's `notBefore`) count whole UTC days through
`viewmodel._age_days`. It reads a datetime or an ISO 8601 string, takes a naive
time as UTC, counts a time up to a day ahead as 0 (python-whois's naive
registry-local times) and answers None, never an exception, for anything else.
The WHOIS panel's `Age` row ("6 days (updated 2 days ago)") is a domain's
only. As for the Status row, a record without a `registrar` key is an IP
allocation, so IP lookups and the self page (`whois_fill`) read as they did.
The hero tags a domain registered fewer than `YOUNG_DOMAIN_DAYS` (30) days
ago with an amber `REGISTERED N DAYS AGO`; 0 turns the tag off. A certificate's
age is never tagged, since ACME renews every few weeks, and `_summary()` reads
only the `TLS` tags, so link previews do not change.
`?fields=domain_age_days` and `cert_age_days` and MCP `registration.age_days`
and `tls.age_days` carry the same numbers (`mcp_server.compact_registration` /
`compact_ssl`, which `textfmt.field_values` reads); `domain_age_days` is `-`
for an IP, whose registration is its network's.

#### Error Handling

- A registration failure is `{"error": "..."}` in the response, never a 500
- A DNS query that fails is never an empty list: each record type's outcome is
  in `domain.status` (`ok|noanswer|nxdomain|timeout|servfail|error`, from
  `managers.dns_status`), next to the unchanged record keys. The page prints
  `(timed out)`-style text and an NXDOMAIN banner; MCP `dns_records` returns
  `{"error": status}` for a failed type. The MX status is the zone's when the
  name fell back to the zone's MX, and the DMARC status the registrable
  domain's when the name fell back to its record
- An IP's forward-confirmed reverse DNS (`viewmodel.fcrdns_state`) is read
  off its PTR and the sweep of the PTR name already fetched, never a query of
  its own: `unknown` when that A/AAAA query failed, never `unconfirmed`. The
  page's PTR row says `→ confirmed` or `→ does not point back`, never spoofed:
  CDNs and shared hosts fail the check legitimately.
  `?fields=reverse_dns_confirmed` stays out of the text block
  (`textfmt._NOT_IN_BLOCK`), where every IP lookup would pay for the sweep,
  and is `-` on `/`, since `main._self_fields` sweeps nothing. MCP `lookup`
  returns the state itself as `reverse_dns_confirmed`, null for a domain
- An untrusted TLS certificate is still returned, with `trusted: false` and `verify_error`; an unreachable port 443 or failed handshake is `{"error", "reason"}`; `None` only when no handshake was attempted
- A browser gets `templates/error.html` for a 400, 403, 429 or 503, with the
  same status as the JSON (`main.render_error`); every other client gets the
  JSON

#### Logging

Configured at `main` module scope:
- Console and file logging (`service.log`, in the working directory)
- `TimedRotatingFileHandler`: daily rotation, `LOG_RETENTION_DAYS` (7) kept;
  `/privacy` reads the same constant
- Request format: `client={client_ip} lookup={target}`; a target with an `@`
  in it is refused and written as `<email-like>` (`lookup.loggable_target`), so
  an email address or a URL's password stays out of the line. uvicorn's access
  line and the OTel trace still carry the path as sent
- Repeated `SECURITY: Blocked banned IP` warnings (the lookup line, the admin
  line, and the MCP "Blocked manually banned IP" line) go through
  `main._log_blocked_ban` and `security.BlockedBanLog`. The first hit logs the
  original wording, so a SigNoz match on that wording still hits; repeats for
  the same (kind, sanitized IP) stay quiet for
  `BLOCKED_IP_LOG_INTERVAL_SECONDS` (3600), then one line carries
  `(%d similar block(s) suppressed)`. A window whose suppressed count is 0
  logs a fresh first line. Geo-block and rate-limit logs are unchanged

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

#### Mobile layout

`static/css/whatismyip.css`, the `@media (max-width: 900px)` blocks and
`@media (hover: none)`; `tests/test_page.py` `TestMobileLayout` pins each rule
below by text:
- Under 900px the search box (`.search input`) and the subdomain filter
  (`.subdomains__filter`) are 16px: iOS Safari zooms a focused field below
  that, and the viewport meta rightly leaves pinch-zoom on (`maximum-scale`
  would take it away), so the font size is the fix. Desktop keeps 14px in the
  440px box and 12.5px in the filter. The filter's 16px rule sits after its
  base rule, not in the main 900px block: same specificity, later wins.
- `@media (hover: none)` hides the `/` badge (`kbd.search__hint`) on
  touch-first devices. The keydown handler in `app.js` stays, so an attached
  keyboard still has the shortcut. `_search.html` is one include, so
  `browser.html`, `error.html` and `privacy.html` all get the rule.
- Accordion titles never wrap (`.accordion__title`), and a hint that does not
  fit truncates with an ellipsis (`.hint`). The cut is visual: the DOM text
  stays whole for a screen reader, and the span's `title` repeats it, so
  everything that writes a hint writes `title` too — the template,
  `app.js`'s `setWhoisHint` / `setSubdomainHint`, `fingerprint.js`'s
  `setHint`. The 390px self page cuts the DNS hint
  (`A 0 · AAAA 0 · MX 0 · NS 0 · TXT 0`); opening the accordion shows it all.
- `.copy-icon` (the fingerprint UNIQUE ID row) is a 24px target: the 14px
  icon with 5px padding, WCAG 2.2's minimum (2.5.8).

#### Lookup links

`main.lookup_href`, `main._dns_rows`, `viewmodel.build_view(link_for=)`:
- Every hostname and address the page prints links to its own lookup: the
  DNS table's A/AAAA/NS/MX/CNAME values (the record's field, so an MX links
  its host, never `10 host.`; a CNAME hop row its hop's target), the rDNS and
  PTR facts, the hero's `A → ip` tag, the WHOIS name servers and the
  subdomain list. TXT rows and failed (`tone: warning`) rows never link.
- `lookup_href(value)` is the one rule: `/{value}` only when `classify_target`
  calls it a domain (written as `lookup.canonical_hostname` spells it: no
  trailing dot, lower case, A-label) or `is_safe_ip` passes the address
  (`quote(..., safe=":")` keeps an IPv6 address's colons); anything else is
  `None` and renders as text. So a private or reserved address never links to
  the 400 page, nor does a special-use name `classify_target` refuses, and a
  name without a public suffix (`ns1.corp.internal`) never becomes a path the
  suspicious-path detector would ban a visitor for.
- Only a row or tag that links gains an `href` key (`main._linked_row`,
  `viewmodel._linked`); every other dict is the one it was, which the tests
  that compare rows and tags whole rely on.
- The anchor wraps the value alone. The DNS table's `(zone)` and `(of
  <owner>)` markers, and the PTR row's FCrDNS verdict (`_ptr_row`'s `suffix`,
  ` → confirmed`), follow it as plain text in the same cell or span.
- `viewmodel.py` stays pure: `render_page` passes `link_for=lookup_href` into
  `build_view()`, whose default `None` links nothing (what
  `tests/test_viewmodel.py` runs on). `whois_display` keeps the name servers
  as one string; `view.whois_name_servers` (`viewmodel.name_server_links`)
  carries them one entry each, and the template draws the "Name servers" row
  from it.
- Every such link is `<a class="lookup-link" … rel="nofollow">` (the hero's
  tag: `class="tag … lookup-link"`, the whole tag, whose border lights on
  hover and focus), in the template and in the anchors `static/js/app.js`
  builds for the subdomain list. `robots.txt` disallows only `?subdomains=`,
  so without `nofollow` a crawler would walk nasa.gov → akam.net → its
  addresses → their PTR names, a full RDAP/DNS/TLS lookup per page,
  `no-store`. Each click is an ordinary lookup under the unchanged rate limit
  (429 and a one-hour ban).
- The self page links the visitor's own PTR name (and the addresses its
  sweep found) too. The page asks nothing new; only a click looks a value
  up, so an address link reaches AbuseIPDB exactly as typing that address
  would, and never on its own.
- The JSON and text responses are untouched: `_dns_rows` and the view model
  feed only the template, so no `href` reaches an API answer.

#### Fingerprint panel

`static/js/fingerprint.js`, `templates/browser.html` (`#acc-fingerprint`):
- Computed in the browser from the page alone, never sent or stored: the CSP's
  `default-src 'self'` would allow a same-origin fetch, so only the file keeps
  that promise (`tests/test_page.py::TestFingerprintPanel::test_module_is_display_only`
  and the `sent`/`stored` tripwires in `tests/test_fingerprint_consistency.py`).
- Its first two rows, "Clock vs address" and "Languages vs address", compare
  `Intl`'s time zone, `getTimezoneOffset()` and the region subtags of
  `navigator.languages` with `location.time_zone`, `country_code` and
  `precision` read from `#page-data`. `compareZones` and `compareLanguages`
  are pure, exported under a `module.exports` guard like `webrtc.js`, and
  answer `same`, `differs` or `not_comparable` with a reason. The wording is
  a hint ("differs: a VPN, proxy or travelling device, and any site can
  notice it too"), never a detection claim: travellers, expats and a
  deliberate English-and-UTC setup all mismatch. A `precision` other than
  `"city"` (a GeoLite2 centroid 1000 km wide says nothing about a clock), a
  null `time_zone`, a browser reporting UTC and a zone the engine does not
  know are `not_comparable`, and so is any zone in an engine without
  `timeZoneName: "shortOffset"` (Safari before 15.4). Every other zone,
  Atlantic/Reykjavik included, is compared by name and offset with no rule of
  its own. Two zone names with the same current offset still read `differs`,
  worded as "the same UTC offset"; any listed language whose region is the
  address's country reads `same`.
- Both zone names go through `canonicalZone` (the engine's
  `resolvedOptions().timeZone`) before they are compared: V8 reports
  `Asia/Calcutta`, `Europe/Kiev` and `Asia/Saigon` where GeoLite2 has the
  modern names, and plain string equality would flag every visitor there.
- The two rows are not signals: they stay out of `signals`, of the UNIQUE ID
  material and of the bit and signal counts, because they change with the
  network and the ID must survive a reload. The row constants are declared
  before phase 1, which renders them; a `const` lower in the file would still
  be in its temporal dead zone.
- Node runs the pure functions and a fake-DOM harness
  (`tests/test_fingerprint_consistency.py`), which skips without node;
  `test_page.py` pins the exports, the labels and the `#page-data` contract
  without node.

#### Web manifest and theme colour

`static/site.webmanifest`, linked from all three templates' `<head>`:
- It is what "Install app" and "Add to Home Screen" read: `name` WhatIsMyIP,
  `short_name` My IP, `description` = `viewmodel.SITE_DESCRIPTION`,
  `id`/`start_url`/`scope` `/`, `display: standalone`, `theme_color` and
  `background_color` = `--bg`, and shortcuts to `/` and `/privacy`.
  `tests/test_page.py` `TestWebManifest` pins each against its source: change
  `--bg` (and `REQUIRED_TOKENS`) and it fails until the manifest follows.
- Every URL in it starts with `/`. A browser resolves the manifest's URLs
  against its own address, `/static/site.webmanifest`, so `./` would open
  `/static/`.
- The app icons are `purpose: "any"`. Both PNGs are full-bleed, so `maskable`
  alone let a round launcher crop the magnifier, and Chrome installs only with
  an `any` icon of 144px or more. Add a `maskable` entry back only with artwork
  that keeps the safe-zone margin. Each shortcut carries the 96×96 favicon,
  since DevTools flags a shortcut without a 96×96 icon.
- No service worker. Offline means nothing for a lookup, and a worker's cache
  would fight the lookup routes' `Cache-Control: no-store`. Launching the app,
  or its My IP shortcut, is one self lookup, the same as a visit; `/privacy` is
  a fixed answer outside the lookup budget. `start_url` carries no
  `?utm_source=`.
- All three templates carry `<meta name="theme-color" content="#0B0D12">` and
  `<meta name="color-scheme" content="dark">` under the viewport meta. Android
  Chrome's address bar and Safari's tab bar take the first; the second draws
  scrollbars and other unstyled controls dark, also on an error page whose
  stylesheet a banned address cannot fetch. One value each, because the CSS
  has no light branch (`TestDesignTokens.test_no_light_mode_branch`); a light
  theme would add `media="(prefers-color-scheme: ...)"` variants.
  `TestThemeColor` pins both on all three templates.

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
- `initialize` reports `serverInfo.version` as `config.APP_VERSION`, passed as
  `MCPServer(..., version=)`: the deployed commit, the same value as `/healthz`
  `version`, or `unknown`. The SDK sends `""` when none is given. It is not
  `server.json`'s registry version, which is not in the image and is bumped
  only when the listing changes.
- Every tool is registered with `title=` and `annotations=`: `_READ_ONLY`
  (`read_only_hint=True, destructive_hint=False, idempotent_hint=True,
  open_world_hint=True`) for the four that reach another system, and
  `_READ_ONLY_LOCAL` (`open_world_hint=False`) for `whoami_caller`, which
  reads only the mmdb and the lists in memory. Without annotations the spec's
  defaults (`readOnlyHint=false`, `destructiveHint=true`) present five write
  tools. Hints, not guarantees. `server.json` lists no tools, so it does not
  change.
- `MCPServer(...)` also gets `title`, `description`, `website_url` and
  `icons` from `config.MCP_SERVER_TITLE`, `MCP_SERVER_DESCRIPTION`,
  `MCP_WEBSITE_URL` and `MCP_ICON_URL`: the same card as `server.json`, which
  is not in the image. `tests/test_mcp_registry.py` fails when the two
  disagree, so change both together. They are constants, not env: the
  registry card names this host, and `PUBLIC_BASE_URL` defaults to `""`.
- `instructions` is `_INSTRUCTIONS`: `_NOT_SAFE` and `_CALLER_ORIGIN` joined,
  no sentence of its own. `whoami_caller`'s description is set as `__doc__`
  from `_CALLER_ORIGIN` and the tool registered right after the function,
  where its decorator stood (a docstring is a literal and cannot read a
  constant), so the description and `instructions` cannot drift and
  `tools/list` keeps its order (`test_tools_list_exposes_the_five_tools`
  pins it). Most clients ignore `instructions`; the descriptions keep their
  caveats. With `ASINFO_ENABLED` the list has a sixth tool, `as_info`, after
  `whoami_caller`; conftest turns the switch off, so that test keeps its five.
- `cache_hints` lets a 2026-07-28 client keep `tools/list` for
  `TOOLS_LIST_TTL_MS` (a day, `public`); the handshake-era wire (2025-11-25
  and earlier) has no `ttlMs` field, so the test reads the hint through the
  per-request envelope (`_modern_rpc` in `tests/test_mcp.py`: `params._meta`
  with the protocol version and client capabilities, plus
  `MCP-Protocol-Version` and `Mcp-Method` headers; `server/discover` stands
  in for `initialize`) and checks that the `_rpc` list carries none. A
  renamed or removed tool reaches a caching client up to a day late.
- `compact_location` carries `precision` and `country_source` and nulls
  `lat`/`lon`/`time_zone` unless `precision` is `city`: the HTTP JSON keeps
  the numbers, the model gets only what the grade supports (a centroid's
  America/Chicago is nobody's time zone). `lookup` and `whoami_caller` say so
  in their descriptions.
- Tool return annotations need `dict[str, Any]`, not a bare `dict` — the SDK
  can't build an output schema from a bare `dict`, so the response never gets
  `structuredContent`.
- A call that failed outright returns `_fail()`: a `CallToolResult` with
  `isError` set and `{"error": ...}` as `structuredContent` (plus `code`,
  through `_fail`'s `**extra`, for a refused address:
  `_fail(exc.message, code=exc.code)` in the three `gather()` tools). The annotation
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
├── security.py          # IP bans, per-IP rules, rate limit, suspicious paths, geo-blocking, ban-log dedupe
├── rdap.py              # RDAP-first registration lookups + WHOIS normalisation, breaker
├── eppstatus.py         # EPP status codes: one spelling (epp_code), a meaning and tone per code
├── dnssecurity.py       # SPF/DMARC/DKIM/CAA/DNSSEC/MTA-STS/TLS-RPT/BIMI: queries + grading
├── models.py            # GeoRulesUpdate, the one Pydantic model
├── lookup.py            # transport-agnostic lookup pipeline (gather()), manager singletons
├── concurrency.py       # lookup gate (503 when full) + RDAP/WHOIS and crt.sh pools
├── textfmt.py           # ?format=text and ?fields=: field table, rendering (pure)
├── subdomains.py        # crt.sh adapter, normalization, cache-fill orchestration
├── subdomain_store.py   # SQLite cache for subdomains.py (data/subdomains.sqlite3)
├── reputation.py        # IP reputation lists (data/reputation/), bisect lookups; score 0-100
├── abuseipdb.py         # AbuseIPDB score for a directly looked-up IP: cache, daily quota
├── asinfo.py            # AS information: seven datasets -> one SQLite file (data/asinfo/), route and AS reads
├── mcp_server.py        # public MCP server mounted at /mcp
├── geo.py               # Gazetteer lookup + haversine distance
├── mapgeom.py           # Web Mercator tiles, antimeridian wrap, great-circle arcs
├── viewmodel.py         # response_data -> template view (pure, no I/O)
├── healthcheck.py       # Docker HEALTHCHECK: /healthz answers 200 or not
├── server.json          # official MCP Registry entry (see mcp-publish.yml)
├── scripts/
│   ├── build_gazetteer.py  # regenerates static/geo/*.json from GeoNames
│   └── fetch_fonts.sh      # vendors Inter + JetBrains Mono into static/fonts/ as pyftsubset subsets (uvx; not a dependency)
├── templates/
│   ├── browser.html     # server-rendered lookup page (no client-side templating)
│   ├── error.html       # 400/403/429/503 page for browsers, same status as the JSON
│   ├── as.html          # /AS<n>: the AS card, its lists and prefixes
│   ├── _raw_json.html   # the Raw JSON panel, shared by browser.html and as.html
│   ├── privacy.html     # /privacy, filled from the constants the code runs on
│   ├── _search.html     # search box included by browser.html and error.html (app.js finds it by id)
│   └── _footer.html     # footer included by all three pages
├── static/
│   ├── css/whatismyip.css  # design tokens + layout (dark only); jsoneditor.css is vendored
│   ├── js/app.js           # search, copy, accordions, WHOIS fill-in, subdomain panel, lazy JSONEditor
│   ├── js/map.js           # paints the server's map payload, with the attribution
│   ├── js/fingerprint.js   # self page's browser fingerprint + clock/languages vs address rows, client-side only; the active probes wait for the panel's first opening
│   ├── js/webrtc.js        # opt-in WebRTC leak test (one STUN request from the browser)
│   ├── js/jsoneditor.min.js # vendored, loaded only when the Raw JSON panel opens
│   ├── fonts/              # self-hosted woff2 (CSP blocks font CDNs): per face a -latin, an -extended-a and a -cyrillic-greek file behind unicode-range
│   ├── image/, favicons    # logo (also og:image), icons, web manifest
│   └── geo/                # cities.json, countries.json (generated, committed)
├── tests/                  # see Testing Strategy for each file
│   ├── asinfo_fixtures.py  # synthetic files in each source format + build_manager(), for the asinfo tests
│   ├── conftest.py         # env switches and a state dir per run, set before main is imported;
│   │                       # per-test reset of module state; offline defaults and the network guard
│   └── fixtures/           # MaxMind's GeoLite2 test mmdbs, the MCP server.json schema
├── docs/
│   ├── images/          # README screenshots
│   └── ops/             # alerts.md (healthz probe, SigNoz alerts), mcp-directories.md
├── .github/
│   ├── dependabot.yml   # Mondays: pip as otel + minor-and-patch groups, other majors alone;
│   │                    # GitHub Actions one group, Docker ungrouped
│   └── workflows/       # ci, deploy, healthz-probe, mcp-publish, security-audit
├── data/                # Volume mount for persistent data (Docker); gitignored contents:
│                        # GeoLite2 mmdbs, tld/, reputation/, asinfo/, subdomains.sqlite3, bans/rules
├── Dockerfile           # single stage: poetry export + uv pip, non-root, OTel entrypoint
├── Makefile             # Docker workflow automation
└── pyproject.toml       # Poetry dependencies and ruff/pytest config
```

### Map subsystem

**Coordinates**: from GeoLite2-City's `location`. When it has none (or only the
geoip2fast country fallback is loaded), `static/geo/cities.json` (GeoNames cities15000)
matches the city name, with a population-weighted country centroid as the last
resort (`geo.Gazetteer.resolve`). Private IPs get no map.

**Precision**: `lookup.lookup_location` grades GeoLite2's coordinates as
`location.precision` (`geo.coordinate_precision`), and `main._apply_resolved_target`
overwrites it with the gazetteer's grade for the coordinates the page draws;
`build_map_payload` puts the visitor's on `origin.precision`. `viewmodel._city_line`
prints "approximate · country-level" (or "registered in … · location unknown"
when `country_source` is `registered`) in place of a city, and `distance_text`
exists only when both ends are `city` (`viewmodel._precise_route`); the JSON's
numbers never change. `render_page` hands map.js `target_precision` and
`origin_precision`, and `pin()` draws a non-city pin as `map__pin--approx`
(dashed in CSS, a halo half as wide again) with no `map__distance` chip.
map.js exports `pin` for node like webrtc.js does; `tests/test_map_pin.py`
runs it, and the page wiring that feeds it, against a fake document.

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
The HTTP gate sees the canonical spelling, so an IDN such as `/straße.de` reaches
it as its A-label; the MCP subdomains tool checks its argument as given.
`.onion` and `home.arpa` names are refused there too (`config.SPECIAL_USE_NAMES`,
the same two suffixes `lookup.special_use_suffix` refuses, on the same IDNA
2003 name): crt.sh may hold
`.onion` certificates, but a Tor address typed here is not sent to a third
party any more than to the DNS.

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
The page's Level row prints `none` as "No signals" and null as "Unknown"
(`viewmodel._level_text`); the JSON, MCP and `?fields=risk_level` keep the word
`none`. `score` is the sum of signal weights capped at 100
(`reputation.risk_score`, `SCORE_MAX`); 100 is the most dangerous, it is null
when `checked` is empty, and 0 is the `none` band, not a clean bill. The page's
Score row sits after Level (`viewmodel._score_text`: "N of 100" or "Unknown").
`?fields=risk_score` stays out of the text block with `risk_level` and
`risk_signals` (`textfmt._RISK_FIELDS`, `_NOT_IN_BLOCK`). MCP
`compact_reputation` carries `score`; a new output key does not bump
`server.json`. Likewise the WHOIS facts column says "record found", never "available",
for a lookup that found a record: "available" beside a name reads as "available
to register".

**Tests.** `tests/conftest.py` sets `REPUTATION_ENABLED=false`, so no test can
make a Spamhaus download (even one that starts a real scheduler) and every other
test sees the responses it always did. `tests/test_reputation.py` builds enabled
managers over synthetic lists and monkeypatches `lookup.reputation_manager` (and
`main.reputation_manager` for `/healthz`).

**AbuseIPDB is the exception: a request per address.** With
`ABUSEIPDB_API_KEY` set, `lookup._run_legs` sends an IP target to AbuseIPDB
(`abuseipdb.py`) alongside the other legs. Only a target given as an IP: never
the address a domain resolves to, and never the visitor's own (`_self_lookup`
and `whoami_caller` call `ip_reputation()`, which has no AbuseIPDB part), since
that would hand every visitor's address to a third party unasked. And only
when the `reputation` leg is wanted: MCP `dns_records` and `ssl_certificate`
of an IP, and `?fields=` without a reputation field, ask nothing. Keep it that
way. The free plan allows 1,000 checks a UTC day, so an answer is cached a day
per address and no request goes out past `ABUSEIPDB_DAILY_LIMIT` or after
AbuseIPDB reports the quota spent (`X-RateLimit-Remaining: 0`, `429`) until its
reset. Never ask for `verbose`: the reports' comments are other users' free
text. The score is the signal's weight, so it grades on the same bands as the
lists; a score of 0 is `checked`, not a signal, and a failure is in
`unavailable`. That weight is added into `score` and then capped at 100, while
`level` is graded on the uncapped sum, so the bands do not move.
`tests/conftest.py` empties `ABUSEIPDB_API_KEY`, so a key in a
developer's `.env` never reaches a test; `tests/test_abuseipdb.py` builds
enabled clients over a fake transport.

### AS information

**Downloaded by the scheduler, read from one SQLite file.** The
`refresh-asinfo` job (`AsInfoManager.refresh()`) downloads seven datasets into
`data/asinfo/`, builds `asinfo.sqlite3.tmp` from the copies and swaps it in
with `os.replace()`; a request reads the live file through
`lookup.address_as_info` / `lookup.as_info_for_asn`, which make no outbound
request and add no SSRF surface. A failed download keeps the previous copy and
a failed build the previous database. The datasets, with the credit each one's
card line carries (`asinfo.Dataset.credit`):

- RIPE NCC AS names (`asn.txt`), the NRO delegated statistics, and the RIPE RIS
  whois dumps for IPv4 and IPv6: daily. "Source: RIPE NCC".
- RPKI VRPs from rpki-client's `rpki.csv`, asked for with `Accept-Encoding:
  gzip`: daily. "RPKI data validated by rpki-client.org".
- CAIDA AS relationships (`YYYYMM01.as-rel2.txt.bz2`) and organizations
  (`YYYYMMDD.as-org2info.jsonl.gz`): the directory listing is read daily and a
  file is downloaded only when the listing names a newer one than the copy.
  "The CAIDA UCSD AS Relationships Dataset, <file date>" and "... AS
  Organizations Dataset, <file date>", the date being the file's own.
- Spamhaus ASN-DROP is not downloaded here: `ReputationManager.asn_listed`
  reads the list `reputation.py` keeps.

**Download rules.** Each request's time is written to `<file>.requested`
before the request is sent, so a failed request and a restart both count, and a
dataset is not asked again within `ASINFO_RETRY_SECONDS`. A download is
streamed to `<file>.tmp` under a byte cap per dataset (NRO is 57 MB, so
`reputation.MAX_LIST_BYTES` would be too small), refused when it ends short of
its `Content-Length` (`http.client` answers a dropped connection with an early
end of file, and a plain-text list cut in half can still clear `min_rows`), and
refused when its parser returns fewer than the dataset's `min_rows`. `min_rows`
counts rows after the parser's filters, so a reformatted file that parses to
almost nothing is rejected too. All sources are sent `REPUTATION_USER_AGENT`;
every URL is overridable by env (`ASINFO_*_URL`).

**Build rules.** A RIS row seen by fewer than `ASINFO_MIN_RIS_PEERS` (10) peers
is dropped: most are leaks and more-specific noise. So is a prefix shorter than
/8 (IPv4) or /16 (IPv6), whatever its count, and a row whose origin is not a
plain integer (an AS_SET). RPKI state (RFC 6811: `valid`, `invalid` with reason
`origin` or `length`, `not-found`) is computed at build time **per (prefix,
origin)**, so a prefix announced by two origins keeps both, each with its own
state and peer count, and the VRPs are not stored. Per-AS aggregates (prefix
counts, address space, RPKI counts, neighbour counts) are computed at build
time too. An IPv4-mapped IPv6 address is matched as the IPv4 address it
carries, as `ReputationManager.check` does.

**"Unavailable" is never empty.** A dataset that is missing, failed to build or
is past its maximum age (`ASINFO_MAX_AGE_HOURS` 72 for the daily ones; CAIDA's
75 days for relationships and 200 for organizations, from the file's own date)
is in the card's `unavailable` with its reason, and its section is `None`. A
`None` section whose dataset is in `unavailable` reads **Unknown**; with the
dataset available it reads "Not in <dataset>" (`viewmodel`). Neither is ever
"0 upstreams" or an empty list. An address no RIS peer routes is `route: null`
and `announced: false`, which is a finding, not a gap. A fresh volume (enabled,
no database yet) answers with every section `None` and every dataset
unavailable, and `/healthz` says `asinfo_unavailable` only after the first
build attempt (`AsInfoManager.build_attempted`) or when a database file exists
and will not open. `asinfo_dataset_stale` is one reason per stale dataset.

**Which AS the card describes.** The route's origin AS (a multi-origin prefix:
the origin seen by the most peers), else GeoLite2-ASN's number for the address;
`source` says which (`route` or `geolite2`). The AS facts follow that number,
and `location.asn_*` is unchanged. So the card's `asn_drop` (ASN-DROP matched
on the card's AS) can disagree for one address with `reputation`'s ASN-DROP
signal (matched on GeoLite2's number) when the two ASNs differ; neither is
wrong, and `reputation` is not changed by AS data.

**Special-purpose ASNs.** `lookup._SPECIAL_ASN` (0, `AS_TRANS`, documentation,
private use, the reserved ranges) answer `200` from `/AS<n>` with `special`
(`code, label, first, last, defined_in, purpose`) and read no dataset: a
private ASN that leaked into RIS, or an AS0 ROA, would otherwise draw a card
that looks like someone's network. An IP routed from one keeps its route and
RPKI state; its `as_info` carries `special` and the AS sections are `None`,
and only the datasets the route came from are credited.

**Performance and size.** Reads run inline on the event-loop thread, like
GeoIP; nothing in them is slow enough to need a pool. The build runs in the
scheduler's thread. Measured on real data (2026-10-20, macOS, not yet on the
Debian image): a refresh of all seven datasets takes about 72 s, raises the
process's peak RSS by about 55 MB, leaves about 241 MB in `data/asinfo/`
(database 152 MB, copies 82 MB) and about 383 MB while the new database sits
beside the old one. SQLite's build temp files (about 140 to 210 MB, `PRAGMA
temp_store = FILE`) go to the system temp directory, not the volume; nothing
sets `SQLITE_TMPDIR`.

**Credits and terms.** The card carries the credit lines above, and
`/privacy` the hosts (`asinfo_manager.hosts()`, shown only when the manager is
enabled), that nothing is downloaded for a particular lookup, and, when CAIDA's
datasets are in use, their citations with links to their dataset pages. CAIDA's terms ask that a
publication cite the dataset and report it to CAIDA; this page is such a
publication, so report it after launch (data-info@caida.org).
`ASINFO_CAIDA_ENABLED=false` turns the relationship and organization rows into
`unavailable` if CAIDA declines. The service is personal and non-commercial,
which is what these terms assume. The page-embedded JSON is escaped with
`main._script_json` (`<`, `>`, `&`), because an AS name is third-party text.

**Tests.** `tests/conftest.py` sets `ASINFO_ENABLED=false`, so the scheduler
downloads nothing and no lookup grows an `as_info` key; a test of the feature
asks for the `asinfo_enabled` fixture (a manager over `asinfo_fixtures`'
synthetic files, patched into `lookup` and `main`, clock at
`asinfo_fixtures.NOW`) or builds its own manager. Nothing in the suite touches
the network.

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
   `version` and OTel `service.version`, and the three templates' stylesheet
   URL carries it as `?v=` (`APP_VERSION`, a Jinja global set in `main.py`)
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
- `dependabot.yml`: version updates once a week, on Monday, beside the
  `security-audit.yml` run. pip comes as at most two grouped PRs, `otel`
  (every `opentelemetry-*` bump) and `minor-and-patch` (every other minor or
  patch bump), and each remaining major as a PR of its own; GitHub Actions as
  one group; Docker ungrouped. Security updates are never grouped. The pip
  groups stay in that order: Dependabot puts a dependency in the first group
  it matches, and `tests/test_dependabot_config.py` pins it. A bundle that
  bumps whoisit can go red on
  `test_rdap.py::TestBootstrapRefresh::test_the_registry_fetch_retries_no_more_than_a_query`:
  `rdap._configure_whoisit` replaces whoisit's private `_bootstrap.session`,
  and a release that renames it fails that test. Take whoisit out of the
  bundle and fix `_configure_whoisit` in a PR of its own

### Testing Strategy

Every test runs on FastAPI's `TestClient`; most use one module-level client,
which never runs the lifespan, and the MCP tests use `with TestClient(app)`,
which does. `tests/conftest.py` sets the environment before any test module
imports `main`: `BACKGROUND_REFRESH_ENABLED=false` (no lifespan starts the
scheduler or downloads anything), `REPUTATION_ENABLED=false`, `ASINFO_ENABLED=false`, an empty
`ABUSEIPDB_API_KEY`, the admin key, the trusted proxies, and ban/geo/IP-rule
files under a per-run temporary `STATE_DIR`; geo-blocking mode, country lists,
and unknown-country handling are pinned off. `pytest_sessionfinish` removes
`STATE_DIR` after the run. Its `reset_security_state` fixture (autouse) runs
`_reset_mutable_state` before and after every test: both rate-limit buckets,
the ban list, `lookup._whois_cache`, `main._self_whois_tasks`,
`main.blocked_ban_log` and `main._refresh_failures` emptied, a new RDAP breaker
bound to both
`rdap.rdap_breaker` and `main.rdap_breaker`, and the geo rules reloaded from
those defaults. A new piece of module-level state gets its line there. A test
never clears these itself, and `test_state_reset.py` fails if one does: a test
that needs a clean slate between two of its own steps lifts what the last step
changed (`ip_ban_manager.unban_ip`), and one that needs a longer burst than a
rate limit allows raises that limiter's `requests_per_second` with
`monkeypatch`.

The external lookups each test checks (RDAP/WHOIS, GeoIP, DNS, TLS) are mocked,
and importing `main` makes no network call. The suite runs offline, and
`tests/conftest.py` keeps it that way in two layers:
- `offline_lookups` (autouse) fails whatever a test leaves unmocked the way a
  machine with no network would. dnspython's `Resolver.resolve`, which every
  DNS query goes through (`zone_apex`'s SOA walk and PTR included), raises
  `NoNameservers`; whoisit's `bootstrap`, `ip` and `domain` raise `QueryError`;
  python-whois's `whois()` raises `ConnectionRefusedError`. TLS needs no stub:
  with no address there is no handshake. These sit at the library edge, under
  every seam the suite mocks, so a test's own patch (`lookup.lookup_rdap`,
  `managers._recursive_resolver`, `Resolver.resolve`, ...) goes on top and
  wins. A test that asserts on DNS or RDAP behaviour mocks it itself.
- A guard on the socket layer, installed when conftest is imported, refuses
  any `connect`/`connect_ex`, UDP `sendto` or hostname lookup (`getaddrinfo`,
  `gethostbyname`) that is not to loopback, and fails the test that made it,
  even when a worker thread made the attempt and the app swallowed the error.
  Loopback stays open: `TestClient` uses no socket, and `test_tls_reasons.py`
  and `test_healthz_degraded.py` run real servers on 127.0.0.1.
  `test_offline_guard.py` pins both layers.
- A test that genuinely needs the network is marked `@pytest.mark.network`. It
  is skipped unless `RUN_NETWORK_TESTS=1`, and then runs with neither layer in
  place. No test needs it today.
- `test_webrtc_leak.py`, `test_map_pin.py`, `test_fingerprint_probes.py`,
  `test_fingerprint_consistency.py` and `test_boot.py` run node and a fresh
  interpreter as subprocesses, outside the guard. The node tests skip when
  `node` is not installed.

Test files:
- Units: `test_geo.py` (gazetteer, distance, coordinate precision), `test_mapgeom.py` (projection,
  tiles, arcs), `test_viewmodel.py` (view model, WHOIS/SSL rendering, the
  FCrDNS verdict, registration and certificate ages),
  `test_rdap.py` (RDAP/WHOIS normalisation, fallback routing, override and
  forced bootstrap refresh behavior, JSContact names, thin records, EPP status
  codes in `eppstatus`),
  `test_managers.py` (GeoLite2 lookups, the country fallback, database
  sources and status, `TldNamesManager`, `is_valid_domain`), `test_lookup.py`
  (target normalisation, `is_safe_ip`, `gather()`), `test_subdomains.py`
  (crt.sh adapter, normalisation and the `@` rule, single-flight, budget),
  `test_subdomain_store.py` (the SQLite cache degrades to a miss)
- Boot: `test_boot.py` (importing `main` touches no network; the lifespan
  starts and stops the scheduler), `test_offline_guard.py` (the offline
  defaults and the network guard), `test_state_reset.py` (a state directory
  per run, what the per-test reset covers, no reset by hand)
- Endpoints and pages: `test_basic.py` (smoke tests, `/healthz`, refresh
  retries, boot fetch), `test_page.py` (API + HTML, map payload, DNS rows,
  security headers, fingerprint panel, `?subdomains=`, lookup links, the font
  subsets and preloads, web manifest, theme-color), `test_negotiation.py`
  (`?format=`/Accept/user-agent), `test_text_format.py`
  (`?format=text`, `?fields=`), `test_error_pages.py` (`error.html` for browsers),
  `test_open_graph.py` (link previews), `test_privacy_page.py` (`/privacy`),
  `test_robots_head.py` (`/robots.txt`, `/favicon.ico`, HEAD and the
  Content-Type and status it shares with GET),
  `test_self_first_paint.py` (self page before WHOIS, `/?whois=only`, and
  `?fields=` joining the self lookup),
  `test_ip_whois_column.py` (an IP's WHOIS column), `test_subdomain_panel.py`
  (the subdomain panel), `test_webrtc_leak.py` (the WebRTC leak test),
  `test_map_pin.py` (map.js's approximate pin and its page wiring, run in
  node), `test_fingerprint_probes.py` (the active fingerprint probes wait for
  the panel's first opening, and a click on its header reads the canvas
  inside the click, the only moment Firefox's resistFingerprinting asks),
  `test_fingerprint_consistency.py` (clock and languages vs address, in node)
- Lookup behaviour: `test_classify_target.py` (refused before any network
  work), `test_ipv6.py` (IPv6 literals, AAAA, the gating A query's log level),
  `test_dns_status.py` (a failed query is never "no records"; DMARC
  discovery), `test_cname_chain.py` (the CNAME chain and canonical name read
  off the A answer, the hop rows, the GeoIP 'Resolves via' row and
  `dns_records`' two keys), `test_zone_apex.py` (NS/MX/SPF from the zone
  apex; DMARC from the registrable domain), `test_psl_public_only.py` (the ICANN-only suffix list `zone_apex`
  floors on, kept offline), `test_dns_fanout.py` (NS/MX host cap), `test_txt_join.py` (TXT over
  255 bytes), `test_resolver_unification.py` (one resolver set and budget),
  `test_tls_reasons.py` (why a certificate fails, the TLS connect and handshake
  budgets), `test_rdap_budget.py`
  (RDAP/WHOIS cost, no port-43 for an IP), `test_concurrency_gate.py` (gate
  503s, what takes no slot, pool isolation, the legs each MCP tool runs),
  `test_subdomain_targets.py` (which targets may reach crt.sh),
  `test_dnssecurity.py` (each grading rule, the CAA climb, DO/AD, DKIM key
  lengths), `test_dns_security_leg.py` (which lookups run the leg, a broken
  leg is unknown, the JSON key), `test_reputation.py` (list parsers, intervals, grade, the 0-100 score,
  download guard, surfaces), `test_abuseipdb.py` (cache, quota, failures,
  which lookups ask, surfaces), `test_asinfo.py` (the dataset parsers, the
  build and RPKI state, route and AS reads, staleness and `unavailable`,
  download and refresh rules, swapping the file under readers),
  `test_as_target.py` (`/AS<n>`: classification, JSON, text, page, `HEAD`,
  the special-purpose numbers, never a ban), `test_as_surfaces.py` (every
  other surface: `as_info` on IP, domain and self lookups, the page's AS panel
  and links, `?fields=`, MCP, `/healthz` and `/privacy`, the credits),
  `asinfo_fixtures.py` (not a test module: the synthetic files and
  `build_manager()`, with conftest's `asinfo_enabled` fixture on top)
- Security: `test_security.py` (proxy-header trust, SSRF and TLS-rebinding
  guards, the admin key, bans, the blocked-ban log dedupe, rate limiting,
  geo-blocking, the probe detector and whitelist, per-IP rules, response
  headers, log injection), `test_ssrf.py`
  (only global unicast becomes a connection target)
- MCP: `test_mcp.py` (handshake and `serverInfo.version`, tools, transport
  limits, rate bucket),
  `test_mcp_iserror.py` (`isError` on outright failures),
  `test_mcp_manual_ban.py` (only a manual ban applies), `test_mcp_registry.py`
  (`server.json`, its publish workflow, the page's tool list, and the
  `initialize` card that must match `server.json`)
- Ops: `test_healthz_degraded.py` (`degraded` and its reasons,
  `healthcheck.py`), `test_deploy_version.py` (`/healthz` `version`),
  `test_dependabot_config.py` (the pip groups and their order, security
  updates left ungrouped, the Monday schedule next to `security-audit.yml`)

## Commit Conventions
- Never include Claude session URLs or metadata in commit messages.
- Do not add "Co-Authored-By" lines.
