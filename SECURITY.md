# Security Features Documentation

## Overview

This application includes comprehensive security features to protect against malicious traffic, abuse, and unauthorized access:

- **IP Banning**: Persistent ban list with TTL support
- **Rate Limiting**: Sliding window rate limiter (per-minute and per-second limits)
- **Suspicious Request Detection**: Pattern-based detection of malicious requests
- **Geographic Blocking**: Country/region-based access control using GeoIP
- **Request Whitelisting**: Allow legitimate static file requests
- **Admin API**: Secure endpoints for security management

## Setup

### 1. Generate Admin API Key

```bash
# Generate a secure random API key
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 2. Configure Environment Variables

Copy `.env.example` to `.env` and update the values:

```bash
cp .env.example .env
chmod 600 .env   # restrict the file to the owner (contains ADMIN_API_KEY)
nano .env        # edit and paste your API key
```

**Important:** Change `ADMIN_API_KEY` to the generated secure key!

### 3. Install Dependencies

```bash
poetry install
```

### 4. Start the Service

```bash
# Development mode
poetry run python main.py

# Or using uvicorn
poetry run uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Production with Docker
make build
make serve
```

## Security Middleware Flow

Requests are processed in this order:

1. **IP Ban Check** - Block banned IPs immediately
2. **Geographic Check** - Apply country/region restrictions
3. **Suspicious Pattern Detection** - Block malicious request patterns. Skipped
   for whitelisted paths: static assets, and the lookup surface, whose target is
   an arbitrary domain and would otherwise trip rules like `\.json$`.
4. **Rate Limiting** - Prevent abuse through request frequency limits. Static
   assets under `/static/` are exempt, because a single page load fetches about
   a dozen of them and would otherwise trip the per-second limit. Everything
   else is limited, including `/` and `/{domain-or-ip}` — that is where the DNS,
   RDAP/WHOIS and TLS work happens.

`/admin/*` and `/mcp` are handled ahead of this chain: both check bans, `/admin/*`
is rate limited on the same bucket, and `/mcp` uses its own looser bucket and
never escalates to a ban (every user of a hosted AI client shares a handful of
provider egress IPs).

## Configuration

### Rate Limiting

Default values in `.env`:

```bash
RATE_LIMIT_REQUESTS_PER_MINUTE=60   # Max requests per minute per IP
RATE_LIMIT_REQUESTS_PER_SECOND=10   # Burst protection
```

### Ban Durations

```bash
BAN_DURATION_RATE_LIMIT=3600      # 1 hour for rate limit violations
BAN_DURATION_SUSPICIOUS=86400     # 24 hours for suspicious requests
```

### Suspicious Patterns

Automatically detected patterns (in `security.py`, `SuspiciousPatternDetector`):
- `.env` files
- `.php`, `.asp`, `.aspx` scripts
- `.json`, `.xml`, `.sql` files
- `.bak`, `.log`, `.conf`, `.ini` files
- `/admin`, `/wp-*` paths
- `/.git/`, `/cgi-bin/` paths
- Hidden files (dotfiles)

A lookup target is a single path segment, so `/admin.php` and `/nasa.gov` are
the same shape and a pattern match alone cannot separate a probe from a lookup.
What separates them is whether the target has a **public suffix**: a matching
request is banned unless it is a real domain or IP.

```
/.env                       -> 403 + 24h ban
/admin                      -> 403 + 24h ban
/admin.php                  -> 403 + 24h ban
/wp-login.php               -> 403 + 24h ban
/config.json                -> 403 + 24h ban
/path/.env                  -> 403 + 24h ban
/.git/config                -> 403 + 24h ban
/nasa.gov                   -> 200, ordinary lookup
/example.dev                -> 200, ordinary lookup (delegated TLD)
/8.8.8.8                    -> 200, ordinary lookup
/static/geo/countries.json  -> 200, static asset, exempt outright
```

The answer comes from `DomainManager.is_valid_domain`, which reads the Public
Suffix List that `TldNamesManager` keeps current — see "Public Suffix List"
below. The site's own search box refuses these targets before navigating, so a
visitor cannot be banned by the page's own form.

### Whitelisted Patterns

Whitelisting exempts a path from suspicious-pattern detection. Only the static
group is additionally exempt from rate limiting.

Static assets (skip the detector **and** the rate limiter):
- `/static/*.(css|js|json|png|jpg|jpeg|gif|svg|ico|webmanifest|woff|woff2)`

Lookup surface (skips the detector **only when the target is a real domain or
IP**, and is always rate limited):
- `/` - Root endpoint (own IP info)
- `/[domain-or-ip]` - Main feature (domain/IP lookup)

### Public Suffix List

Source: <https://publicsuffix.org/list/public_suffix_list.dat> (Mozilla), the
same list the `tld` package parses. IANA's flat top-level list at
<https://data.iana.org/TLD/tlds-alpha-by-domain.txt> is an alternative, but the
PSL also covers multi-label suffixes like `co.uk`, which domain validation needs.

It is not left to the `tld` package. The bundled snapshot only ages with the
release, so a TLD delegated afterwards would read as a probe; and on a cache
miss `tld` downloads the list synchronously inside whichever request needs it
first, writing into its own package directory — root-owned once the container
drops to `appuser`, so the write fails and every later lookup retries it.

The list therefore lives in the data volume:

| When | What happens |
| --- | --- |
| startup | seeded from the copy bundled with `tld`, stamped expired |
| first boot | pulled once, because the seed is expired by definition |
| daily | re-checked; re-fetched only once older than `TLD_MAX_AGE_DAYS` (14) |
| on failure | retried after `TLD_UPDATE_RETRY_SECONDS` (1 hour) |

A response missing the `===BEGIN ICANN DOMAINS===` marker is rejected rather
than installed — a list that matches nothing would make every domain read as a
probe and ban the visitors looking them up. `GET /healthz` reports which copy is
live (`downloaded`, `bundled` or `missing`) and its age.

## Admin API Usage

All admin endpoints require the `api-key` header with your `ADMIN_API_KEY`,
compared using `hmac.compare_digest`. A missing or wrong key returns `404`
rather than `401`, so the endpoints look like paths that do not exist.

**There is no IP allowlist on `/admin/*`.** The key is the entire perimeter:
the endpoints are reachable from any address, and the only IP-based checks
applied to them are the ban list and the rate limiter (exceeding it bans, with
reason `rate_limit_admin`). Note that `bypass_ips` in `data/geo_rules.json` is a
geo-blocking bypass and plays no part in admin authentication. To restrict admin
by source address, do it in the reverse proxy or with `GEO_MODE=allowlist`;
neither is configured by default.

### Authentication

```bash
# Set your API key
export API_KEY="your-api-key-from-env-file"
```

### Ban Management

#### List all banned IPs

```bash
curl -H "api-key: $API_KEY" http://localhost:8000/admin/bans
```

#### Manually ban an IP

```bash
# Ban for default duration (24 hours)
curl -X POST -H "api-key: $API_KEY" \
  http://localhost:8000/admin/ban/192.168.1.100

# Ban for custom duration (in seconds)
curl -X POST -H "api-key: $API_KEY" \
  "http://localhost:8000/admin/ban/192.168.1.100?duration=7200"
```

#### Unban an IP

```bash
curl -X DELETE -H "api-key: $API_KEY" \
  http://localhost:8000/admin/ban/192.168.1.100
```

### Geo-Blocking Management

#### Get current geo-blocking rules

```bash
curl -H "api-key: $API_KEY" http://localhost:8000/admin/geo/rules
```

#### Update geo-blocking configuration

```bash
# Enable blocklist mode and block specific countries
curl -X PUT -H "api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "blocklist",
    "blocked_countries": ["CN", "RU", "KP"],
    "block_unknown": false
  }' \
  http://localhost:8000/admin/geo/rules
```

#### Block a country

```bash
curl -X POST -H "api-key: $API_KEY" \
  http://localhost:8000/admin/geo/block/country/CN
```

#### Unblock a country

```bash
curl -X DELETE -H "api-key: $API_KEY" \
  http://localhost:8000/admin/geo/block/country/CN
```

#### Add country to allowlist

```bash
curl -X POST -H "api-key: $API_KEY" \
  http://localhost:8000/admin/geo/allow/country/US
```

#### Remove country from allowlist

```bash
curl -X DELETE -H "api-key: $API_KEY" \
  http://localhost:8000/admin/geo/allow/country/US
```

### Geographic Information

#### Lookup IP location

```bash
curl -H "api-key: $API_KEY" \
  http://localhost:8000/admin/geo/lookup/8.8.8.8
```

#### List available country codes

```bash
curl -H "api-key: $API_KEY" \
  http://localhost:8000/admin/geo/countries
```

### Statistics

#### Get security statistics

```bash
curl -H "api-key: $API_KEY" http://localhost:8000/admin/stats
```

Returns:
- Number of banned IPs
- Number of rate-limited IPs being tracked
- Current geo-blocking mode
- Number of blocked/allowed countries

## Geo-Blocking Modes

### 1. Disabled (Default)

```json
{
  "mode": "disabled"
}
```

No geographic restrictions applied.

### 2. Blocklist Mode

```json
{
  "mode": "blocklist",
  "blocked_countries": ["CN", "RU", "KP", "IR"],
  "blocked_regions": ["US-TX"],
  "block_unknown": false
}
```

Block specific countries/regions, allow all others.

**Use case:** Public service that wants to block high-risk countries.

### 3. Allowlist Mode

```json
{
  "mode": "allowlist",
  "allowed_countries": ["US", "CA", "GB", "DE", "JP"],
  "allowed_regions": ["US-CA", "US-NY"],
  "block_unknown": true
}
```

Only allow specific countries/regions, block all others.

**Use case:** Internal service for specific geographic markets.

## Persistent Storage

### Ban List

**File:** `data/banned_ips.json`

```json
{
  "192.168.1.100": {
    "banned_at": "2025-11-05T10:30:00+00:00",
    "expires_at": "2025-11-06T10:30:00+00:00",
    "reason": "rate_limit",
    "request_path": "/api/data",
    "country": "CN"
  }
}
```

### Geo-Blocking Rules

**File:** `data/geo_rules.json`

```json
{
  "mode": "blocklist",
  "blocked_countries": ["CN", "RU", "KP"],
  "blocked_regions": [],
  "allowed_countries": [],
  "allowed_regions": [],
  "block_unknown": false,
  "bypass_ips": ["8.8.8.8"]
}
```

## Background Jobs

Automated maintenance tasks run via APScheduler:

1. **GeoIP Database Update** - Every 3 days
2. **Ban Cleanup** - Every 5 minutes (removes expired bans)
3. **Rate Limit Cleanup** - Every 1 minute (prevents memory leaks)

## Security Best Practices

### 1. Secure Your Admin API Key

- Use `secrets.token_urlsafe(32)` to generate strong keys
- Never commit `.env` to version control
- Rotate keys periodically
- Use different keys for dev/staging/production

### 2. Configure Rate Limits

Adjust based on your service needs:

```bash
# Conservative (low-traffic site)
RATE_LIMIT_REQUESTS_PER_MINUTE=30
RATE_LIMIT_REQUESTS_PER_SECOND=5

# Moderate (default)
RATE_LIMIT_REQUESTS_PER_MINUTE=60
RATE_LIMIT_REQUESTS_PER_SECOND=10

# Permissive (high-traffic site)
RATE_LIMIT_REQUESTS_PER_MINUTE=120
RATE_LIMIT_REQUESTS_PER_SECOND=20
```

### 3. Monitor Logs

Watch for security events:

```bash
# Watch live logs
tail -f service.log | grep SECURITY

# Count security events
grep SECURITY service.log | wc -l
```

### 4. Geographic Blocking Strategy

**Recommended for public services:**

```json
{
  "mode": "blocklist",
  "blocked_countries": ["CN", "RU", "KP", "IR"],
  "block_unknown": false
}
```

**For internal/regional services:**

```json
{
  "mode": "allowlist",
  "allowed_countries": ["US", "CA", "GB"],
  "block_unknown": true
}
```

### 5. Bypass Critical IPs

Add trusted IPs to bypass geo-blocking:

```json
{
  "bypass_ips": ["8.8.8.8", "1.1.1.1", "your-monitoring-ip"]
}
```

## Troubleshooting

### Admin API returns 404

**Error:** "Not Found"

**Reason:** For security purposes, admin endpoints return 404 instead of authentication errors to hide their existence from unauthorized users.

**Possible causes:**
1. **ADMIN_API_KEY not set in `.env`**
   - Generate API key: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
   - Update `.env` file with generated key
   - Restart service

2. **Invalid API key**
   - Check you're using the correct header: `api-key: YOUR_KEY`
   - Verify the key matches your `.env` file exactly
   - Ensure no extra spaces in the key
   - API key is case-sensitive

3. **Endpoint doesn't exist**
   - Verify the URL is correct
   - Check available endpoints in this documentation

### Legitimate traffic being blocked

**Check:**
1. Review whitelist patterns in `main.py` (WhitelistManager)
2. Check if IP is in ban list: `GET /admin/bans`
3. Verify geo-blocking rules: `GET /admin/geo/rules`
4. Check rate limits in `.env`

### False positive suspicious requests

**Solution:**
- Update suspicious patterns in `main.py` (SuspiciousPatternDetector)
- Add exception to whitelist patterns
- Restart service after changes

## Region Codes

Region format: `{COUNTRY_CODE}-{SUBDIVISION_CODE}`

Examples:
- `US-CA` - California, United States
- `US-NY` - New York, United States
- `US-TX` - Texas, United States
- `CA-ON` - Ontario, Canada
- `CA-QC` - Quebec, Canada
- `GB-ENG` - England, United Kingdom

Use `/admin/geo/lookup/{ip}` to find region codes for specific IPs.

## Response Codes

- `200` - Success
- `403` - Forbidden (banned IP, geo-blocked, suspicious request)
- `404` - Not Found (endpoint doesn't exist, or invalid/missing admin API key - returns this for security to hide admin endpoints)
- `429` - Too Many Requests (rate limit exceeded)

## Security Logs

All security events are logged with this format:

```
2025-11-05 10:30:00 - main.py:805 - security_middleware - SECURITY: Banned 192.168.1.100 (CN) for suspicious request: /.env
```

Log levels:
- `WARNING` - Security events (bans, blocks)
- `INFO` - Configuration changes, cleanup events
- `ERROR` - System errors

## Docker Deployment

The security features work seamlessly with Docker:

```dockerfile
# .env is loaded automatically
# Persistent storage in data/ directory
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  --env-file .env \
  whatismyip
```

Or using docker-compose:

```yaml
version: '3.8'
services:
  whatismyip:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
    env_file:
      - .env
    restart: unless-stopped
```

## Testing Security Features

### Test rate limiting

```bash
# Send 70 requests rapidly (should trigger rate limit)
for i in {1..70}; do curl http://localhost:8000/ & done

# Check if banned
curl -H "api-key: $API_KEY" http://localhost:8000/admin/bans
```

### Test suspicious request detection

```bash
# Should return 403 and ban IP
curl http://localhost:8000/.env

# Verify ban
curl -H "api-key: $API_KEY" http://localhost:8000/admin/bans
```

### Test geo-blocking

```bash
# Block China
curl -X POST -H "api-key: $API_KEY" \
  http://localhost:8000/admin/geo/block/country/CN

# Update mode to blocklist
curl -X PUT -H "api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"mode": "blocklist"}' \
  http://localhost:8000/admin/geo/rules
```

### Test whitelist (should work)

```bash
# These should all succeed
curl http://localhost:8000/static/style.css
curl http://localhost:8000/
curl http://localhost:8000/google.com
```

## Transport & Response Hardening

Set by `security_headers_middleware` in `main.py` on every response.

| Header | Value | Purpose |
|---|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | Enforce HTTPS for 2 years |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'nonce-XXX'; …; frame-ancestors 'none'` | Per-request nonce, no `'unsafe-inline'` for scripts |
| `X-Frame-Options` | `DENY` | Clickjacking defense |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME sniffing |
| `Referrer-Policy` | `no-referrer` | Don't leak URLs cross-site |
| `Permissions-Policy` | `interest-cohort=(), browsing-topics=()` | Opt out of FLoC/Topics |
| `Cross-Origin-Opener-Policy` | `same-origin` | Process isolation |
| `Server` | `hidden` | Obscure fingerprinting (+ `uvicorn --no-server-header`) |

The inline `<script>` in `templates/browser.html` gets a fresh nonce
per request from `request.state.csp_nonce`; click handlers are wired
via `addEventListener` on `data-toggle` / `data-copy` attributes
(CSP nonces do not cover `onclick="..."`).

The FastAPI app is constructed with `openapi_url=None` so
`/openapi.json` does not publish the admin attack surface.

## SSRF and DNS Rebinding

User-supplied domains/IPs flow into WHOIS, DNS, GeoIP, and SSL
certificate lookups. Two defenses:

1. **Private/reserved IP filter** (`is_safe_ip`). Any IP that falls
   in RFC1918, loopback, link-local, or reserved ranges is rejected
   with HTTP 400 before any outbound request.
2. **SSL lookup requires a verified IP** (`SSLManager.get_ssl_info`).
   The caller resolves DNS once, runs `is_safe_ip`, and passes the
   verified IP. The socket connects to that IP directly and uses the
   hostname only for SNI/cert validation. If no verified IP is
   available the SSL lookup is skipped. This closes the TOCTOU
   rebinding window between the safety check and the TCP connect.

## Reverse Proxy Trust (`TRUSTED_PROXIES`)

The app distrusts `X-Forwarded-For` and `X-Real-IP` by default.

- **Explicit allowlist**: set `TRUSTED_PROXIES=ip1,ip2,…` in `.env`
  to honor proxy headers only when the direct peer matches.
- **Unset (default)**: a private-peer heuristic kicks in. Proxy
  headers are honored only when the direct peer is RFC1918,
  loopback, or link-local — which covers Docker / Kubernetes /
  Traefik sidecar setups automatically. If the app is accidentally
  exposed without a reverse proxy, the attacker's public peer IP is
  used instead, so rate limiting and banning still track them.

## Dependency & Supply Chain

- `poetry.lock` pins every Python dep by hash. Docker install uses
  `uv pip install --require-hashes`.
- `pip-audit` runs in CI on every push (`.github/workflows/ci.yml`).
- Third-party and first-party GitHub Actions are pinned by commit
  SHA, not floating tags.
- The `python:3.12-slim` base image is pinned by multi-arch manifest
  digest.
- `.github/dependabot.yml` raises weekly PRs across GitHub Actions,
  pip, and Docker ecosystems, so pinned SHAs and digests stay fresh.

## Support

For issues or questions:
1. Check logs: `tail -f service.log`
2. Review configuration: `.env` and `data/geo_rules.json`
3. Verify admin API: `curl -H "api-key: $API_KEY" http://localhost:8000/admin/stats`
