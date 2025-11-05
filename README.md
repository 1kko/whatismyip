# WhatIsMyIp
![screenshot](https://github.com/user-attachments/assets/d9179bcc-7a74-4e69-8aa1-c78c185e91d8)

# IP and WHOIS Information Service
A FastAPI-based web service that provides WHOIS and GeoIP information about IP addresses and domain names. This service performs WHOIS lookups, fetches geographical information based on IP, logs the incoming requests, and keeps the GeoIP database up to date.

## Features

### Core Features
- WHOIS lookup for IP addresses and domain names
- Geographical information retrieval using GeoIP
- Reverse DNS lookup for IP addresses
- Automatic browser/API detection (HTML or JSON response)
- Background task to update GeoIP database every 3 days

### Security Features
- **IP Banning**: Persistent ban list with TTL support and automatic cleanup
- **Rate Limiting**: Sliding window rate limiter (60 req/min, 10 req/sec per IP)
- **Geographic Blocking**: Country/region-based access control with allowlist/blocklist modes
- **Suspicious Request Detection**: Automatic detection and blocking of malicious patterns (`.env`, `.php`, admin paths, etc.)
- **Request Whitelisting**: Protection for legitimate static file requests
- **Secure Admin API**: API key-protected endpoints for security management
- **Comprehensive Logging**: All security events logged with country information

> 📖 See [SECURITY.md](SECURITY.md) for detailed security documentation, configuration, and API usage.

## Requirements
- Python 3.10+
- Poetry (dependency management)
- Docker (optional, for containerized deployment)

### Key Dependencies
- FastAPI - Web framework
- uvicorn - ASGI server
- python-whois - WHOIS lookups
- geoip2fast - GeoIP database
- dnspython - DNS resolution
- python-dotenv - Environment configuration
- APScheduler - Background tasks

See `pyproject.toml` for complete dependency list.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/1kko/whatismyip.git
cd whatismyip
```

### 2. Configure security settings

```bash
# Copy environment template
cp .env.example .env

# Generate a secure API key
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Edit .env and paste your generated API key
nano .env  # or vim/code
```

**Important:** Replace `ADMIN_API_KEY=CHANGE_ME_TO_SECURE_RANDOM_STRING` with your generated key!

### 3. Install dependencies

```bash
poetry shell
poetry install
```

### 4. Build (Docker)

```bash
make
```

## Configuration

The service is configured via environment variables in `.env` file:

### Security Settings

```bash
# Admin API authentication (REQUIRED for admin endpoints)
ADMIN_API_KEY=your-secure-random-key-here

# Rate limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=60    # Max requests per minute per IP
RATE_LIMIT_REQUESTS_PER_SECOND=10    # Burst protection

# Ban durations (in seconds)
BAN_DURATION_RATE_LIMIT=3600         # 1 hour for rate limit violations
BAN_DURATION_SUSPICIOUS=86400        # 24 hours for suspicious requests

# Geographic blocking (optional)
# GEO_MODE=disabled                  # disabled, allowlist, or blocklist
# GEO_BLOCKED_COUNTRIES=CN,RU,KP     # Comma-separated country codes
# GEO_ALLOWED_COUNTRIES=US,CA,GB     # For allowlist mode
```

See `.env.example` for all available options.

## Usage

### 1. Run

#### with Docker (preferred way)
```
make serve
```

#### Run the FastAPI application

```
uvicorn main:app --host 0.0.0.0 --port 8000
```


### 2. Access the service:

- WHOIS and GeoIP lookup for your current IP:
```
GET http://localhost:8000/
```

WHOIS and GeoIP lookup for a specific domain or IP:
```
GET http://localhost:8000/{domain_or_ip}
```

## API Endpoints

### Public Endpoints

#### `GET /`

Returns WHOIS and GeoIP information for the client's IP address.

**Response:** JSON or HTML (based on User-Agent)

#### `GET /{domain_or_ip}`

Returns WHOIS and GeoIP information for the provided domain or IP address.

**Response Example:**
```json
{
  "address": "8.8.8.8",
  "datetime": "2024-09-24T06:55:45.597769Z",
  "location": {
    "ip": "8.8.8.8",
    "country_code": "US",
    "country_name": "United States",
    "city": {
      "name": "",
      "subdivision_code": "",
      "subdivision_name": "",
      "latitude": null,
      "longitude": null
    },
    "cidr": "8.8.8.0/23",
    "hostname": "",
    "asn_name": "GOOGLE",
    "asn_cidr": "8.8.8.0/24",
    "is_private": false
  },
  "whois": {
    "domain_name": ["GOOGLE.COM", "google.com"],
    "registrar": "MARKMONITOR INC.",
    "whois_server": "whois.markmonitor.com",
    ...
  },
  "headers": {
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    ...
  }
}
```

### Admin Endpoints

All admin endpoints require the `api-key` header with your `ADMIN_API_KEY`.

#### Ban Management

- `GET /admin/bans` - List all banned IPs
- `POST /admin/ban/{ip}?duration=3600` - Manually ban an IP
- `DELETE /admin/ban/{ip}` - Unban an IP

#### Geographic Blocking

- `GET /admin/geo/rules` - Get current geo-blocking configuration
- `PUT /admin/geo/rules` - Update geo-blocking configuration
- `POST /admin/geo/block/country/{code}` - Block a country
- `DELETE /admin/geo/block/country/{code}` - Unblock a country
- `POST /admin/geo/allow/country/{code}` - Add country to allowlist
- `DELETE /admin/geo/allow/country/{code}` - Remove from allowlist
- `GET /admin/geo/lookup/{ip}` - Get geographic info for an IP
- `GET /admin/geo/countries` - List available country codes

#### Statistics

- `GET /admin/stats` - Get security statistics

**Example:**
```bash
# Set your API key
export API_KEY="your-api-key-from-env"

# Get all banned IPs
curl -H "api-key: $API_KEY" http://localhost:8000/admin/bans

# Block China
curl -X POST -H "api-key: $API_KEY" \
  http://localhost:8000/admin/geo/block/country/CN

# Get statistics
curl -H "api-key: $API_KEY" http://localhost:8000/admin/stats
```

> 📖 See [SECURITY.md](SECURITY.md) for complete API documentation and examples.


## Security

### Protection Layers

The service implements multiple security layers:

1. **IP Ban Check** - Blocked banned IPs immediately (403)
2. **Geographic Filtering** - Country/region-based access control (403)
3. **Request Whitelist** - Allow legitimate static files and main endpoints
4. **Suspicious Pattern Detection** - Auto-ban malicious requests (403 + ban)
5. **Rate Limiting** - Prevent abuse (429 + ban)

### Automatic Banning

IPs are automatically banned when:
- **Rate limit exceeded**: 60 requests/minute or 10 requests/second → 1 hour ban
- **Suspicious request detected**: Requests for `.env`, `.php`, `/admin`, etc. → 24 hour ban

### Blocked Request Patterns

The following patterns are automatically detected and banned:
- Environment files: `.env`
- Script files: `.php`, `.asp`, `.aspx`
- Data files: `.json`, `.xml`, `.sql`
- Backup files: `.bak`, `.log`, `.conf`, `.ini`
- Admin paths: `/admin`, `/wp-*`, `/cgi-bin/`
- Hidden files: `/.*` (dotfiles)
- Git repository: `/.git/`

### Geographic Blocking Modes

**Disabled (default):**
```bash
GEO_MODE=disabled
```

**Blocklist (recommended):**
```bash
GEO_MODE=blocklist
GEO_BLOCKED_COUNTRIES=CN,RU,KP,IR
```

**Allowlist (high security):**
```bash
GEO_MODE=allowlist
GEO_ALLOWED_COUNTRIES=US,CA,GB,DE,JP
GEO_BLOCK_UNKNOWN=true
```

### Persistent Storage

Security data is stored in the `data/` directory:
- `data/banned_ips.json` - Banned IPs with expiration times
- `data/geo_rules.json` - Geographic blocking configuration

These files persist across service restarts.

## Logging

Logs are written to console and to a file `service.log` with rotation every day, keeping the last 7 days of logs.

### Security Events

All security events are logged with the format:
```
2025-11-05 10:30:00 - main.py:805 - security_middleware - SECURITY: Banned 192.168.1.100 (CN) for suspicious request: /.env
```

View security logs:
```bash
# Watch live security events
tail -f service.log | grep SECURITY

# Count security events
grep SECURITY service.log | wc -l
```

## Quick Reference

### Common Admin Commands

```bash
# Set your API key (required for all admin commands)
export API_KEY="your-api-key-from-env"

# View all banned IPs
curl -H "api-key: $API_KEY" http://localhost:8000/admin/bans

# Ban an IP manually
curl -X POST -H "api-key: $API_KEY" \
  http://localhost:8000/admin/ban/192.168.1.100

# Unban an IP
curl -X DELETE -H "api-key: $API_KEY" \
  http://localhost:8000/admin/ban/192.168.1.100

# Block a country (China)
curl -X POST -H "api-key: $API_KEY" \
  http://localhost:8000/admin/geo/block/country/CN

# Enable blocklist mode
curl -X PUT -H "api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"mode": "blocklist"}' \
  http://localhost:8000/admin/geo/rules

# Get security statistics
curl -H "api-key: $API_KEY" http://localhost:8000/admin/stats

# Lookup IP geographic info
curl -H "api-key: $API_KEY" \
  http://localhost:8000/admin/geo/lookup/8.8.8.8
```

### Response Codes

- `200` - Success
- `403` - Forbidden (banned IP, geo-blocked, or suspicious request)
- `404` - Not Found (endpoint doesn't exist, or invalid admin API key for security)
- `429` - Too Many Requests (rate limit exceeded)

### File Locations

- Configuration: `.env`
- Ban list: `data/banned_ips.json`
- Geo rules: `data/geo_rules.json`
- Logs: `service.log` (rotated daily, 7-day retention)
- GeoIP database: Auto-downloaded and updated every 3 days

## Contributing
1. Fork the repository.
2. Create a new branch (git checkout -b feature-branch).
3. Make your changes.
4. Commit your changes (git commit -am 'Add new feature').
5. Push to the branch (git push origin feature-branch).
6. Create a new Pull Request.

## License
MIT License. See LICENSE file for details.

---

**🔒 Security:** For detailed security documentation, configuration options, and troubleshooting, see [SECURITY.md](SECURITY.md)
