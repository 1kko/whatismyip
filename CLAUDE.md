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
# Run all tests (requires service running on localhost:8000)
pytest

# Run specific test
pytest tests/test_basic.py::TestBasic::test_get_domain_info

# Run with verbose output
pytest -v
```

**Note:** Tests expect the service to be running at `http://127.0.0.1:8000` before execution.

### Code Quality
```bash
# Lint with ruff
poetry run ruff check .

# Format with ruff
poetry run ruff format .
```

## Architecture

### Core Components

**Manager Classes** (main.py:116-268):
- `GeoIpManager`: Handles GeoIP database updates (every 3 days via APScheduler) and location lookups using geoip2fast
- `DomainManager`: DNS operations including A, MX, NS, CNAME, TXT record resolution, reverse DNS lookups, and domain validation
- `SSLManager`: SSL certificate retrieval for HTTPS endpoints
- `HeaderManager`: Request header filtering to remove proxy/forwarding headers
- `BrowserDetector`: User-agent analysis to determine if HTML or JSON response should be returned

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
├── main.py              # Single-file FastAPI application with all logic
├── tests/
│   └── test_basic.py    # Integration tests (requires running service)
├── templates/           # Jinja2 HTML templates for browser responses
│   └── browser.html
├── static/              # Static assets (CSS, JS, images)
├── data/                # Volume mount for persistent data (Docker)
├── Dockerfile           # Multi-stage build with poetry + uv
├── Makefile             # Docker workflow automation
└── pyproject.toml       # Poetry dependencies and project metadata
```

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

Tests are integration tests that make actual HTTP requests to a running service instance. They verify:
- Client IP information retrieval
- Domain resolution (google.com)
- Direct IP lookup (8.8.8.8)
- 404 handling for non-existent paths

**Before running tests, start the service:**
```bash
make serve  # or uvicorn main:app
pytest
```
