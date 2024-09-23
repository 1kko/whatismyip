# WhatIsMyIp
# IP and WHOIS Information Service
A FastAPI-based web service that provides WHOIS and GeoIP information about IP addresses and domain names. This service performs WHOIS lookups, fetches geographical information based on IP, logs the incoming requests, and keeps the GeoIP database up to date.

## Features
- WHOIS lookup for IP addresses and domain names
- Geographical information retrieval using GeoIP
- Logging of incoming requests and responses
- Background task to update GeoIP database every 3 days

## Requirements
- Python 3.10+
- poetry
- docker (optional)
- Dependencies listed in requirements.txt

## Installation
1. Clone the repository:

```
git clone https://github.com/1kko/whatismyip.git
cd whatismyip
```

2. Activate virtual environment and install dependencies:

```
poetry shell
poetry install 
```

3. Build
```
make
```

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

`GET /`

Returns WHOIS and GeoIP information for the client's IP address.

`GET /{domain_or_ip}`

Returns WHOIS and GeoIP information for the provided domain or IP address.

Response:
```
{
  "ip_address": "8.8.8.8",
  "datetime": "2023-01-01T00:00:00Z",
  "location": {
    "ip": "8.8.8.8",
    "city": "Mountain View",
    "region": "California",
    "country": "US",
    "loc": "37.3860,-122.0838",
    "org": "AS15169 Google LLC",
    "postal": "94035",
    "timezone": "America/Los_Angeles"
  },
  "whois": {
    "domain_name": "GOOGLE.COM",
    "registrar": "MARKMONITOR INC.",
    "whois_server": "whois.markmonitor.com",
    ...
  },
  "headers": {
    ...
  }
}
```


## Logging
Logs are written to console and to a file service.log with rotation every day, keeping the last 7 days of logs.

## Contributing
1. Fork the repository.
2. Create a new branch (git checkout -b feature-branch).
4. Make your changes.
5. Commit your changes (git commit -am 'Add new feature').
6. Push to the branch (git push origin feature-branch).
7. Create a new Pull Request.

## License
MIT License. See LICENSE file for details.
