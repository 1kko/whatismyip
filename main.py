#!/usr/bin/env python3

import datetime
import ipaddress
import logging
import socket
from logging.handlers import TimedRotatingFileHandler
from typing import Any

import dns.resolver
import uvicorn
import whois  # whoisdomain for WHOIS lookups
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import ORJSONResponse
from geoip2fast import GeoIP2Fast
from pydantic import BaseModel
from tld import exceptions as tld_exceptions
from tld import get_tld

app = FastAPI()

# GEOIP2Fast instance for GeoIP lookups
GEOIP = GeoIP2Fast()

# Configure logging
log_formatter = logging.Formatter(
    "%(asctime)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s"
)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

# File handler with rotation every 1 days, keeping 7 days of logs
file_handler = TimedRotatingFileHandler(
    "service.log", when="D", interval=1, backupCount=7
)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)


# Define the Pydantic model for the response
class WhoisResponse(BaseModel):
    address: str
    datetime: datetime.datetime
    domain: dict
    location: dict
    whois: dict
    headers: dict

    class Config:
        json_schema_extra = {
            "example": {
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
                        "latitude": None,
                        "longitude": None,
                    },
                    "cidr": "8.8.8.0/23",
                    "hostname": "",
                    "asn_name": "GOOGLE",
                    "asn_cidr": "8.8.8.0/24",
                    "is_private": False,
                },
                "whois": {
                    "domain_name": "GOOGLE.COM",
                    "registrar": "MARKMONITOR INC.",
                    "whois_server": "whois.markmonitor.com",
                    "referral_url": None,
                    "updated_date": "2020-09-09 09:21:45",
                    "creation_date": "1997-09-15 04:00:00",
                    "expiration_date": "2028-09-14 04:00:00",
                    "name_servers": [
                        "NS1.GOOGLE.COM",
                        "NS2.GOOGLE.COM",
                        "NS3.GOOGLE.COM",
                        "NS4.GOOGLE.COM",
                    ],
                    "status": "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
                    "emails": "abusecomplaints@markmonitor.com",
                    "dnssec": "unsigned",
                    "name": None,
                    "org": "Google LLC",
                    "address": None,
                    "city": None,
                    "state": "CA",
                    "zipcode": None,
                    "country": "US",
                },
            }
        }


# Function to fetch ip location data
def fetch_ip_location(ip: str) -> dict[str, Any]:
    # return whois.whois(ip)
    return GEOIP.lookup(ip).to_dict()


# GeoIP2Fast database update
def update_geoip2fast() -> None:
    try:
        update_result = GEOIP.update_file(
            "geoip2fast-city-asn-ipv6.dat.gz", "geoip2fast.dat.gz", verbose=False
        )
        reload_result = GEOIP.reload_data(verbose=False)
        logging.info(f"{update_result=}")
        logging.info(f"{reload_result=}")
    except Exception as e:
        logging.exception(f"Error updating GeoIP2Fast database: {str(e)}")
        pass


# check if is ipv4
def is_ipv4(ip: str) -> bool:
    """
    check if the ip address is valid ipv4
    """
    try:
        ip = ipaddress.ip_address(ip)
        if ip.version == 4:
            return True
        else:
            return False
    except ValueError:
        return False

# check if is valid domain name


def is_domain(domain) -> bool:
    try:
        _ = get_tld(domain, fix_protocol=True)
        return True
    except tld_exceptions.TldDomainNotFound:
        return False


def get_domain_records(domain: str, ns_servers: list | None = None) -> dict:
    """
    Get the domain records
    """
    records = {
        'mx': [],
        'ns': [],
        'cname': None,
        'txt': []
    }

    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = dns.resolver.get_default_resolver().nameservers
        for ns in ns_servers:
            server = ns if is_ipv4(ns) else dns.resolver.resolve(ns, 'A')[
                0].address
            resolver.nameservers.append(server)

        # Get MX records
        mx_records = resolver.resolve(domain, 'MX')
        for r in mx_records:
            records['mx'].append(
                {'exchange': r.exchange.to_text(), 'ttl': mx_records.rrset.ttl})

        # Get NS records
        ns_records = resolver.resolve(domain, 'NS')
        for r in ns_records:
            records['ns'].append(
                {'ns': r.target.to_text(), 'ttl': ns_records.rrset.ttl})

        # Get CNAME record
        try:
            cname_record = resolver.resolve(domain, 'CNAME')
            records['cname'] = {
                'cname': cname_record.rrset[0].target.to_text(), 'ttl': cname_record.rrset.ttl}
        except dns.resolver.NoAnswer:
            records['cname'] = None

        # Get TXT records
        txt_records = resolver.resolve(domain, 'TXT')
        for r in txt_records:
            records['txt'].append(
                {'text': r.strings, 'ttl': txt_records.rrset.ttl})

    except Exception as e:
        logging.error(f"Error retrieving DNS records for {domain}: {str(e)}")

    return records


# Create a BackgroundScheduler instance
scheduler = BackgroundScheduler()
# Schedule the GeoIP2Fast database update to run every 24 hours
scheduler.add_job(update_geoip2fast, "interval", days=3)
# Start the scheduler
scheduler.start()

# run only once to update_geoip2fast function on startup
update_geoip2fast()


@app.get("/", response_model=WhoisResponse, response_class=ORJSONResponse)
async def get_self_info(request: Request) -> dict[str, Any]:
    # Extract request headers
    request_headers = dict(request.headers)

    # Get the client's IP address
    # this is considered runnint in a reverse proxy
    client_ip = request_headers.get("x-real-ip", request.client.host)
    logging.info(f"client={client_ip} lookup={client_ip} (self)")

    # Perform a WHOIS lookup for the client's IP address or domain
    try:
        whois_data = whois.whois(client_ip)
    except Exception as e:
        whois_data = {"error": str(e)}

    # Await the result of the IP location task
    ip_data = fetch_ip_location(client_ip)
    # remove elapsed_time
    ip_data.pop("elapsed_time", None)

    # Return the IP info and WHOIS data as JSON
    response_data = {
        "address": client_ip,
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "domain": {},
        "location": ip_data,
        "whois": whois_data,
        "headers": request_headers,
    }
    return response_data


@app.get("/{domain_ip}", response_model=WhoisResponse, response_class=ORJSONResponse)
async def get_ip_info(domain_ip: str, request: Request) -> dict[str, Any]:
    if domain_ip in [
        "favicon.ico",
        "robots.txt",
        "apple-touch-icon.png",
        "apple-touch-icon-precomposed.png",
        "apple-touch-icon-120x120.png",
        "apple-touch-icon-120x120-precomposed.png",
        "apple-touch-icon-152x152.png",
        "apple-touch-icon-152x152-precomposed.png",
    ]:
        raise HTTPException(status_code=404, detail="Not Found")
    # Extract request headers
    request_headers = dict(request.headers)
    # remove host header
    request_headers.pop("host", None)

    # this is considered runnint in a reverse proxy
    client_ip = request_headers.get("x-real-ip", request.client.host)
    logging.info(f"client={client_ip} lookup={domain_ip}")

    # Perform a WHOIS lookup for given address
    try:
        whois_data = whois.whois(domain_ip)
    except Exception as e:
        whois_data = {"error": str(e)}

    if is_domain(domain_ip):
        logging.debug(f"domain={domain_ip}")
        resolved_ip = socket.gethostbyname(domain_ip)
        domain_data = get_domain_records(
            domain_ip, ns_servers=whois_data.get("name_servers", []))
    elif is_ipv4(domain_ip):
        logging.debug(f"ip={domain_ip}")
        domain_data = {}
        resolved_ip = domain_ip

    # Await the result of the IP location task
    ip_data = fetch_ip_location(resolved_ip)
    # remove elapsed_time
    ip_data.pop("elapsed_time", None)

    # Return the IP info and WHOIS data as JSON
    response_data = {
        "address": domain_ip,
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "domain": domain_data,
        "location": ip_data,
        "whois": whois_data,
        "headers": request_headers,
    }
    return response_data


if __name__ == "__main__":
    # start the scheduler
    uvicorn.run(app, host="0.0.0.0", port=8000)
