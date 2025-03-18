#!/usr/bin/env python3

import datetime
import ipaddress
import json
import logging
import re
import socket
import ssl
from logging.handlers import TimedRotatingFileHandler
from typing import Any, Dict

import dns.resolver
import dns.reversename
import uvicorn
import whois
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request
from fastapi.responses import ORJSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from geoip2fast import GeoIP2Fast
from pydantic import BaseModel
from tld import exceptions as tld_exceptions
from tld import get_tld

# First, mount static files
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

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

TIMEOUT_SECONDS = 5


class WhoisResponse(BaseModel):
    address: str
    datetime: datetime.datetime
    domain: dict
    location: dict
    whois: dict
    ssl: dict | None
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


class GeoIpManager:
    def __init__(self):
        self.instance = GeoIP2Fast()

    def update_database(self):
        try:
            update_result = self.instance.update_file(
                "geoip2fast-city-asn-ipv6.dat.gz", "geoip2fast.dat.gz", verbose=False
            )
            reload_result = self.instance.reload_data(verbose=False)
            logging.info(f"{update_result=}")
            logging.info(f"{reload_result=}")
        except Exception as e:
            logging.exception(f"Error updating GeoIP2Fast database: {str(e)}")

    def fetch_location(self, ip: str) -> Dict[str, Any]:
        return self.instance.lookup(ip).to_dict()


class DomainManager:
    def is_ipv4(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).version == 4
        except ValueError:
            return False

    def is_valid_domain(self, domain) -> bool:
        try:
            get_tld(domain, fix_protocol=True)
            return True
        except tld_exceptions.TldDomainNotFound:
            return False

    def get_records(self, domain: str, ns_servers: list = None) -> dict:
        records = {"mx": [], "ns": [], "cname": None, "txt": [], "a": []}
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = dns.resolver.get_default_resolver().nameservers
            for ns in ns_servers or []:
                server = (
                    ns if self.is_ipv4(ns) else str(dns.resolver.resolve(ns, "A")[0])
                )
                resolver.nameservers.append(server)

            # Get A records
            try:
                a_records = resolver.resolve(domain, "A")
                for r in a_records:
                    records["a"].append({"ip": str(r), "ttl": a_records.rrset.ttl})
            except dns.resolver.NoAnswer:
                pass

            mx_records = resolver.resolve(domain, "MX")
            for r in mx_records:
                mx_ip = str(resolver.resolve(str(r.exchange), "A")[0])
                records["mx"].append({
                    "hostname": r.exchange.to_text(),
                    "ttl": mx_records.rrset.ttl,
                    "ip": mx_ip,
                })

            ns_records = resolver.resolve(domain, "NS")
            for r in ns_records:
                ns_ip = str(resolver.resolve(str(r.target), "A")[0])
                records["ns"].append({
                    "hostname": r.target.to_text(),
                    "ttl": ns_records.rrset.ttl,
                    "ip": ns_ip,
                })

            try:
                cname_record = resolver.resolve(domain, "CNAME")
                records["cname"] = {
                    "cname": cname_record.rrset[0].target.to_text(),
                    "ttl": cname_record.rrset.ttl,
                }
            except dns.resolver.NoAnswer:
                records["cname"] = None

            txt_records = resolver.resolve(domain, "TXT")
            for r in txt_records:
                records["txt"].append({"text": r.strings, "ttl": txt_records.rrset.ttl})

        except Exception as e:
            logging.error(f"Error retrieving DNS records for {domain}: {str(e)}")

        return records

    def perform_reverse_lookup(self, ip: str) -> str:
        try:
            reverse_name = dns.reversename.from_address(ip)
            return str(
                dns.resolver.resolve(reverse_name, "PTR")[0], lifetime=TIMEOUT_SECONDS
            )
        except Exception as e:
            logging.error(f"Error performing reverse lookup for IP {ip}: {str(e)}")
            return None


class SSLManager:
    @staticmethod
    def get_ssl_info(hostname: str) -> dict | None:
        cert = None
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(TIMEOUT_SECONDS)
                s.connect((hostname, 443))
                cert = s.getpeercert()
            return cert
        except Exception as e:
            logging.exception(
                f"Error performing SSL certificate lookup for hostname: {str(hostname)}"
            )
            return None


class HeaderManager:
    @staticmethod
    def filter_out_unwanted(original_headers: dict, exclude_prefixes: list) -> dict:
        return {
            k: v
            for k, v in original_headers.items()
            if not any(k.lower().startswith(prefix) for prefix in exclude_prefixes)
        }


geo_ip_manager = GeoIpManager()
domain_manager = DomainManager()

scheduler = BackgroundScheduler()
scheduler.add_job(geo_ip_manager.update_database, "interval", days=3)
scheduler.start()
geo_ip_manager.update_database()


class BrowserDetector:
    @staticmethod
    def is_browser(user_agent: str) -> bool:
        browser_patterns = [
            r"Mozilla",
            r"Chrome",
            r"Safari",
            r"Firefox",
            r"Edge",
            r"Opera",
        ]
        return any(
            re.search(pattern, user_agent, re.IGNORECASE)
            for pattern in browser_patterns
        )


@app.get("/", response_model=None)
async def get_self_info(request: Request):
    filter_manager = HeaderManager()
    request_headers = filter_manager.filter_out_unwanted(
        dict(request.headers), ["x-forwarded-", "x-real-ip"]
    )
    client_ip = request.headers.get("x-real-ip", request.client.host)
    logging.info(f"client={client_ip} lookup={client_ip} (self)")

    try:
        whois_data = whois.whois(client_ip)
    except Exception as e:
        whois_data = {"error": str(e)}

    ip_data = geo_ip_manager.fetch_location(client_ip)
    ip_data.pop("elapsed_time", None)

    domain = domain_manager.perform_reverse_lookup(client_ip)

    response_data = {
        "address": client_ip,
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "domain": domain_manager.get_records(domain) if domain else {},
        "location": ip_data,
        "whois": whois_data,
        "ssl": None,
        "headers": request_headers,
    }

    user_agent = request.headers.get("user-agent", "")
    if BrowserDetector.is_browser(user_agent):
        return templates.TemplateResponse(
            "browser.html",
            {
                "request": request,
                "json_data": json.dumps(response_data, indent=2, default=str),
            },
        )

    return ORJSONResponse(response_data)


@app.get("/{domain_ip}", response_model=None)
async def get_ip_info(domain_ip: str, request: Request):
    # Remove the static path check since it's handled by the static files mount
    filter_manager = HeaderManager()
    request_headers = filter_manager.filter_out_unwanted(
        dict(request.headers), ["x-forwarded-", "x-real-ip"]
    )
    request_headers.pop("host", None)

    client_ip = request.headers.get("x-real-ip", request.client.host)
    logging.info(f"client={client_ip} lookup={domain_ip}")

    try:
        whois_data = whois.whois(domain_ip)
    except Exception as e:
        whois_data = {"error": str(e)}

    ssl_data = None
    resolved_ip = None
    domain_data = None

    if domain_manager.is_valid_domain(domain_ip):
        logging.debug(f"domain={domain_ip}")
        try:
            a_records = dns.resolver.resolve(domain_ip, "A")
            resolved_ip = str(a_records[0])  # Get the first A record
        except Exception as e:
            logging.exception(f"Error resolving domain {domain_ip}: {str(e)}")
        domain_data = domain_manager.get_records(domain_ip)
        ssl_data = SSLManager.get_ssl_info(domain_ip)
    elif domain_manager.is_ipv4(domain_ip):
        logging.debug(f"ip={domain_ip}")
        domain = domain_manager.perform_reverse_lookup(domain_ip)
        domain_data = domain_manager.get_records(domain) if domain else {}
        resolved_ip = domain_ip

    if resolved_ip:
        ip_data = geo_ip_manager.fetch_location(resolved_ip)
        ip_data.pop("elapsed_time", None)
    else:
        ip_data = {}

    response_data = {
        "address": domain_ip,
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "domain": domain_data,
        "location": ip_data,
        "whois": whois_data,
        "ssl": ssl_data,
        "headers": request_headers,
    }

    user_agent = request.headers.get("user-agent", "")
    if BrowserDetector.is_browser(user_agent):
        return templates.TemplateResponse(
            "browser.html",
            {
                "request": request,
                "json_data": json.dumps(response_data, indent=2, default=str),
            },
        )

    return ORJSONResponse(response_data)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
