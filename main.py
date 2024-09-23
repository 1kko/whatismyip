#!/usr/bin/env python3

import datetime
import logging
import socket
from logging.handlers import TimedRotatingFileHandler

import uvicorn
import whois  # whoisdomain for WHOIS lookups
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import ORJSONResponse
from geoip2fast import GeoIP2Fast
from pydantic import BaseModel

app = FastAPI()

# GEOIP2Fast instance for GeoIP lookups
GEOIP = GeoIP2Fast()

# Configure logging
log_formatter = logging.Formatter(
    '%(asctime)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(log_formatter)
logger.addHandler(console_handler)

# File handler with rotation every 1 days, keeping 7 days of logs
file_handler = TimedRotatingFileHandler(
    'service.log', when='D', interval=1, backupCount=7)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(log_formatter)
logger.addHandler(file_handler)


# Define the Pydantic model for the response
class WhoisResponse(BaseModel):
    ip_address: str
    datetime: datetime.datetime
    location: dict
    whois: dict
    headers: dict

    class Config:
        json_schema_extra = {
            "example": {
                "ip_address": "8.8.8.8",
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
                    "referral_url": None,
                    "updated_date": "2020-09-09 09:21:45",
                    "creation_date": "1997-09-15 04:00:00",
                    "expiration_date": "2028-09-14 04:00:00",
                    "name_servers": [
                        "NS1.GOOGLE.COM",
                        "NS2.GOOGLE.COM",
                        "NS3.GOOGLE.COM",
                        "NS4.GOOGLE.COM"
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
                    "country": "US"
                }
            }
        }


# Function to fetch ip location data
def fetch_ip_location(ip: str):
    # return whois.whois(ip)
    return GEOIP.lookup(ip).to_dict()


# GeoIP2Fast database update
def update_geoip2fast():
    update_result = GEOIP.update_all(verbose=False)
    reload_result = GEOIP.reload_data(verbose=False)
    logging.info(f"{update_result=}")
    logging.info(f"{reload_result=}")


# Create a BackgroundScheduler instance
scheduler = BackgroundScheduler()
# Schedule the GeoIP2Fast database update to run every 24 hours
scheduler.add_job(update_geoip2fast, "interval", days=3)
# Start the scheduler
scheduler.start()

# run only once to update_geoip2fast function on startup
update_geoip2fast()


@app.get("/", response_model=WhoisResponse, response_class=ORJSONResponse)
async def get_ip_info(request: Request):
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
    ip_data.pop('elapsed_time', None)

    # Return the IP info and WHOIS data as JSON
    response_data = {
        "ip_address": client_ip,
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "location": ip_data,
        "whois": whois_data,
        "headers": request_headers,
    }
    return response_data


@app.get("/{domain_ip}", response_model=WhoisResponse, response_class=ORJSONResponse)
async def get_ip_info(domain_ip: str, request: Request):
    # Extract request headers
    request_headers = dict(request.headers)
    # this is considered runnint in a reverse proxy
    client_ip = request_headers.get("x-real-ip", request.client.host)
    logging.info(f"client={client_ip} lookup={domain_ip}")

    # Check if the input is a domain or an IP address
    if any(c.isalpha() for c in domain_ip):
        # It's a domain, resolve it to an IP address
        try:
            resolved_ip = socket.gethostbyname(domain_ip)
        except socket.gaierror as e:
            raise HTTPException(
                status_code=400, detail=f"Invalid domain: {domain_ip}")
    else:
        # It's an IP address
        resolved_ip = domain_ip

    # Get the client's IP address

    # Perform a WHOIS lookup for the client's IP address or domain
    try:
        whois_data = whois.whois(domain_ip)
    except Exception as e:
        whois_data = {"error": str(e)}

    # Await the result of the IP location task
    ip_data = fetch_ip_location(resolved_ip)
    # remove elapsed_time
    ip_data.pop('elapsed_time', None)

    # Return the IP info and WHOIS data as JSON
    response_data = {
        "ip_address": domain_ip,
        "datetime": datetime.datetime.now(tz=datetime.timezone.utc),
        "location": ip_data,
        "whois": whois_data,
        "headers": request_headers,
    }
    return response_data

if __name__ == "__main__":
    # start the scheduler
    uvicorn.run(app, host="0.0.0.0", port=8000)
