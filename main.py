#!/usr/bin/env python3

from fastapi import FastAPI, Request
import whois  # whoisdomain for WHOIS lookups
import asyncio
from pydantic import BaseModel
import uvicorn

app = FastAPI()

# Define the Pydantic model for the response


class WhoisResponse(BaseModel):
    ip_address: str
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

# Function to fetch location data using aiohttp


async def fetch_ip_location(ip: str):
    return whois.whois(ip)


@app.get("/", response_model=WhoisResponse)
async def get_ip_info(request: Request):
    # Get the client's IP address
    client_ip = request.client.host

    # Extract request headers
    request_headers = dict(request.headers)

    # Create an asyncio task to fetch IP location info
    ip_location_task = asyncio.create_task(fetch_ip_location(client_ip))

    # Perform a WHOIS lookup for the client's IP address or domain
    try:
        whois_data = whois.whois(client_ip)
    except Exception as e:
        whois_data = {"error": str(e)}

    # Await the result of the IP location task
    ip_data = await ip_location_task

    # Return the IP info and WHOIS data as JSON
    return {
        "ip_address": client_ip,
        "location": ip_data,
        "whois": whois_data,
        "headers": request_headers,
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
