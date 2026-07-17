"""Pydantic request/response models."""

import datetime

from pydantic import BaseModel


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


class GeoRulesUpdate(BaseModel):
    model_config = {"extra": "forbid"}

    mode: str | None = None
    blocked_countries: list[str] | None = None
    allowed_countries: list[str] | None = None
    blocked_regions: list[str] | None = None
    allowed_regions: list[str] | None = None
    block_unknown: bool | None = None
    bypass_ips: list[str] | None = None
