"""Pydantic request models."""

from pydantic import BaseModel


class GeoRulesUpdate(BaseModel):
    model_config = {"extra": "forbid"}

    mode: str | None = None
    blocked_countries: list[str] | None = None
    allowed_countries: list[str] | None = None
    blocked_regions: list[str] | None = None
    allowed_regions: list[str] | None = None
    block_unknown: bool | None = None
    bypass_ips: list[str] | None = None
