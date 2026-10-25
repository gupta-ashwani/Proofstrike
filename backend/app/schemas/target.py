"""
Pydantic schemas for Target — request/response validation.
"""

from urllib.parse import urlparse

from pydantic import BaseModel, field_validator
from datetime import datetime


def _validate_base_url(value: str) -> str:
    """A target base_url must be an absolute http(s) URL with a host."""
    if not isinstance(value, str):
        raise ValueError("base_url must be a string")
    cleaned = value.strip()
    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("base_url must start with http:// or https://")
    if not parsed.netloc:
        raise ValueError("base_url must include a host, e.g. https://app.example.com")
    return cleaned


# ── Request schemas ──

class TargetCreate(BaseModel):
    name: str
    base_url: str
    auth_config: dict | None = None

    @field_validator("base_url")
    @classmethod
    def _check_base_url(cls, v: str) -> str:
        return _validate_base_url(v)


class TargetUpdate(BaseModel):
    name: str | None = None
    base_url: str | None = None
    auth_config: dict | None = None

    @field_validator("base_url")
    @classmethod
    def _check_base_url(cls, v):
        return _validate_base_url(v) if v is not None else v


# Smallest interval the scheduler accepts, to avoid hammering a target.
MIN_SCAN_INTERVAL_MINUTES = 5


class ScheduleUpdate(BaseModel):
    """Configure (or turn off) continuous scanning for a target."""
    enabled: bool
    # Required when enabling (unless the target already has an interval saved).
    interval_minutes: int | None = None
    # Scan.config each scheduled run uses (detectors, crawl limits). Omit to keep
    # the target's current schedule_config; send null to clear it (engine defaults).
    config: dict | None = None

    @field_validator("interval_minutes")
    @classmethod
    def _check_interval(cls, v):
        if v is not None and v < MIN_SCAN_INTERVAL_MINUTES:
            raise ValueError(
                f"interval_minutes must be at least {MIN_SCAN_INTERVAL_MINUTES}"
            )
        return v


# ── Response schemas ──

class TargetResponse(BaseModel):
    id: str
    name: str
    base_url: str
    auth_config: dict | None = None
    created_at: datetime
    updated_at: datetime
    scan_count: int = 0

    # Continuous-scan schedule
    schedule_enabled: bool = False
    scan_interval_minutes: int | None = None
    schedule_config: dict | None = None
    last_scheduled_scan_at: datetime | None = None
    next_scan_at: datetime | None = None

    model_config = {"from_attributes": True}


class TargetListResponse(BaseModel):
    targets: list[TargetResponse]
    total: int
