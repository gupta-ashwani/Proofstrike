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


# ── Response schemas ──

class TargetResponse(BaseModel):
    id: str
    name: str
    base_url: str
    auth_config: dict | None = None
    created_at: datetime
    updated_at: datetime
    scan_count: int = 0

    model_config = {"from_attributes": True}


class TargetListResponse(BaseModel):
    targets: list[TargetResponse]
    total: int
