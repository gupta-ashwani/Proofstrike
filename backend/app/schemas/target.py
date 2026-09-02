"""
Pydantic schemas for Target — request/response validation.
"""

from pydantic import BaseModel, HttpUrl
from datetime import datetime


# ── Request schemas ──

class TargetCreate(BaseModel):
    name: str
    base_url: str
    auth_config: dict | None = None


class TargetUpdate(BaseModel):
    name: str | None = None
    base_url: str | None = None
    auth_config: dict | None = None


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
