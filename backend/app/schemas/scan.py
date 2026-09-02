"""
Pydantic schemas for Scan — request/response validation.
"""

from pydantic import BaseModel
from datetime import datetime


# ── Request schemas ──

class ScanCreate(BaseModel):
    target_id: str
    config: dict | None = None


# ── Response schemas ──

class ScanResponse(BaseModel):
    id: str
    target_id: str
    status: str
    config: dict | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    stats: dict | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]
    total: int


class ScanProgress(BaseModel):
    id: str
    status: str
    endpoints_found: int = 0
    findings_count: int = 0
    elapsed_seconds: float | None = None
