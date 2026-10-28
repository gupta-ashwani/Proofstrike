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


# ── Differential (scan-to-scan diff) ──

class DiffItem(BaseModel):
    fingerprint: str
    type: str
    severity: str
    title: str
    finding_id: str | None = None


class ScanDiffResponse(BaseModel):
    scan_id: str
    target_id: str
    previous_scan_id: str | None = None
    is_baseline: bool = False
    new_count: int = 0
    fixed_count: int = 0
    unchanged_count: int = 0
    new: list[DiffItem] = []
    fixed: list[DiffItem] = []
    unchanged: list[DiffItem] = []
    created_at: datetime
