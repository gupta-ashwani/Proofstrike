"""
Pydantic schemas for Finding — request/response validation.
"""

from pydantic import BaseModel
from datetime import datetime


# ── Request schemas ──

class FindingUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None


# ── Response schemas ──

class EvidenceResponse(BaseModel):
    id: str
    type: str
    content: str | None = None
    file_path: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    endpoint_id: str | None = None
    type: str
    severity: str
    status: str
    title: str
    description: str | None = None
    reproduction_steps: str | None = None
    remediation: str | None = None
    created_at: datetime
    evidence_items: list[EvidenceResponse] = []

    model_config = {"from_attributes": True}


class FindingListResponse(BaseModel):
    findings: list[FindingResponse]
    total: int


class EndpointResponse(BaseModel):
    id: str
    scan_id: str
    url: str
    method: str
    params: dict | None = None
    auth_required: bool
    source: str
    created_at: datetime

    model_config = {"from_attributes": True}


class EndpointListResponse(BaseModel):
    endpoints: list[EndpointResponse]
    total: int
