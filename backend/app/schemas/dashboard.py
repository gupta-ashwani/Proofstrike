"""
Pydantic schemas for Dashboard — aggregated stats.
"""

from pydantic import BaseModel


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class DashboardStats(BaseModel):
    total_targets: int = 0
    total_scans: int = 0
    active_scans: int = 0
    total_findings: int = 0
    confirmed_findings: int = 0
    severity_breakdown: SeverityBreakdown = SeverityBreakdown()
