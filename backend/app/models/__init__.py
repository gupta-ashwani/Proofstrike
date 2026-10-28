"""
Import all models so SQLAlchemy's Base.metadata knows about them.
"""

from app.models.target import Target
from app.models.scan import Scan
from app.models.endpoint import Endpoint
from app.models.finding import Finding
from app.models.evidence import Evidence
from app.models.scan_diff import ScanDiff

__all__ = ["Target", "Scan", "Endpoint", "Finding", "Evidence", "ScanDiff"]
