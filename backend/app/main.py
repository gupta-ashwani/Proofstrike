"""
ProofStrike — FastAPI application entry point.

Registers all routers, sets up CORS, and initializes the database on startup.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.config import settings
from app.database import init_db, async_session

# Import models so Base.metadata knows about all tables
import app.models  # noqa: F401
from app.models.scan import Scan, ScanStatus

from app.routers import targets, scans, findings, dashboard, reports, crawler


async def fail_interrupted_scans():
    """
    Scans run on in-process background threads, so a restart (including a
    --reload) kills them. Mark any scan still "active" as failed so it doesn't
    show as running forever.
    """
    active = [
        ScanStatus.QUEUED.value,
        ScanStatus.CRAWLING.value,
        ScanStatus.TESTING.value,
        ScanStatus.VERIFYING.value,
    ]
    async with async_session() as db:
        result = await db.execute(select(Scan).where(Scan.status.in_(active)))
        for scan in result.scalars():
            scan.status = ScanStatus.FAILED.value
            scan.completed_at = datetime.now(timezone.utc)
            stats = dict(scan.stats or {})
            stats["errors"] = [*stats.get("errors", []), "Interrupted by server restart"]
            scan.stats = stats
        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create DB tables, recover interrupted scans. Shutdown: cleanup."""
    await init_db()
    await fail_interrupted_scans()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Verification-First Continuous Web Security Validation Platform",
    lifespan=lifespan,
)

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register routers ──
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(dashboard.router)
app.include_router(reports.router)
app.include_router(crawler.router)


@app.get("/", tags=["Health"])
async def health_check():
    """Simple health check endpoint."""
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }
