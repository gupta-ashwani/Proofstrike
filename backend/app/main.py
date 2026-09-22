"""
ProofStrike — FastAPI application entry point.

Registers all routers, sets up CORS, and initializes the database on startup.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db

# Import models so Base.metadata knows about all tables
import app.models  # noqa: F401

from app.routers import targets, scans, findings, dashboard, reports, crawler


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: create DB tables. Shutdown: cleanup."""
    await init_db()
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
