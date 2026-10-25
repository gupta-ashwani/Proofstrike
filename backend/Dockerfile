# syntax=docker/dockerfile:1
#
# ProofStrike backend — FastAPI + the scan engine (Playwright/Chromium).
# Runs the API server by default; override the command to run the CLI instead:
#   docker run --rm -v ps-data:/data proofstrike-backend \
#       python -m proofstrike scan https://target.example --fail-on high --report-dir /data/reports

FROM python:3.13-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Persist scan data (DB, reports, evidence) under a single mounted volume.
    DATABASE_URL=sqlite+aiosqlite:////data/proofstrike.db \
    REPORT_DIR=/data/reports \
    EVIDENCE_DIR=/data/evidence \
    # Chromium runs as root in the container — launch it with --no-sandbox.
    PROOFSTRIKE_BROWSER_NO_SANDBOX=1

WORKDIR /app

# 1) Python deps first so the layer caches across code changes.
# 2) Then the Chromium browser + the OS libraries it needs (--with-deps handles apt).
COPY requirements.txt ./
RUN pip install -r requirements.txt \
    && python -m playwright install --with-deps chromium

# Application code (see .dockerignore for what is excluded).
COPY . /app/

RUN mkdir -p /data/reports /data/evidence
VOLUME ["/data"]

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
