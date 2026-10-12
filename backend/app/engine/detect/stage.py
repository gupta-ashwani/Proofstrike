"""
Detect stage — run the enabled detectors over discovered endpoints and store
candidate findings (status = candidate). Verification happens in the next stage.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from playwright.async_api import async_playwright
from sqlalchemy import select

from app.engine.detect.base import DetectorHttp, EndpointProbe
from app.engine.detect.xss import XssDetector
from app.models.endpoint import Endpoint
from app.models.finding import Finding, FindingStatus
from app.models.evidence import Evidence

if TYPE_CHECKING:
    from app.engine.context import ScanContext

logger = logging.getLogger("proofstrike.detect.stage")

# Detectors implemented so far. (sqli / idor to follow.)
AVAILABLE = {"xss": XssDetector}


async def new_request_context(playwright, storage_state):
    """APIRequestContext that reuses the crawl's authenticated session if present."""
    kwargs = {"ignore_https_errors": True, "timeout": 20_000}
    if not storage_state:
        return await playwright.request.new_context(**kwargs), None
    try:
        return await playwright.request.new_context(storage_state=storage_state, **kwargs), None
    except Exception:
        # Older Playwright wants a file path rather than a dict
        import json
        import os
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(storage_state, f)
        ctx = await playwright.request.new_context(storage_state=path, **kwargs)
        return ctx, path


class DetectStage:
    name = "detect"

    def __init__(self):
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def _stopped(self) -> bool:
        return self._cancelled

    async def run(self, ctx: "ScanContext"):
        ctx.stats["detect_session"] = "authenticated" if ctx.storage_state else "anonymous"

        detectors = [AVAILABLE[name]() for name in ctx.detectors if name in AVAILABLE]
        skipped = [name for name in ctx.detectors if name not in AVAILABLE]
        if skipped:
            logger.info("Detectors not implemented yet, skipped: %s", skipped)
        if not detectors:
            logger.info("Detect stage: no implemented detectors selected")
            ctx.stats.setdefault("candidates_found", 0)
            return

        probes = await self._load_probes(ctx)
        logger.info("Detect stage: %d endpoints to test with %s",
                    len(probes), [d.name for d in detectors])

        candidates_found = 0
        seen: set[tuple[str, str, str]] = set()  # (endpoint_id, param, type)
        temp_path = None

        async with async_playwright() as p:
            request_ctx, temp_path = await new_request_context(p, ctx.storage_state)
            http = DetectorHttp(request_ctx, ctx.limiter)
            try:
                for probe in probes:
                    if self._stopped():
                        break
                    for detector in detectors:
                        if self._stopped():
                            break
                        try:
                            candidates = await detector.detect(probe, http)
                        except Exception as e:
                            logger.debug("Detector %s failed on %s: %s", detector.name, probe.url, e)
                            continue
                        for candidate in candidates:
                            key = (probe.id, candidate.param, candidate.type)
                            if key in seen:
                                continue
                            seen.add(key)
                            await self._store(ctx, probe, candidate)
                            candidates_found += 1
            finally:
                await request_ctx.dispose()
                if temp_path:
                    import os
                    try:
                        os.unlink(temp_path)
                    except OSError:
                        pass

        ctx.stats["candidates_found"] = candidates_found
        logger.info("Detect stage done: %d candidates", candidates_found)

    async def _load_probes(self, ctx: "ScanContext") -> list[EndpointProbe]:
        async with ctx.session_factory() as db:
            rows = (await db.execute(
                select(Endpoint).where(Endpoint.scan_id == ctx.scan_id)
            )).scalars().all()
        probes = []
        for ep in rows:
            if not ep.params:
                continue  # nothing to inject
            if ctx.excluder.is_excluded(ep.url):
                continue
            probes.append(EndpointProbe.from_endpoint(ep))
        return probes

    async def _store(self, ctx: "ScanContext", probe: EndpointProbe, candidate):
        async with ctx.session_factory() as db:
            finding = Finding(
                scan_id=ctx.scan_id,
                endpoint_id=probe.id,
                type=candidate.type,
                severity=candidate.severity,
                status=FindingStatus.CANDIDATE.value,
                title=candidate.title,
                description=candidate.description,
                reproduction_steps=self._reproduction(candidate),
                remediation=candidate.remediation or None,
            )
            db.add(finding)
            await db.flush()
            for etype, content in candidate.evidence:
                db.add(Evidence(finding_id=finding.id, type=etype, content=content))
            await db.commit()

    @staticmethod
    def _reproduction(candidate) -> str:
        return (
            f"1. Send the request below with '{candidate.param}' set to the payload.\n"
            f"2. Observe the payload reflected un-encoded in the HTML response.\n\n"
            f"Payload: {candidate.payload}"
        )
