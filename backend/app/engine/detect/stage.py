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
from app.engine.detect.sqli import SqliDetector
from app.engine.detect.idor import IdorDetector, CrossSessionIdorDetector, AccessControlDetector
from app.engine.detect.passive import PassiveScanner
from app.engine.detect.csrf import CsrfScanner
from app.engine.detect.stored_xss import StoredXssDetector
from app.engine.detect.stored_sqli import StoredSqliDetector
from app.models.endpoint import Endpoint
from app.models.finding import Finding, FindingStatus
from app.models.evidence import Evidence

if TYPE_CHECKING:
    from app.engine.context import ScanContext

logger = logging.getLogger("proofstrike.detect.stage")

# Per-probe detectors. (Others run as batch passes: stored XSS under "xss",
# cross-session/access-control under "idor", and "passive".)
AVAILABLE = {"xss": XssDetector, "sqli": SqliDetector, "idor": IdorDetector}
_BATCH_ONLY = {"passive", "csrf"}  # selected names handled by a batch pass, not a per-probe detector


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
        skipped = [n for n in ctx.detectors if n not in AVAILABLE and n not in _BATCH_ONLY]
        if skipped:
            logger.info("Detectors not implemented yet, skipped: %s", skipped)
        run_passive = "passive" in ctx.detectors
        run_csrf = "csrf" in ctx.detectors
        if not detectors and not run_passive and not run_csrf:
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

                # Stored XSS is cross-endpoint (inject at A, surfaces at B), so it runs
                # as a batch pass over all probes + sink pages once XSS is enabled.
                if "xss" in ctx.detectors and not self._stopped():
                    sink_urls = await self._load_sink_urls(ctx)
                    try:
                        pairs = await StoredXssDetector().detect_all(probes, sink_urls, http)
                    except Exception as e:
                        logger.debug("Stored XSS detector failed: %s", e)
                        pairs = []
                    for probe, candidate in pairs:
                        key = (probe.id, candidate.param, candidate.type)
                        if key in seen:
                            continue
                        seen.add(key)
                        await self._store(ctx, probe, candidate)
                        candidates_found += 1

                # Second-order (stored) SQLi: seed writable params, harvest sinks for a
                # late DB error (cross-endpoint, like stored XSS).
                if "sqli" in ctx.detectors and not self._stopped():
                    so_sinks = await self._load_sink_urls(ctx)
                    try:
                        pairs = await StoredSqliDetector().detect_all(probes, so_sinks, http)
                    except Exception as e:
                        logger.debug("Stored SQLi detector failed: %s", e)
                        pairs = []
                    for probe, candidate in pairs:
                        # Keyed with the technique so a second-order finding is not shadowed
                        # by a first-order SQLi candidate on the same (endpoint, param): the
                        # per-probe pass can see this sink's error by following a redirect.
                        key = (probe.id, candidate.param, candidate.type, candidate.technique)
                        if key in seen:
                            continue
                        seen.add(key)
                        await self._store(ctx, probe, candidate)
                        candidates_found += 1

                # Session-based access control (needs an authenticated crawl session):
                #   - cross-session IDOR   (object owned by A, read by user B)
                #   - unauthenticated access (protected endpoint read with no session)
                #   - privilege escalation (privileged endpoint read by a lower user)
                if "idor" in ctx.detectors and ctx.storage_state and not self._stopped():
                    ctx_anon = ctx_b = None
                    http_b = None
                    temps: list[str] = []
                    access_pairs = []
                    try:
                        anon_ctx, temp_anon = await new_request_context(p, None)
                        ctx_anon = anon_ctx
                        if temp_anon:
                            temps.append(temp_anon)
                        http_anon = DetectorHttp(ctx_anon, ctx.limiter)
                        if ctx.storage_state_b:
                            ctx_b, temp_b = await new_request_context(p, ctx.storage_state_b)
                            if temp_b:
                                temps.append(temp_b)
                            http_b = DetectorHttp(ctx_b, ctx.limiter)
                            access_pairs += await CrossSessionIdorDetector().detect_all(
                                probes, http, http_b)
                        access_pairs += await AccessControlDetector().detect_all(
                            probes, http, http_anon, http_b)
                    except Exception as e:
                        logger.debug("Access-control detectors failed: %s", e)
                        access_pairs = []
                    finally:
                        if ctx_anon is not None:
                            await ctx_anon.dispose()
                        if ctx_b is not None:
                            await ctx_b.dispose()
                        for t in temps:
                            import os
                            try:
                                os.unlink(t)
                            except OSError:
                                pass
                    for probe, candidate in access_pairs:
                        key = (probe.id, candidate.param, candidate.type)
                        if key in seen:
                            continue
                        seen.add(key)
                        await self._store(ctx, probe, candidate)
                        candidates_found += 1

                # Passive checks: security headers, cookie flags, info disclosure,
                # open redirect — read off normal responses. These are page-level, so
                # they run over ALL discovered pages (base URL + every GET page), not
                # just the injectable endpoints the active detectors use.
                if run_passive and not self._stopped():
                    passive_probes = await self._load_passive_probes(ctx, probes)
                    try:
                        pairs = await PassiveScanner().scan_all(passive_probes, http)
                    except Exception as e:
                        logger.debug("Passive scanner failed: %s", e)
                        pairs = []
                    for probe, candidate in pairs:
                        key = (probe.id, candidate.param, candidate.type)
                        if key in seen:
                            continue
                        seen.add(key)
                        await self._store(ctx, probe, candidate)
                        candidates_found += 1

                # CSRF: state-changing endpoints with no token + no SameSite (sync, uses
                # the captured session's cookies to know whether SameSite already protects).
                if run_csrf and not self._stopped():
                    try:
                        pairs = CsrfScanner().scan(probes, ctx.storage_state)
                    except Exception as e:
                        logger.debug("CSRF scanner failed: %s", e)
                        pairs = []
                    for probe, candidate in pairs:
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

    async def _load_passive_probes(
        self, ctx: "ScanContext", injectable: list[EndpointProbe]
    ) -> list[EndpointProbe]:
        """
        Pages for the passive scanner: the base URL + every discovered GET page, plus
        the injectable probes (so open-redirect still covers param endpoints). Header /
        cookie / info-disclosure checks are page-level and must not be limited to
        endpoints that happen to carry a parameter — otherwise a site's landing and
        authenticated pages (often param-less) are never header-checked.
        """
        probes: list[EndpointProbe] = []
        seen_urls: set[str] = set()

        # Base URL first, so a shared issue (e.g. missing CSP) attaches to the root page.
        if ctx.base_url and not ctx.excluder.is_excluded(ctx.base_url):
            probes.append(EndpointProbe(id=None, url=ctx.base_url, method="GET", baseline={}))
            seen_urls.add(ctx.base_url)

        # Injectable probes keep open-redirect coverage (they carry params).
        for p in injectable:
            if p.url not in seen_urls:
                probes.append(p)
                seen_urls.add(p.url)

        # Every other GET page (including param-less ones the active pass skips).
        async with ctx.session_factory() as db:
            rows = (await db.execute(
                select(Endpoint).where(Endpoint.scan_id == ctx.scan_id)
            )).scalars().all()
        for ep in rows:
            if (ep.method or "GET").upper() != "GET":
                continue
            if ep.url in seen_urls or ctx.excluder.is_excluded(ep.url):
                continue
            seen_urls.add(ep.url)
            probes.append(EndpointProbe.from_endpoint(ep))
        return probes

    async def _load_sink_urls(self, ctx: "ScanContext") -> list[str]:
        """
        Pages where stored content might surface: every discovered GET URL plus the
        base URL. Deduped, excluding logout/destructive routes.
        """
        urls: list[str] = []
        seen: set[str] = set()

        def add(u: str):
            if u and u not in seen and not ctx.excluder.is_excluded(u):
                seen.add(u)
                urls.append(u)

        add(ctx.base_url)
        async with ctx.session_factory() as db:
            rows = (await db.execute(
                select(Endpoint).where(Endpoint.scan_id == ctx.scan_id)
            )).scalars().all()
        for ep in rows:
            if (ep.method or "GET").upper() == "GET":
                add(ep.url)
        return urls

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
        if candidate.type == "stored_xss":
            sink = next((c for t, c in candidate.evidence if t == "stored_sink"), "another page")
            return (
                f"1. Send the request below with '{candidate.param}' set to the payload.\n"
                f"2. Open {sink} and observe the payload rendered un-encoded (it was stored).\n\n"
                f"Payload: {candidate.payload}"
            )
        if candidate.type == "csrf":
            return (
                "1. From a different origin, auto-submit the request below to a logged-in "
                "victim (no anti-CSRF token is required).\n"
                "2. Observe the state change is performed on the victim's behalf.\n\n"
                f"Request: {candidate.title}"
            )
        if candidate.type == "auth_bypass":
            return (
                "1. Send the request below WITHOUT a valid session (log out / use a fresh "
                "browser), or as a lower-privilege user.\n"
                "2. Observe the protected content is returned anyway — the server performs "
                "no authentication/authorization check for this endpoint.\n\n"
                f"Technique: {candidate.technique}"
            )
        if candidate.type == "idor":
            return (
                f"1. Send the request with '{candidate.param}' set to its baseline id, note the record.\n"
                f"2. Change '{candidate.param}' to the neighbouring id '{candidate.payload}' and observe a "
                f"different, valid record returned (no authorisation check).\n"
                f"3. Change it to a far out-of-range id and observe it is rejected — confirming the "
                f"parameter indexes records directly.\n\n"
                f"Neighbouring id: {candidate.payload}"
            )
        return (
            f"1. Send the request below with '{candidate.param}' set to the payload.\n"
            f"2. Observe the payload reflected un-encoded in the HTML response.\n\n"
            f"Payload: {candidate.payload}"
        )
