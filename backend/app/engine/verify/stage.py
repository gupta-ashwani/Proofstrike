"""
Verify stage — confirm or reject candidate findings.

For XSS: render each candidate in a real browser and confirm the payload
executes. Confirmed findings get a screenshot + DOM proof and keep their
severity; candidates that don't execute are rejected (false-positive control).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from playwright.async_api import async_playwright
from sqlalchemy import select

from app.engine.crawler.browser import BrowserManager
from app.engine.detect.base import DetectorHttp, EndpointProbe
from app.engine.detect.stage import new_request_context
from app.engine.detect.stored_xss import SINK_EVIDENCE_TYPE
from app.engine.verify.xss_verifier import XssVerifier
from app.engine.verify.sqli_verifier import SqliVerifier
from app.engine.verify.idor_verifier import IdorVerifier
from app.models.endpoint import Endpoint
from app.models.finding import Finding, FindingStatus
from app.models.evidence import Evidence

if TYPE_CHECKING:
    from app.engine.context import ScanContext

logger = logging.getLogger("proofstrike.verify.stage")


class VerifyStage:
    name = "verify"

    def __init__(self):
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def _stopped(self) -> bool:
        return self._cancelled

    async def run(self, ctx: "ScanContext"):
        reflected = await self._load_candidates(ctx, "xss")
        stored = await self._load_stored_candidates(ctx)
        sqli = await self._load_candidates(ctx, "sqli")
        idor = await self._load_candidates(ctx, "idor")
        if not reflected and not stored and not sqli and not idor:
            ctx.stats.setdefault("confirmed_findings", 0)
            return

        logger.info("Verify stage: %d reflected + %d stored XSS + %d SQLi + %d IDOR candidate(s)",
                    len(reflected), len(stored), len(sqli), len(idor))
        self._counts = {"confirmed": 0, "rejected": 0, "unverified": 0}

        if reflected or stored:
            await self._verify_xss(ctx, reflected, stored)
        if (sqli or idor) and not self._stopped():
            await self._verify_http(ctx, sqli, idor)

        confirmed = self._counts["confirmed"]
        rejected = self._counts["rejected"]
        unverified = self._counts["unverified"]
        ctx.stats["confirmed_findings"] = confirmed
        ctx.stats["rejected_findings"] = rejected
        ctx.stats["unverified_findings"] = unverified
        logger.info("Verify stage done: %d confirmed, %d rejected, %d unverified",
                    confirmed, rejected, unverified)

    async def _verify_xss(self, ctx: "ScanContext", reflected, stored):
        async with BrowserManager(headless=ctx.headless, storage_state=ctx.storage_state) as browser:
            page = await browser.new_page()
            page.on("dialog", lambda d: d.dismiss())  # don't block on any alert()
            fired: list[str] = []
            await page.expose_function("__psxss", lambda t: fired.append(t))
            verifier = XssVerifier()

            for finding_id, endpoint, param in reflected:
                if self._stopped():
                    break
                if ctx.excluder.is_excluded(endpoint.url):
                    continue
                probe = EndpointProbe.from_endpoint(endpoint)
                # Use the parsed param if valid, else fall back to trying each param.
                params_to_try = [param] if param in probe.baseline else probe.testable_params
                result = None
                for candidate_param in params_to_try:
                    result = await verifier.verify(
                        page, fired, probe, candidate_param, ctx.limiter, allow_post=ctx.verify_post
                    )
                    if result.confirmed:
                        break
                await self._record(ctx, finding_id, result)

            for finding_id, endpoint, param, sink_url in stored:
                if self._stopped():
                    break
                if ctx.excluder.is_excluded(endpoint.url) or ctx.excluder.is_excluded(sink_url):
                    continue
                probe = EndpointProbe.from_endpoint(endpoint)
                params_to_try = [param] if param in probe.baseline else probe.testable_params
                result = None
                for candidate_param in params_to_try:
                    result = await verifier.verify_stored(
                        page, fired, probe, candidate_param, sink_url, ctx.limiter,
                        allow_post=ctx.verify_post,
                    )
                    if result.confirmed:
                        break
                await self._record(ctx, finding_id, result)

    async def _verify_http(self, ctx: "ScanContext", sqli, idor):
        """SQLi and IDOR are pure-HTTP checks — verify over one APIRequestContext, no browser."""
        temps: list[str] = []
        async with async_playwright() as p:
            request_ctx, temp_path = await new_request_context(p, ctx.storage_state)
            if temp_path:
                temps.append(temp_path)
            http = DetectorHttp(request_ctx, ctx.limiter)

            # A second user's session enables cross-session (two-user) IDOR proof.
            http_b = None
            ctx_b = None
            if ctx.storage_state_b:
                ctx_b, temp_b = await new_request_context(p, ctx.storage_state_b)
                if temp_b:
                    temps.append(temp_b)
                http_b = DetectorHttp(ctx_b, ctx.limiter)

            try:
                await self._verify_with(ctx, http, sqli, SqliVerifier())
                if not self._stopped():
                    await self._verify_with(ctx, http, idor, IdorVerifier(), http_b=http_b)
            finally:
                await request_ctx.dispose()
                if ctx_b is not None:
                    await ctx_b.dispose()
                for t in temps:
                    import os
                    try:
                        os.unlink(t)
                    except OSError:
                        pass

    async def _verify_with(self, ctx: "ScanContext", http, items, verifier, http_b=None):
        """Run one HTTP verifier over its candidates (shared by SQLi and IDOR)."""
        extra = {"http_b": http_b} if http_b is not None else {}
        for finding_id, endpoint, param in items:
            if self._stopped():
                break
            if ctx.excluder.is_excluded(endpoint.url):
                continue
            probe = EndpointProbe.from_endpoint(endpoint)
            params_to_try = [param] if param in probe.baseline else probe.testable_params
            result = None
            for candidate_param in params_to_try:
                result = await verifier.verify(http, probe, candidate_param, **extra)
                if result.confirmed:
                    break
            await self._record(ctx, finding_id, result)

    async def _record(self, ctx: "ScanContext", finding_id: str, result):
        outcome = self._classify(result)
        await self._apply(ctx, finding_id, result, outcome)
        self._counts[outcome] += 1

    @staticmethod
    def _classify(result) -> str:
        if result and result.confirmed:
            return "confirmed"
        if result and not result.attempted:
            # Could not actually run the check — keep as a candidate, don't reject
            return "unverified"
        return "rejected"

    async def _apply(self, ctx: "ScanContext", finding_id: str, result, outcome: str):
        if outcome == "confirmed":
            await self._confirm(ctx, finding_id, result)
        elif outcome == "unverified":
            await self._leave_candidate(ctx, finding_id, result.note if result else "")
        else:
            await self._reject(ctx, finding_id, result)

    async def _load_candidates(self, ctx: "ScanContext", ftype: str):
        """Return (finding_id, endpoint, param) for each candidate of this type."""
        out = []
        async with ctx.session_factory() as db:
            findings = (await db.execute(
                select(Finding).where(
                    Finding.scan_id == ctx.scan_id,
                    Finding.status == FindingStatus.CANDIDATE.value,
                    Finding.type == ftype,
                )
            )).scalars().all()
            for f in findings:
                if not f.endpoint_id:
                    continue
                endpoint = (await db.execute(
                    select(Endpoint).where(Endpoint.id == f.endpoint_id)
                )).scalar_one_or_none()
                if endpoint:
                    out.append((f.id, endpoint, _param_of(f)))
        return out

    async def _load_stored_candidates(self, ctx: "ScanContext"):
        """Return (finding_id, injection_endpoint, param, sink_url) for stored candidates."""
        out = []
        async with ctx.session_factory() as db:
            findings = (await db.execute(
                select(Finding).where(
                    Finding.scan_id == ctx.scan_id,
                    Finding.status == FindingStatus.CANDIDATE.value,
                    Finding.type == "stored_xss",
                )
            )).scalars().all()
            for f in findings:
                if not f.endpoint_id:
                    continue
                endpoint = (await db.execute(
                    select(Endpoint).where(Endpoint.id == f.endpoint_id)
                )).scalar_one_or_none()
                if not endpoint:
                    continue
                sink = (await db.execute(
                    select(Evidence).where(
                        Evidence.finding_id == f.id,
                        Evidence.type == SINK_EVIDENCE_TYPE,
                    )
                )).scalars().first()
                if not sink:
                    continue  # no sink recorded — can't verify
                out.append((f.id, endpoint, _param_of(f), sink.content))
        return out

    async def _confirm(self, ctx: "ScanContext", finding_id: str, result):
        async with ctx.session_factory() as db:
            finding = (await db.execute(select(Finding).where(Finding.id == finding_id))).scalar_one_or_none()
            if not finding:
                return
            finding.status = FindingStatus.CONFIRMED.value
            if finding.type == "sqli":
                proof = ("the database evaluated injected SQL — a TRUE vs FALSE "
                         "condition produced a deterministic, repeatable response split")
            elif finding.type == "idor":
                proof = ("an object was accessed without a valid authorisation check, "
                         "reproduced deterministically on every repeat (see evidence for "
                         "whether this was cross-user access or identifier enumeration)")
            else:
                proof = "the payload executed in a real browser (callback fired)"
            finding.description = (
                (finding.description or "")
                + f"\n\nCONFIRMED: {proof}. Confirming payload: {result.payload}"
            )
            if result.screenshot_b64:
                db.add(Evidence(finding_id=finding_id, type="screenshot", content=result.screenshot_b64))
            if result.dom_snippet:
                db.add(Evidence(finding_id=finding_id, type="dom_snapshot",
                                content=f"...{result.dom_snippet}..."))
            request_desc = result.request_desc or (f"GET {result.url}" if result.url else "")
            if request_desc:
                db.add(Evidence(finding_id=finding_id, type="request", content=request_desc))
            await db.commit()

    async def _leave_candidate(self, ctx: "ScanContext", finding_id: str, note: str):
        """Keep the finding as a candidate (detected, not yet verified) and note why."""
        async with ctx.session_factory() as db:
            finding = (await db.execute(select(Finding).where(Finding.id == finding_id))).scalar_one_or_none()
            if not finding:
                return
            if note:
                finding.description = (finding.description or "") + f"\n\nNOT VERIFIED: {note}."
            await db.commit()

    async def _reject(self, ctx: "ScanContext", finding_id: str, result):
        note = getattr(result, "note", None) or "not verified"
        snippet = getattr(result, "dom_snippet", "") if result else ""
        async with ctx.session_factory() as db:
            finding = (await db.execute(select(Finding).where(Finding.id == finding_id))).scalar_one_or_none()
            if not finding:
                return
            finding.status = FindingStatus.REJECTED.value
            finding.description = (finding.description or "") + f"\n\nREJECTED: {note}."
            if snippet:
                # How the payload was actually reflected — helps diagnose why it didn't execute
                db.add(Evidence(finding_id=finding_id, type="response",
                                content=f"How the payload reflected:\n...{snippet}..."))
            await db.commit()


def _param_of(finding: Finding) -> str:
    """Recover the injected parameter name from the candidate's title ('... in 'x'')."""
    title = finding.title or ""
    if "'" in title:
        parts = title.split("'")
        if len(parts) >= 2:
            return parts[-2]
    return ""
