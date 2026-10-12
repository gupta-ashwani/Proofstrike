"""
Verify stage — confirm or reject candidate findings.

For XSS: render each candidate in a real browser and confirm the payload
executes. Confirmed findings get a screenshot + DOM proof and keep their
severity; candidates that don't execute are rejected (false-positive control).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sqlalchemy import select

from app.engine.crawler.browser import BrowserManager
from app.engine.detect.base import EndpointProbe
from app.engine.detect.stored_xss import SINK_EVIDENCE_TYPE
from app.engine.verify.xss_verifier import XssVerifier
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
        if not reflected and not stored:
            ctx.stats.setdefault("confirmed_findings", 0)
            return

        logger.info("Verify stage: %d reflected + %d stored XSS candidate(s)",
                    len(reflected), len(stored))
        confirmed = rejected = unverified = 0

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
                outcome = self._classify(result)
                await self._apply(ctx, finding_id, result, outcome)
                confirmed += outcome == "confirmed"
                rejected += outcome == "rejected"
                unverified += outcome == "unverified"

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
                outcome = self._classify(result)
                await self._apply(ctx, finding_id, result, outcome)
                confirmed += outcome == "confirmed"
                rejected += outcome == "rejected"
                unverified += outcome == "unverified"

        ctx.stats["confirmed_findings"] = confirmed
        ctx.stats["rejected_findings"] = rejected
        ctx.stats["unverified_findings"] = unverified
        logger.info("Verify stage done: %d confirmed, %d rejected, %d unverified",
                    confirmed, rejected, unverified)

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
            finding.description = (
                (finding.description or "")
                + f"\n\nCONFIRMED: the payload executed in a real browser "
                  f"(callback fired). Confirming payload: {result.payload}"
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
