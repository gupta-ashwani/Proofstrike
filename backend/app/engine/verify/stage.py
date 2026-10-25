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
from app.engine.verify.passive_verifier import PassiveVerifier
from app.engine.verify.dom_xss import DomXssScanner, dom_xss_finding_fields
from app.engine.verify.csrf_verifier import CsrfVerifier
from app.engine.verify.stored_sqli_verifier import StoredSqliVerifier
from app.engine.detect.idor import (
    idor_oracle,
    path_numeric_segments,
    with_path_segment,
    _neighbors as _idor_neighbors,
    _absent as _idor_absent,
    _MIN_BODY as _IDOR_MIN_BODY,
)
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
        sqli, sqli_second = await self._load_sqli_candidates_split(ctx)
        idor = await self._load_candidates(ctx, "idor")
        authbypass = await self._load_candidates(ctx, "auth_bypass")
        csrf = await self._load_candidates(ctx, "csrf")
        passive = {t: await self._load_candidates(ctx, t)
                   for t in ("security_headers", "insecure_cookie", "info_disclosure", "open_redirect")}
        has_passive = any(passive.values())
        # Path-based IDOR is discovered live over HTTP whenever IDOR is enabled.
        scan_path_idor = "idor" in ctx.detectors
        http_work = (sqli or sqli_second or idor or authbypass or csrf
                     or has_passive or scan_path_idor)
        dom_xss = "xss" in ctx.detectors  # DOM XSS is discovered live in the browser
        if not reflected and not stored and not http_work and not dom_xss:
            ctx.stats.setdefault("confirmed_findings", 0)
            return

        logger.info("Verify stage: %d reflected + %d stored XSS + %d SQLi + %d IDOR + "
                    "%d access-control + %d passive candidate(s); dom-xss=%s",
                    len(reflected), len(stored), len(sqli), len(idor), len(authbypass),
                    sum(len(v) for v in passive.values()), dom_xss)
        self._counts = {"confirmed": 0, "rejected": 0, "unverified": 0}

        if reflected or stored or dom_xss:
            await self._verify_xss(ctx, reflected, stored, dom_xss)
        if http_work and not self._stopped():
            await self._verify_http(ctx, sqli, sqli_second, idor, authbypass, csrf, passive)

        confirmed = self._counts["confirmed"]
        rejected = self._counts["rejected"]
        unverified = self._counts["unverified"]
        ctx.stats["confirmed_findings"] = confirmed
        ctx.stats["rejected_findings"] = rejected
        ctx.stats["unverified_findings"] = unverified
        logger.info("Verify stage done: %d confirmed, %d rejected, %d unverified",
                    confirmed, rejected, unverified)

    async def _verify_xss(self, ctx: "ScanContext", reflected, stored, dom_xss=False):
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

            # DOM-based XSS: discovered + confirmed in one browser action (the payload
            # rides the URL fragment, which never reaches the server).
            if dom_xss and not self._stopped():
                urls = await self._load_page_urls(ctx)
                try:
                    hits = await DomXssScanner().scan(page, fired, urls, ctx.limiter)
                except Exception as e:
                    logger.debug("DOM XSS scan failed: %s", e)
                    hits = []
                for hit in hits:
                    await self._store_dom_xss(ctx, hit)
                    self._counts["confirmed"] += 1

    async def _load_page_urls(self, ctx: "ScanContext") -> list[str]:
        """Base URL + every discovered GET URL (deduped, excluder-filtered)."""
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

    async def _store_dom_xss(self, ctx: "ScanContext", hit):
        fields = dom_xss_finding_fields(hit)
        async with ctx.session_factory() as db:
            finding = Finding(
                scan_id=ctx.scan_id, endpoint_id=None,
                status=FindingStatus.CONFIRMED.value, **fields,
            )
            db.add(finding)
            await db.flush()
            if hit.screenshot_b64:
                db.add(Evidence(finding_id=finding.id, type="screenshot", content=hit.screenshot_b64))
            db.add(Evidence(finding_id=finding.id, type="dom_snapshot", content=hit.snippet))
            db.add(Evidence(finding_id=finding.id, type="request",
                            content=f"GET {hit.url}#{hit.payload}"))
            await db.commit()

    async def _verify_http(self, ctx: "ScanContext", sqli, sqli_second, idor,
                           authbypass, csrf, passive):
        """SQLi, IDOR, access-control, CSRF and passive are pure-HTTP checks — one browser, no page."""
        temps: list[str] = []
        ctx_b = ctx_anon = None
        async with async_playwright() as p:
            request_ctx, temp_path = await new_request_context(p, ctx.storage_state)
            if temp_path:
                temps.append(temp_path)
            http = DetectorHttp(request_ctx, ctx.limiter)

            # A second user's session enables cross-session IDOR + privilege escalation;
            # an anonymous session enables the unauthenticated-access check.
            http_b = http_anon = None
            if ctx.storage_state_b:
                ctx_b, temp_b = await new_request_context(p, ctx.storage_state_b)
                if temp_b:
                    temps.append(temp_b)
                http_b = DetectorHttp(ctx_b, ctx.limiter)
            if authbypass:
                ctx_anon, temp_anon = await new_request_context(p, None)
                if temp_anon:
                    temps.append(temp_anon)
                http_anon = DetectorHttp(ctx_anon, ctx.limiter)

            try:
                await self._verify_with(ctx, http, sqli, SqliVerifier())
                if sqli_second and not self._stopped():
                    await self._verify_stored_sqli(ctx, http, sqli_second)
                if idor and not self._stopped():
                    await self._verify_with(ctx, http, idor, IdorVerifier(), http_b=http_b)
                if authbypass and not self._stopped():
                    await self._verify_access(ctx, http, authbypass, http_anon, http_b)
                if csrf and not self._stopped():
                    await self._verify_csrf(ctx, http, csrf)
                if "idor" in ctx.detectors and not self._stopped():
                    await self._scan_path_idor(ctx, http)
                for ftype, items in passive.items():
                    if items and not self._stopped():
                        await self._verify_passive(ctx, http, ftype, items)
            finally:
                await request_ctx.dispose()
                if ctx_b is not None:
                    await ctx_b.dispose()
                if ctx_anon is not None:
                    await ctx_anon.dispose()
                for t in temps:
                    import os
                    try:
                        os.unlink(t)
                    except OSError:
                        pass

    async def _verify_access(self, ctx: "ScanContext", http, items, http_anon, http_b):
        """Confirm access-control findings: an unauthorized session reaches the content."""
        verifier = IdorVerifier()
        attackers = [h for h in (http_anon, http_b) if h is not None]
        for finding_id, endpoint, param in items:
            if self._stopped():
                break
            if ctx.excluder.is_excluded(endpoint.url):
                continue
            probe = EndpointProbe.from_endpoint(endpoint)
            result = await verifier.verify_access(http, attackers, probe, param)
            await self._record(ctx, finding_id, result)

    async def _scan_path_idor(self, ctx: "ScanContext", http):
        """Path-based IDOR: /users/1/profile — enumerate a numeric path segment, confirm
        neighbours are distinct records and an out-of-range id is rejected, every repeat."""
        urls = await self._load_path_urls(ctx)
        seen: set[tuple[str, int]] = set()
        for url, method in urls:
            if self._stopped():
                break
            for index, value in path_numeric_segments(url):
                if (url, index) in seen:
                    continue
                seen.add((url, index))
                try:
                    base = await http.send(method, url, None)
                except Exception:
                    continue
                if base.status != 200 or len(base.text) < _IDOR_MIN_BODY:
                    continue
                absent_val = _idor_absent(value)
                try:
                    absent = await http.send(method, with_path_segment(url, index, absent_val), None)
                except Exception:
                    continue
                winner = await self._confirm_path_segment(
                    http, method, url, index, value, base, absent, absent_val)
                if winner:
                    await self._store_path_idor(ctx, method, url, index, value, winner)
                    self._counts["confirmed"] += 1

    async def _confirm_path_segment(self, http, method, url, index, value, base,
                                    absent, absent_val, repeats: int = 3):
        """Return (neighbour_value, sim) if a neighbour is a distinct record deterministically."""
        for nbr in _idor_neighbors(value):
            stable, last = True, None
            for _ in range(repeats):
                try:
                    r = await http.send(method, with_path_segment(url, index, nbr), None)
                except Exception:
                    stable = False
                    break
                hit, (sim_nb, sim_abs) = idor_oracle(
                    base.text, value, r.text, nbr, r.status,
                    absent.text, absent_val, absent.status)
                if not hit:
                    stable = False
                    break
                last = (sim_nb, sim_abs)
            if stable and last:
                return (nbr, last[0], last[1])
        return None

    async def _load_path_urls(self, ctx: "ScanContext"):
        out, seen = [], set()
        async with ctx.session_factory() as db:
            rows = (await db.execute(
                select(Endpoint).where(Endpoint.scan_id == ctx.scan_id)
            )).scalars().all()
        for ep in rows:
            if (ep.method or "GET").upper() != "GET":
                continue
            if not path_numeric_segments(ep.url):
                continue
            key = ep.url
            if key in seen or ctx.excluder.is_excluded(ep.url):
                continue
            seen.add(key)
            out.append((ep.url, "GET"))
        return out

    async def _store_path_idor(self, ctx: "ScanContext", method, url, index, value, winner):
        nbr, sim_nb, sim_abs = winner
        from urllib.parse import urlparse
        path = urlparse(url).path or "/"
        async with ctx.session_factory() as db:
            finding = Finding(
                scan_id=ctx.scan_id, endpoint_id=None, type="idor", severity="medium",
                status=FindingStatus.CONFIRMED.value,
                title=f"Insecure direct object reference in path ({path})",
                description=(
                    f"The numeric path segment in {method} {path} selects an object directly. "
                    f"Changing it from '{value}' to '{nbr}' returned a different but same-shaped "
                    f"record (similarity {sim_nb:.3f}) while an out-of-range id was rejected "
                    f"(similarity {sim_abs:.3f}), deterministically on every repeat. CONFIRMED: "
                    f"the path identifier indexes records with no access-control check."
                ),
                reproduction_steps=(
                    f"1. Request {url}\n"
                    f"2. Change the id segment to '{nbr}' ({with_path_segment(url, index, nbr)}) and "
                    f"observe a different valid record.\n"
                    f"3. Use a far out-of-range id and observe it is rejected."
                ),
                remediation=(
                    "Authorize every object access against the current principal, and return "
                    "404/403 when the caller may not see the requested object — for path "
                    "identifiers just as for query parameters."
                ),
            )
            db.add(finding)
            await db.flush()
            db.add(Evidence(finding_id=finding.id, type="request",
                            content=f"baseline: {url}\nneighbour: {with_path_segment(url, index, nbr)}\n"
                                    f"out-of-range: {with_path_segment(url, index, _idor_absent(value))}"))
            db.add(Evidence(finding_id=finding.id, type="response",
                            content=f"neighbour-vs-baseline similarity {sim_nb:.3f} (same template, "
                                    f"different record); out-of-range similarity {sim_abs:.3f} (rejected)"))
            await db.commit()

    async def _verify_stored_sqli(self, ctx: "ScanContext", http, items):
        """Confirm second-order SQLi: re-store a breaking vs benign value, check the sink."""
        verifier = StoredSqliVerifier()
        for finding_id, endpoint, param, sink_url in items:
            if self._stopped():
                break
            if ctx.excluder.is_excluded(endpoint.url) or ctx.excluder.is_excluded(sink_url):
                continue
            probe = EndpointProbe.from_endpoint(endpoint)
            params_to_try = [param] if param in probe.baseline else probe.testable_params
            result = None
            for candidate_param in params_to_try:
                result = await verifier.verify_stored(http, probe, candidate_param, sink_url)
                if result.confirmed:
                    break
            await self._record(ctx, finding_id, result)

    async def _verify_csrf(self, ctx: "ScanContext", http, items):
        """Confirm CSRF by replaying each state-changing request without a token."""
        verifier = CsrfVerifier()
        for finding_id, endpoint, _param in items:
            if self._stopped():
                break
            if ctx.excluder.is_excluded(endpoint.url):
                continue
            probe = EndpointProbe.from_endpoint(endpoint)
            result = await verifier.verify(http, probe)
            await self._record(ctx, finding_id, result)

    async def _verify_passive(self, ctx: "ScanContext", http, ftype, items):
        """Re-check a passive finding (the param carries the issue key, e.g. header name)."""
        verifier = PassiveVerifier(ftype)
        for finding_id, endpoint, param in items:
            if self._stopped():
                break
            if ctx.excluder.is_excluded(endpoint.url):
                continue
            probe = EndpointProbe.from_endpoint(endpoint)
            result = await verifier.verify(http, probe, param)
            await self._record(ctx, finding_id, result)

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

    async def _load_sqli_candidates_split(self, ctx: "ScanContext"):
        """Split SQLi candidates into first-order and second-order (the latter carry a
        stored-sink evidence row and are verified with a store→harvest check)."""
        first, second = [], []
        async with ctx.session_factory() as db:
            findings = (await db.execute(
                select(Finding).where(
                    Finding.scan_id == ctx.scan_id,
                    Finding.status == FindingStatus.CANDIDATE.value,
                    Finding.type == "sqli",
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
                if sink:
                    second.append((f.id, endpoint, _param_of(f), sink.content))
                else:
                    first.append((f.id, endpoint, _param_of(f)))
        return first, second

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
            elif finding.type == "auth_bypass":
                proof = ("a session with no right to the endpoint (anonymous or a "
                         "lower-privilege user) retrieved the protected content, "
                         "reproduced deterministically on every repeat")
            elif finding.type == "csrf":
                proof = ("the state-changing request was accepted when replayed without "
                         "any anti-CSRF token, so it can be forged from another origin")
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
