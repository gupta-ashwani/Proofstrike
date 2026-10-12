"""
XSS verifier — confirms a candidate by making the payload actually execute in a
real browser.

It injects execution payloads that call a JS binding (window.__psxss) exposed on
the page. If the binding fires with our token, the injected script ran — the XSS
is confirmed, and we capture a screenshot + the DOM context as proof.

GET:  navigate to the URL with the payload in the query string.
POST: submit a real POST from inside the browser (a hidden auto-submitting form
      built with the captured fields), so the response renders and any script runs.

Outcome is three-way:
  - confirmed : the payload executed (proof attached)
  - rejected  : we ran the check, the input reflected, but it did NOT execute
  - unverified: we could not actually test it (e.g. the POST was blocked by
                CSRF/session/validation and our input never reflected) → stays a candidate
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

from app.engine.detect.base import EndpointProbe
from app.engine.detect.payloads import xss_exec_payloads

logger = logging.getLogger("proofstrike.verify.xss")

_BUILD_FORM_JS = """(d) => {
    const f = document.createElement('form');
    f.method = 'POST';
    f.action = d.action;
    f.id = '__xssform';
    for (const k in d.params) {
        const i = document.createElement('input');
        i.type = 'hidden';
        i.name = k;
        i.value = d.params[k];
        f.appendChild(i);
    }
    document.body.appendChild(f);
}"""


@dataclass
class VerifyResult:
    confirmed: bool
    attempted: bool = True   # False = we could not actually run the check (so it's not a rejection)
    payload: str = ""
    url: str = ""
    request_desc: str = ""   # human-readable request for evidence
    screenshot_b64: str = ""
    dom_snippet: str = ""
    note: str = ""


class XssVerifier:
    async def verify(self, page, fired: list, probe: EndpointProbe, param: str,
                     limiter, allow_post: bool = True) -> VerifyResult:
        if probe.method == "GET":
            return await self._verify_get(page, fired, probe, param, limiter)
        if allow_post:
            return await self._verify_post(page, fired, probe, param, limiter)
        return VerifyResult(
            False, attempted=False,
            note="reflected via a POST parameter; POST verification is disabled for this scan",
        )

    # ── GET ──────────────────────────────────────────────────────────────
    async def _verify_get(self, page, fired, probe, param, limiter) -> VerifyResult:
        for payload in xss_exec_payloads(secrets.token_hex(5)):
            token = _token_of(payload)
            target = f"{probe.url}?{urlencode(probe.inject(param, payload))}"
            fired.clear()
            try:
                async with limiter:
                    await page.goto(target, wait_until="domcontentloaded", timeout=20_000)
                fired_ok = await self._await_fire(page, fired, token)
            except Exception as e:
                logger.debug("XSS GET verify failed for %s: %s", target, e)
                continue
            if fired_ok:
                return await self._confirmed(page, token, payload, target, f"GET {target}")
        return VerifyResult(False, note="reflection did not execute in a browser")

    # ── POST ─────────────────────────────────────────────────────────────
    async def _verify_post(self, page, fired, probe, param, limiter) -> VerifyResult:
        any_reflected = False
        reflected_snippet = ""
        for payload in xss_exec_payloads(secrets.token_hex(5)):
            token = _token_of(payload)
            params = probe.inject(param, payload)
            fired.clear()
            try:
                await self._submit_post(page, probe.url, params, limiter)
                fired_ok = await self._await_fire(page, fired, token)
            except Exception as e:
                logger.debug("XSS POST verify failed for %s: %s", probe.url, e)
                continue

            if fired_ok:
                desc = f"POST {probe.url}\n\n{urlencode(params)}"
                return await self._confirmed(page, token, payload, probe.url, desc)

            try:
                content = await page.content()
                if token in content:
                    any_reflected = True
                    if not reflected_snippet:
                        reflected_snippet = _snip(content, token)
            except Exception:
                pass

        if any_reflected:
            return VerifyResult(
                False, attempted=True, dom_snippet=reflected_snippet,
                note="reflected via POST but did not execute in a browser (see how it was "
                     "reflected below — it may be encoded, or in a non-executing context)",
            )
        # Input never reflected — the POST was likely blocked (CSRF/session/validation),
        # so we cannot conclude. Keep it as a candidate.
        return VerifyResult(
            False, attempted=False,
            note="could not confirm via POST — the request may have been blocked by "
                 "CSRF/session/validation (our input did not reflect); verify manually",
        )

    async def _submit_post(self, page, action: str, params: dict, limiter):
        """Submit a real POST from the browser via a hidden auto-submitting form."""
        data = json.dumps({"action": action, "params": params})
        async with limiter:
            await page.goto("about:blank")
            await page.evaluate(_BUILD_FORM_JS, json.loads(data))
            try:
                async with page.expect_navigation(wait_until="domcontentloaded", timeout=20_000):
                    await page.evaluate("document.getElementById('__xssform').submit()")
            except Exception as e:
                # Navigation destroys the execution context — expected; the page did navigate
                logger.debug("POST submit navigation note: %s", e)

    # ── shared ───────────────────────────────────────────────────────────
    @staticmethod
    async def _await_fire(page, fired: list, token: str, tries: int = 24, interval_ms: int = 150) -> bool:
        """
        Poll for the execution callback for up to tries*interval (~3.6s), returning
        early as soon as it fires. Gives network-dependent vectors (img onerror) time
        to fire on remote targets, instead of a single fixed wait.
        """
        for _ in range(tries):
            if token in fired:
                return True
            try:
                await page.wait_for_timeout(interval_ms)
            except Exception:
                break
        return token in fired

    async def _confirmed(self, page, token, payload, url, request_desc) -> VerifyResult:
        shot = ""
        try:
            shot = base64.b64encode(await page.screenshot()).decode()
        except Exception:
            pass
        return VerifyResult(
            confirmed=True,
            payload=payload,
            url=url,
            request_desc=request_desc,
            screenshot_b64=shot,
            dom_snippet=await self._dom_snippet(page, token),
        )

    @staticmethod
    async def _dom_snippet(page, needle: str, pad: int = 180) -> str:
        try:
            html = await page.content()
        except Exception:
            return ""
        return _snip(html, needle, pad)


def _snip(text: str, needle: str, pad: int = 180) -> str:
    idx = text.find(needle)
    if idx < 0:
        return text[:1200]
    return text[max(0, idx - pad): idx + len(needle) + pad]


def _token_of(payload: str) -> str:
    # Our exec payloads embed the token inside __psxss("<token>")
    marker = "__psxss("
    i = payload.find(marker)
    if i < 0:
        return ""
    rest = payload[i + len(marker):]
    return rest.strip("\"')").split(")")[0].strip("\"'")
