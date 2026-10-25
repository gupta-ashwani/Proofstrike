"""
DOM-based XSS scanner.

Reflected/stored XSS both need the payload to pass through the server. DOM XSS does
not: a client-side sink (``innerHTML``, ``document.write``, ``eval`` …) reads an
attacker-controlled *source* and executes it entirely in the browser. The classic
source is the URL fragment (``location.hash``) — which browsers never send to the
server, so a payload placed there cannot be a reflected/stored finding.

This scanner navigates each page with an exec payload in the fragment and watches
the shared ``window.__psxss`` binding. If it fires, a DOM sink executed our markup
from the hash — a confirmed DOM XSS, proven the same way as every other XSS here
(the payload actually ran in a real browser). Because the hash never reached the
server, detection and confirmation are the same browser action.
"""

from __future__ import annotations

import base64
import logging
import secrets
from dataclasses import dataclass
from urllib.parse import urlparse

from app.engine.detect.payloads import EXEC_BINDING

logger = logging.getLogger("proofstrike.verify.dom_xss")

_URL_CAP = 25  # pages to probe per scan


def dom_xss_payloads(token: str) -> list[str]:
    """Exec payloads for DOM sinks that write a source into HTML (innerHTML/write)."""
    cb = f"window.{EXEC_BINDING}"
    return [
        f"<img src=x onerror={cb}('{token}')>",
        f"<svg onload={cb}('{token}')>",
    ]


@dataclass
class DomXssHit:
    url: str
    payload: str
    screenshot_b64: str = ""
    snippet: str = ""


class DomXssScanner:
    async def scan(self, page, fired: list, urls: list[str], limiter) -> list[DomXssHit]:
        hits: list[DomXssHit] = []
        for url in urls[:_URL_CAP]:
            hit = await self._probe(page, fired, url, limiter)
            if hit is not None:
                hits.append(hit)
        return hits

    async def _probe(self, page, fired, url, limiter) -> DomXssHit | None:
        token = secrets.token_hex(5)
        for payload in dom_xss_payloads(token):
            target = f"{url}#{payload}"
            fired.clear()
            try:
                async with limiter:
                    await page.goto(target, wait_until="domcontentloaded", timeout=20_000)
                fired_ok = await self._await_fire(page, fired, token)
            except Exception as e:
                logger.debug("DOM XSS probe failed for %s: %s", target, e)
                continue
            if fired_ok:
                shot = ""
                try:
                    shot = base64.b64encode(await page.screenshot(full_page=False)).decode()
                except Exception:
                    pass
                return DomXssHit(
                    url=url, payload=payload, screenshot_b64=shot,
                    snippet=(f"A DOM sink read the URL fragment and executed it: navigating "
                             f"to {url}#<payload> fired the callback, so the markup ran "
                             f"client-side without ever reaching the server."),
                )
        return None

    @staticmethod
    async def _await_fire(page, fired, token, tries: int = 14, delay_ms: int = 250) -> bool:
        for _ in range(tries):
            if token in fired:
                return True
            try:
                await page.wait_for_timeout(delay_ms)
            except Exception:
                break
        return token in fired


def dom_xss_finding_fields(hit: DomXssHit) -> dict:
    """Finding column values for a confirmed DOM XSS (stored directly by the verify stage)."""
    path = urlparse(hit.url).path or "/"
    return {
        "type": "xss",
        "severity": "high",
        "title": f"DOM-based XSS at {path}",
        "description": (
            f"A client-side sink on {hit.url} executed a payload supplied in the URL "
            f"fragment (location.hash) — the value never reached the server, so this is a "
            f"DOM-based XSS, not reflected or stored. CONFIRMED: the payload ran in a real "
            f"browser (callback fired). Confirming payload: {hit.payload}"
        ),
        "reproduction_steps": (
            f"1. Open {hit.url}#{hit.payload}\n"
            f"2. The page's JavaScript reads the fragment and writes it into the DOM, "
            f"executing the payload (the callback fires).\n\n"
            f"Payload (in the URL fragment): {hit.payload}"
        ),
        "remediation": (
            "Never pass untrusted sources (location.hash/search/href, postMessage, "
            "document.referrer) into dangerous sinks (innerHTML, outerHTML, document.write, "
            "eval, setTimeout(string), insertAdjacentHTML). Use textContent or a sanitizer "
            "(e.g. DOMPurify), and add a Content-Security-Policy as defense in depth."
        ),
    }
