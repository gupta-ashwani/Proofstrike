"""
Passive verifier — re-request the page and confirm the observed condition still
holds. Passive findings are deterministic facts about a response, so "verify" means
re-reading it once: the header is still missing, the cookie still lacks a flag, the
leak is still in the body, or the off-site redirect still happens.
"""

from __future__ import annotations

import logging

from app.engine.detect.base import DetectorHttp, EndpointProbe
from app.engine.detect.passive import (
    OOB_HOST,
    check_cookies,
    check_info_disclosure,
    check_security_headers,
)
from app.engine.verify.xss_verifier import VerifyResult

logger = logging.getLogger("proofstrike.verify.passive")


class PassiveVerifier:
    """One instance per finding type ('security_headers', 'insecure_cookie', …)."""

    def __init__(self, ftype: str):
        self.ftype = ftype

    async def verify(self, http: DetectorHttp, probe: EndpointProbe, param: str, **_) -> VerifyResult:
        if self.ftype == "open_redirect":
            return await self._verify_open_redirect(http, probe, param)

        try:
            resp = await http.send("GET", probe.url, probe.baseline)
        except Exception as e:
            logger.debug("Passive verify fetch failed %s: %s", probe.url, e)
            return VerifyResult(False, attempted=False,
                                note="could not reach the endpoint to re-check; verify manually")

        if self.ftype == "security_headers":
            still = {k for k, *_rest in check_security_headers(resp.headers, probe.url)}
            present = param in still
            note = (f"header '{param}' is still absent" if present
                    else f"header '{param}' is now present")
        elif self.ftype == "insecure_cookie":
            issues = check_cookies(resp.headers, probe.url)
            present = bool(issues)
            note = issues[0][3] if issues else "cookie flags are now set correctly"
        elif self.ftype == "info_disclosure":
            cats = {k for k, *_rest in check_info_disclosure(resp.text)}
            present = param in cats
            note = (f"'{param}' is still disclosed in the response" if present
                    else f"'{param}' is no longer present")
        else:
            return VerifyResult(False, attempted=False, note=f"unknown passive type {self.ftype}")

        if present:
            return VerifyResult(True, attempted=True, payload=param, url=probe.url,
                                request_desc=f"GET {probe.url}",
                                dom_snippet=f"Re-checked {probe.url}: {note}.")
        return VerifyResult(False, attempted=True, note=note)

    async def _verify_open_redirect(self, http, probe, param) -> VerifyResult:
        payload = f"https://{OOB_HOST}/evil"
        try:
            resp = await http.send(probe.method, probe.url,
                                   probe.inject(param, payload), max_redirects=0)
        except Exception as e:
            logger.debug("Open-redirect verify failed %s: %s", probe.url, e)
            return VerifyResult(False, attempted=False,
                                note="could not re-check the redirect; verify manually")
        location = ""
        for k, v in (resp.headers or {}).items():
            if k.lower() == "location":
                location = v or ""
                break
        if resp.status in (301, 302, 303, 307, 308) and OOB_HOST in location:
            return VerifyResult(True, attempted=True, payload=payload, url=probe.url,
                                request_desc=f"{probe.method} {probe.url} ({param}={payload})",
                                dom_snippet=f"Re-sent probe: HTTP {resp.status}, "
                                            f"Location redirects off-site to {location[:120]}.")
        return VerifyResult(False, attempted=True,
                            note="the off-site redirect did not reproduce")
