"""
CSRF verifier — replay the state-changing request WITHOUT a token and see if the
server accepts it.

Detection only saw that the form had no token field. The proof is behavioural: if a
tokenless request (benign values) is processed rather than rejected, the server does
not require an anti-CSRF token, so the request is forgeable. If instead it is refused
(HTTP 4xx, or a body that mentions a token/CSRF/forbidden), the server enforces
protection some other way (header token, double-submit cookie) and the candidate is
rejected — no false positive.
"""

from __future__ import annotations

import logging

from app.engine.detect.base import DetectorHttp, EndpointProbe
from app.engine.detect.csrf import _CSRF_TOKEN_RE
from app.engine.verify.xss_verifier import VerifyResult

logger = logging.getLogger("proofstrike.verify.csrf")

_REJECT_HINTS = ("csrf", "xsrf", "invalid token", "missing token", "forbidden",
                 "not allowed", "403", "access denied")


class CsrfVerifier:
    async def verify(self, http: DetectorHttp, probe: EndpointProbe) -> VerifyResult:
        # Benign values, and strip any token-looking field so the request is truly tokenless.
        params = {k: v for k, v in probe.baseline.items() if not _CSRF_TOKEN_RE.search(str(k))}
        try:
            resp = await http.send(probe.method, probe.url, params)
        except Exception as e:
            logger.debug("CSRF verify send failed for %s: %s", probe.url, e)
            return VerifyResult(False, attempted=False,
                                note="could not send the test request; verify manually")

        low = (resp.text or "")[:5000].lower()
        rejected = resp.status >= 400 or any(h in low for h in _REJECT_HINTS)
        if rejected:
            return VerifyResult(
                False, attempted=True,
                note=f"tokenless request was rejected (HTTP {resp.status}) — the server "
                     f"appears to enforce CSRF protection")
        detail = (f"Tokenless {probe.method} {probe.url} was accepted (HTTP {resp.status}, "
                  f"no token/forbidden response) — the server does not require an anti-CSRF "
                  f"token, so the request can be forged cross-site.")
        return VerifyResult(True, attempted=True, payload="(tokenless cross-site request)",
                            url=probe.url,
                            request_desc=f"{probe.method} {probe.url} (sent without any CSRF token)",
                            dom_snippet=detail)
