"""
CSRF detector — state-changing requests with no anti-CSRF defence.

A form that performs a state change (POST/PUT/DELETE/PATCH) is forgeable from
another origin unless it is protected by either:
  - a per-request anti-CSRF token field (synchronizer token), or
  - a session cookie with SameSite=Strict/Lax (so the browser won't attach it to a
    cross-site request).

This batch pass flags state-changing endpoints that have neither: no recognizable
token parameter, and no SameSite cookie in the authenticated session. It is a
*candidate* — the verifier then actually replays the request without a token and
confirms the server accepts it (which also filters out header-token / double-submit
schemes that reject a tokenless request).
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from app.engine.detect.base import Candidate, EndpointProbe, build_curl

logger = logging.getLogger("proofstrike.detect.csrf")

_STATE_CHANGING = {"POST", "PUT", "DELETE", "PATCH"}

# Parameter names that are (or carry) an anti-CSRF token.
_CSRF_TOKEN_RE = re.compile(
    r"csrf|xsrf|authenticity_token|csrfmiddlewaretoken|requestverificationtoken|"
    r"(^|_)token$|(^|_)nonce$",
    re.IGNORECASE,
)

REMEDIATION = (
    "Protect every state-changing request: use a per-session/per-request synchronizer "
    "token checked server-side, and set session cookies with SameSite=Lax or Strict. "
    "For APIs, require a custom header (e.g. X-CSRF-Token) that cross-site forms cannot set."
)


def has_csrf_token(params: dict | None) -> bool:
    return bool(params) and any(_CSRF_TOKEN_RE.search(str(name)) for name in params)


def session_has_samesite(storage_state: dict | None) -> bool:
    """True if any cookie in the captured session uses SameSite=Strict/Lax."""
    for c in (storage_state or {}).get("cookies", []) or []:
        if str(c.get("sameSite", "")).lower() in ("strict", "lax"):
            return True
    return False


class CsrfScanner:
    name = "csrf"
    severity = "medium"

    def scan(self, probes: list[EndpointProbe],
             storage_state: dict | None) -> list[tuple[EndpointProbe, Candidate]]:
        samesite = session_has_samesite(storage_state)
        found: list[tuple[EndpointProbe, Candidate]] = []
        for probe in probes:
            if probe.method.upper() not in _STATE_CHANGING:
                continue
            if has_csrf_token(probe.baseline):
                continue           # synchronizer token present
            if samesite:
                continue           # SameSite cookies already block cross-site sends
            found.append((probe, self._candidate(probe)))
        return found

    def _candidate(self, probe: EndpointProbe) -> Candidate:
        path = urlparse(probe.url).path or "/"
        return Candidate(
            type="csrf", severity=self.severity, param="", payload="(tokenless request)",
            title=f"Possible CSRF on {probe.method} {path} (no anti-CSRF token)",
            description=(
                f"{probe.method} {path} changes state but its form carries no anti-CSRF "
                f"token, and the session has no SameSite cookie, so a page on another origin "
                f"could submit this request on a victim's behalf. Verification replays the "
                f"request without a token to confirm the server accepts it."
            ),
            remediation=REMEDIATION,
            technique="missing-token",
            evidence=[
                ("curl", build_curl(probe.method, probe.url, probe.baseline, probe.auth_required)),
                ("response",
                 f"State-changing endpoint with no CSRF token field.\n"
                 f"  method: {probe.method}\n"
                 f"  fields: {', '.join(probe.baseline.keys()) or '(none)'}\n"
                 f"  session SameSite cookie: no"),
            ],
        )
