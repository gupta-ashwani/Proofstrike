"""
Passive checks — findings you can read straight off a normal response, no exploit.

Cheap, deterministic, low-false-positive coverage that complements the active
detectors:

  - security headers : missing CSP / X-Frame-Options / X-Content-Type-Options /
                       Referrer-Policy / HSTS (on https)
  - insecure cookies : Set-Cookie without HttpOnly / Secure / SameSite
  - info disclosure  : stack traces, framework errors, directory listings in a body
  - open redirect    : a redirect-ish parameter whose value controls an off-site
                       Location (this one is active — it sends a probe)

Each is still a *candidate* until the verify stage re-checks it, so the three-way
outcome (confirmed / rejected / unverified) is preserved. Page-level issues are
de-duplicated to one finding per issue per scan so a 50-page site doesn't emit 50
identical "missing CSP" findings.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from app.engine.detect.base import Candidate, DetectorHttp, EndpointProbe, build_curl

logger = logging.getLogger("proofstrike.detect.passive")

_MAX_PAGES = 25                       # cap page-level fetches per scan
OOB_HOST = "proofstrike-oob.example"  # distinctive off-site host for open-redirect probes

# Parameter names that commonly carry a redirect target.
_REDIRECT_PARAMS = {
    "next", "url", "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
    "return_to", "returnto", "dest", "destination", "continue", "goto", "callback",
    "u", "link", "to", "out", "target", "forward",
}

_INFO_SIGNATURES = {
    "stack trace / framework error": [
        "traceback (most recent call last)", "java.lang.", "at java.", "stack trace:",
        '.py", line ', "fatal error:", "uncaught exception", "system.web.",
        "microsoft .net", "undefined index:", "notice: undefined", "warning: include(",
    ],
    "directory listing": ["index of /", "<title>directory listing for"],
}


# ── pure checks (response in, issues out) ────────────────────────────────────
def check_security_headers(headers: dict, url: str) -> list[tuple[str, str, str, str]]:
    """Return (key, severity, title, detail) for each missing security header."""
    h = {k.lower(): (v or "") for k, v in (headers or {}).items()}
    csp = h.get("content-security-policy", "")
    issues: list[tuple[str, str, str, str]] = []

    if not csp:
        issues.append(("content-security-policy", "medium",
                       "Missing Content-Security-Policy",
                       "No CSP header — a key defence-in-depth control against XSS and "
                       "content injection is absent."))
    if "x-frame-options" not in h and "frame-ancestors" not in csp.lower():
        issues.append(("x-frame-options", "medium",
                       "Missing anti-clickjacking header",
                       "No X-Frame-Options and no CSP frame-ancestors — the page can be "
                       "framed by any site, enabling clickjacking."))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        issues.append(("x-content-type-options", "low",
                       "Missing X-Content-Type-Options: nosniff",
                       "Browsers may MIME-sniff responses, enabling content-type confusion."))
    if "referrer-policy" not in h:
        issues.append(("referrer-policy", "low", "Missing Referrer-Policy",
                       "The full URL may leak to third parties via the Referer header."))
    if urlparse(url).scheme == "https" and "strict-transport-security" not in h:
        issues.append(("strict-transport-security", "low",
                       "Missing HTTP Strict-Transport-Security",
                       "Without HSTS, a user can be downgraded to http by a MITM."))
    return issues


def check_cookies(headers: dict, url: str) -> list[tuple[str, str, str, str]]:
    """Flag a Set-Cookie that lacks HttpOnly / Secure / SameSite."""
    raw = ""
    for k, v in (headers or {}).items():
        if k.lower() == "set-cookie":
            raw = v or ""
            break
    if not raw:
        return []
    low = raw.lower()
    missing = []
    if "httponly" not in low:
        missing.append("HttpOnly")
    if urlparse(url).scheme == "https" and "secure" not in low:
        missing.append("Secure")
    if "samesite" not in low:
        missing.append("SameSite")
    if not missing:
        return []
    return [("set-cookie", "medium" if "HttpOnly" in missing else "low",
             "Insecure cookie flags",
             f"A Set-Cookie is missing: {', '.join(missing)}. Session cookies should be "
             f"HttpOnly + Secure + SameSite to resist theft and CSRF.")]


def check_info_disclosure(body: str) -> list[tuple[str, str, str, str]]:
    """Flag stack traces / framework errors / directory listings leaking in a body."""
    low = (body or "")[:50_000].lower()
    out = []
    for category, needles in _INFO_SIGNATURES.items():
        hit = next((n for n in needles if n in low), None)
        if hit:
            out.append((category, "medium", f"Information disclosure — {category}",
                        f"The response body contains '{hit}', exposing internal "
                        f"implementation detail that aids an attacker."))
    return out


# ── the batch scanner ─────────────────────────────────────────────────────────
class PassiveScanner:
    name = "passive"

    async def scan_all(self, probes: list[EndpointProbe],
                       http: DetectorHttp) -> list[tuple[EndpointProbe, Candidate]]:
        found: list[tuple[EndpointProbe, Candidate]] = []
        seen_keys: set[str] = set()   # global dedup for page-level issues
        pages = 0

        for probe in probes:
            # Page-level checks run once per GET page, deduped across the whole scan.
            if probe.method.upper() == "GET" and pages < _MAX_PAGES:
                pages += 1
                try:
                    resp = await http.send("GET", probe.url, probe.baseline)
                except Exception as e:
                    logger.debug("Passive fetch failed %s: %s", probe.url, e)
                    resp = None
                if resp is not None:
                    checks = (
                        [("security_headers", i) for i in check_security_headers(resp.headers, probe.url)]
                        + [("insecure_cookie", i) for i in check_cookies(resp.headers, probe.url)]
                        + [("info_disclosure", i) for i in check_info_disclosure(resp.text)]
                    )
                    for ftype, (key, sev, title, detail) in checks:
                        dedup = f"{ftype}:{key}"
                        if dedup in seen_keys:
                            continue
                        seen_keys.add(dedup)
                        found.append((probe, self._page_candidate(probe, ftype, key, sev, title, detail)))

            # Open redirect is active — one probe per redirect-ish parameter.
            for param in probe.testable_params:
                if param.lower() not in _REDIRECT_PARAMS:
                    continue
                cand = await self._check_open_redirect(probe, param, http)
                if cand is not None:
                    found.append((probe, cand))
        return found

    async def _check_open_redirect(self, probe, param, http) -> Candidate | None:
        payload = f"https://{OOB_HOST}/evil"
        try:
            resp = await http.send(probe.method, probe.url,
                                   probe.inject(param, payload), max_redirects=0)
        except Exception as e:
            logger.debug("Open-redirect probe failed %s?%s: %s", probe.url, param, e)
            return None
        location = ""
        for k, v in (resp.headers or {}).items():
            if k.lower() == "location":
                location = v or ""
                break
        if resp.status in (301, 302, 303, 307, 308) and OOB_HOST in location:
            path = urlparse(probe.url).path or "/"
            return Candidate(
                type="open_redirect", severity="medium", param=param, payload=payload,
                title=f"Open redirect in '{param}' ({path})",
                description=(f"The '{param}' parameter controls the redirect target: a request "
                            f"with it set to an external URL returned a redirect to that host "
                            f"(Location: {location[:120]}). Attackers can craft trustworthy-looking "
                            f"links that bounce victims to a malicious site (phishing / token leak). "
                            f"Verification re-sends the probe to confirm the off-site redirect."),
                remediation=("Do not build redirects from raw user input. Allow-list permitted "
                             "destinations (or use server-side keys that map to known URLs), and "
                             "reject absolute/protocol-relative URLs to other hosts."),
                technique="open-redirect",
                evidence=[
                    ("curl", build_curl(probe.method, probe.url, probe.inject(param, payload),
                                        probe.auth_required)),
                    ("response", f"Open redirect on '{param}':\n"
                                 f"  payload: {payload}\n"
                                 f"  HTTP {resp.status}, Location: {location}"),
                ],
            )
        return None

    def _page_candidate(self, probe, ftype, key, sev, title, detail) -> Candidate:
        path = urlparse(probe.url).path or "/"
        # The key is embedded in quotes so the verify stage can recover it from the
        # title (findings have no param column; param is parsed back from the title).
        label = _TITLE_LABEL.get(ftype, "Issue")
        return Candidate(
            type=ftype, severity=sev, param=key, payload="(passive — no payload)",
            title=f"{label} '{key}' ({path})",
            description=(f"{title}. {detail} Observed on {probe.method} {probe.url}. "
                        f"Verification re-requests the page to confirm the condition holds."),
            remediation=_REMEDIATION.get(ftype, "Review and harden this response."),
            technique=ftype,
            evidence=[
                ("curl", build_curl("GET", probe.url, probe.baseline, probe.auth_required)),
                ("response", f"Passive check '{key}': {title}"),
            ],
        )


_TITLE_LABEL = {
    "security_headers": "Missing security header",
    "insecure_cookie": "Insecure cookie",
    "info_disclosure": "Information disclosure",
}

_REMEDIATION = {
    "security_headers": ("Set the standard response security headers at the edge/app: "
                         "Content-Security-Policy, X-Frame-Options (or CSP frame-ancestors), "
                         "X-Content-Type-Options: nosniff, Referrer-Policy, and HSTS over https."),
    "insecure_cookie": ("Set session cookies with HttpOnly, Secure, and an appropriate "
                        "SameSite value so they resist theft and cross-site use."),
    "info_disclosure": ("Return generic error pages in production, disable debug/stack traces, "
                        "and turn off directory listing."),
}
