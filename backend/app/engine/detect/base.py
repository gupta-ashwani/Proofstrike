"""
Shared detector plumbing: the HTTP client, endpoint probes, candidate records,
and parameter helpers used by the detectors.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

# Benign baseline values by field type / name, used for the parameters we are not
# currently injecting into (so the request still looks valid).
_DEFAULT_BY_TYPE = {"email": "test@example.com", "number": "1", "tel": "1234567890", "url": "http://example.com"}
MASK = "********"
MAX_TESTABLE_PARAMS = 25


def _default_value(name: str, field_type: str | None) -> str:
    if field_type in _DEFAULT_BY_TYPE:
        return _DEFAULT_BY_TYPE[field_type]
    low = name.lower()
    if "email" in low:
        return "test@example.com"
    if any(k in low for k in ("id", "num", "qty", "count", "page")):
        return "1"
    return "test"


def baseline_params(raw_params: dict | None) -> dict[str, str]:
    """Flatten stored params (plain / list / form-field descriptor) to benign string values."""
    out: dict[str, str] = {}
    for name, value in (raw_params or {}).items():
        if isinstance(value, dict) and "value" in value:
            val = value.get("value") or ""
            if val in ("", MASK):
                val = _default_value(name, value.get("type"))
        elif isinstance(value, list):
            val = value[0] if value else ""
        elif isinstance(value, (str, int, float, bool)):
            val = value
        else:
            val = ""
        out[str(name)] = str(val)
    return out


@dataclass
class EndpointProbe:
    """A discovered endpoint prepared for injection testing."""
    id: str
    url: str
    method: str
    baseline: dict[str, str]
    auth_required: bool = False

    @property
    def testable_params(self) -> list[str]:
        return list(self.baseline.keys())[:MAX_TESTABLE_PARAMS]

    def inject(self, param: str, payload: str) -> dict[str, str]:
        """Copy of the baseline params with one param replaced by the payload."""
        variant = dict(self.baseline)
        variant[param] = payload
        return variant

    @classmethod
    def from_endpoint(cls, endpoint) -> "EndpointProbe":
        return cls(
            id=endpoint.id,
            url=endpoint.url,
            method=(endpoint.method or "GET").upper(),
            baseline=baseline_params(endpoint.params),
            auth_required=bool(endpoint.auth_required),
        )


@dataclass
class HttpResponse:
    status: int
    text: str
    headers: dict
    elapsed_ms: float


class DetectorHttp:
    """Rate-limited HTTP client over a Playwright APIRequestContext (shares the session)."""

    def __init__(self, request_context, limiter):
        self._req = request_context
        self._limiter = limiter

    async def send(self, method: str, url: str, params: dict | None) -> HttpResponse:
        is_body = method.upper() not in ("GET", "HEAD", "DELETE")
        async with self._limiter:
            start = time.monotonic()
            resp = await self._req.fetch(
                url,
                method=method,
                params=None if is_body else (params or None),
                form=(params or None) if is_body else None,
                max_redirects=5,
                timeout=20_000,
            )
            text = await resp.text()
            elapsed = (time.monotonic() - start) * 1000.0
        try:
            headers = dict(resp.headers)
        except Exception:
            headers = {}
        status = resp.status
        await resp.dispose()
        return HttpResponse(status=status, text=text, headers=headers, elapsed_ms=elapsed)


@dataclass
class Candidate:
    """A potential finding raised by a detector (before verification)."""
    type: str
    severity: str
    param: str
    payload: str
    title: str
    description: str
    remediation: str = ""
    technique: str = ""
    # (evidence_type, content) pairs, e.g. ("curl", "..."), ("response", "...")
    evidence: list[tuple[str, str]] = field(default_factory=list)


def build_curl(method: str, url: str, params: dict[str, str], auth_required: bool = False) -> str:
    """A copy-paste curl command that reproduces the request."""
    method = method.upper()
    lines = []
    if auth_required:
        lines.append("# requires an authenticated session cookie: add -b 'cookie=value'")
    if method in ("GET", "HEAD", "DELETE"):
        qs = urlencode(params or {})
        full = f"{url}?{qs}" if qs else url
        verb = "" if method == "GET" else f"-X {method} "
        lines.append(f"curl {verb}'{full}'")
    else:
        body = urlencode(params or {})
        lines.append(f"curl -X {method} '{url}' \\\n  --data '{body}'")
    return "\n".join(lines)
