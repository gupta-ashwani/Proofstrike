"""
XSS detector — raises a candidate when a parameter reflects our marker un-escaped.

This is detection only: it finds parameters whose input reaches the HTML response
without encoding. The verifier (app.engine.verify.xss_verifier) later renders the
page in a real browser to confirm the reflection actually executes.
"""

import logging
import secrets
from urllib.parse import urlparse

from app.engine.detect.base import Candidate, DetectorHttp, EndpointProbe, build_curl
from app.engine.detect.payloads import xss_marker_payload, xss_marker_signal

logger = logging.getLogger("proofstrike.detect.xss")

REMEDIATION = (
    "Context-encode all untrusted input when writing it into HTML (HTML-entity "
    "encode for body/attribute, JS-encode for scripts). Prefer a templating engine "
    "that auto-escapes, and add a Content-Security-Policy as defense in depth."
)


class XssDetector:
    name = "xss"
    severity = "high"

    async def detect(self, probe: EndpointProbe, http: DetectorHttp) -> list[Candidate]:
        candidates: list[Candidate] = []
        for param in probe.testable_params:
            token = secrets.token_hex(4)
            payload = xss_marker_payload(token)
            signal = xss_marker_signal(token)
            try:
                resp = await http.send(probe.method, probe.url, probe.inject(param, payload))
            except Exception as e:
                logger.debug("XSS probe failed for %s?%s: %s", probe.url, param, e)
                continue

            if signal in resp.text:
                snippet = self._context_snippet(resp.text, signal)
                candidates.append(Candidate(
                    type="xss",
                    severity=self.severity,
                    param=param,
                    payload=payload,
                    title=f"Reflected XSS in '{param}' ({urlparse(probe.url).path or '/'})",
                    description=(
                        f"The '{param}' parameter is reflected into the HTML response "
                        f"without encoding — the raw markup '{signal}' appears verbatim. "
                        f"This indicates a possible reflected XSS; verification will "
                        f"confirm whether it executes in a browser."
                    ),
                    remediation=REMEDIATION,
                    technique="reflection",
                    evidence=[
                        ("curl", build_curl(probe.method, probe.url, probe.inject(param, payload), probe.auth_required)),
                        ("response", f"Reflected context:\n...{snippet}..."),
                    ],
                ))
                # One candidate per (endpoint, param) is enough; the verifier does the rest.
        return candidates

    @staticmethod
    def _context_snippet(text: str, signal: str, pad: int = 80) -> str:
        idx = text.find(signal)
        start = max(0, idx - pad)
        end = min(len(text), idx + len(signal) + pad)
        return text[start:end]
