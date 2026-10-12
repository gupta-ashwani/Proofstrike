"""
Stored (persistent) XSS detector.

Unlike reflected XSS — where the payload comes straight back in the same response
— stored XSS is written at one endpoint and surfaces later on a *different* page.
A single request/response check can never catch it, so this detector works in two
phases across the whole attack surface:

  1. Seed:    inject a unique marker into every injectable parameter, remembering
              which injection (endpoint + param) each token came from.
  2. Harvest: fetch every known "sink" page once and look for any seeded marker
              surfacing un-escaped. A hit on a page that is NOT the injection URL
              means the input was stored and reflected elsewhere — a candidate.

This keeps the cost at O(injections + sinks) requests instead of the product.

Detection only confirms the marker was stored and reflected un-encoded; the
verifier (app.engine.verify.xss_verifier.verify_stored) renders the sink page in a
real browser to prove the stored payload actually executes.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from urllib.parse import urlparse

from app.engine.detect.base import Candidate, DetectorHttp, EndpointProbe, build_curl
from app.engine.detect.payloads import stored_marker_payload, stored_marker_signal

logger = logging.getLogger("proofstrike.detect.stored_xss")

# Evidence key under which we persist the sink URL so the verifier knows where to look.
SINK_EVIDENCE_TYPE = "stored_sink"

REMEDIATION = (
    "Encode untrusted input for the HTML context at the point it is rendered, not "
    "just when it is stored. A value saved verbatim is safe only until it is written "
    "into a page — escape on output, prefer an auto-escaping template engine, and add "
    "a Content-Security-Policy as defense in depth."
)


def _path_key(url: str) -> str:
    """host + path, so we can tell the injection page apart from a sink page."""
    parsed = urlparse(url)
    return parsed.netloc.lower() + (parsed.path.rstrip("/") or "/")


@dataclass
class _Seed:
    token: str
    probe: EndpointProbe
    param: str


class StoredXssDetector:
    """Batch detector — operates over all probes + sink pages at once, not one probe."""

    name = "stored_xss"
    severity = "high"

    async def detect_all(
        self,
        probes: list[EndpointProbe],
        sink_urls: list[str],
        http: DetectorHttp,
    ) -> list[tuple[EndpointProbe, Candidate]]:
        seeds = await self._seed(probes, http)
        if not seeds:
            return []
        logger.info("Stored XSS: seeded %d marker(s); harvesting %d sink page(s)",
                    len(seeds), len(sink_urls))
        return await self._harvest(seeds, sink_urls, http)

    async def _seed(self, probes: list[EndpointProbe], http: DetectorHttp) -> list[_Seed]:
        """Inject a unique marker into every injectable parameter."""
        seeds: list[_Seed] = []
        for probe in probes:
            for param in probe.testable_params:
                token = secrets.token_hex(5)
                payload = stored_marker_payload(token)
                try:
                    await http.send(probe.method, probe.url, probe.inject(param, payload))
                except Exception as e:
                    logger.debug("Stored seed failed for %s?%s: %s", probe.url, param, e)
                    continue
                seeds.append(_Seed(token=token, probe=probe, param=param))
        return seeds

    async def _harvest(
        self,
        seeds: list[_Seed],
        sink_urls: list[str],
        http: DetectorHttp,
    ) -> list[tuple[EndpointProbe, Candidate]]:
        """Fetch each sink once; match any still-unconsumed marker surfacing un-escaped."""
        pending = {seed.token: seed for seed in seeds}
        found: list[tuple[EndpointProbe, Candidate]] = []

        for sink in sink_urls:
            if not pending:
                break
            try:
                resp = await http.send("GET", sink, None)
            except Exception as e:
                logger.debug("Stored harvest failed for %s: %s", sink, e)
                continue
            for token, seed in list(pending.items()):
                signal = stored_marker_signal(token)
                if signal not in resp.text:
                    continue
                if _path_key(sink) == _path_key(seed.probe.url):
                    continue  # same page it was submitted to — that's reflected, not stored
                del pending[token]  # one candidate per seed
                found.append((seed.probe, self._candidate(seed, sink, resp.text, signal)))

        return found

    def _candidate(self, seed: _Seed, sink: str, body: str, signal: str) -> Candidate:
        probe = seed.probe
        inj_path = urlparse(probe.url).path or "/"
        sink_path = urlparse(sink).path or "/"
        marker = stored_marker_payload(seed.token)
        return Candidate(
            type="stored_xss",
            severity=self.severity,
            param=seed.param,
            payload=marker,
            title=f"Stored XSS via '{seed.param}' ({inj_path} -> {sink_path})",
            description=(
                f"Input to the '{seed.param}' parameter of {probe.method} {inj_path} is "
                f"stored and later reflected un-encoded on a different page ({sink_path}) — "
                f"the raw markup '{signal}' appears there verbatim. This indicates a "
                f"possible stored (persistent) XSS; verification will confirm whether the "
                f"stored payload executes in a browser when the sink page is viewed."
            ),
            remediation=REMEDIATION,
            technique="stored",
            evidence=[
                (SINK_EVIDENCE_TYPE, sink),
                ("curl", build_curl(probe.method, probe.url,
                                    probe.inject(seed.param, marker), probe.auth_required)),
                ("response", f"Stored marker reflected on {sink_path}:\n"
                             f"...{self._snippet(body, signal)}..."),
            ],
        )

    @staticmethod
    def _snippet(text: str, signal: str, pad: int = 80) -> str:
        idx = text.find(signal)
        start = max(0, idx - pad)
        end = min(len(text), idx + len(signal) + pad)
        return text[start:end]
