"""
Second-order (stored) SQL injection detector.

A first-order SQLi shows up in the same response. A second-order one is stored
safely at one endpoint and only becomes an injection when a *different* page later
builds a query from the stored value. A single request/response check can't see it,
so — like stored XSS — this works in two phases across the whole surface:

  1. Seed:    store a unique marker + a lone quote (``pssqli<token>'``) in every
              writable parameter, remembering which injection each token came from.
  2. Harvest: fetch every sink page once; if a page that is NOT the injection page
              now shows a DB error (absent from its baseline) together with our
              marker, the stored value reached the SQL engine on that page.

The quote is what trips the later query; the marker is what proves the error is ours
and gives precise attribution. The verifier then re-seeds a breaking vs a benign
value and confirms the error appears only for the breaking one.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from urllib.parse import urlparse

from app.engine.detect.base import Candidate, DetectorHttp, EndpointProbe, build_curl
from app.engine.detect.payloads import (
    SQL_ERROR_SIGNATURES, stored_sqli_payload, stored_sqli_signal)
from app.engine.detect.sqli import REMEDIATION
from app.engine.detect.stored_xss import SINK_EVIDENCE_TYPE, _path_key

logger = logging.getLogger("proofstrike.detect.stored_sqli")

_WINDOW = 300  # chars after our marker to scan for the error it caused


def _marker_errors(text: str, signal: str) -> str:
    """A DB-error signature appearing right after our marker, else ''. Localising the
    error to our own seed makes this robust to other quote-bearing values already stored
    on the sink by earlier detectors (seeding order would otherwise poison a baseline)."""
    idx = text.find(signal)
    if idx < 0:
        return ""
    window = text[idx: idx + len(signal) + _WINDOW].lower()
    return next((s for s in SQL_ERROR_SIGNATURES if s in window), "")


@dataclass
class _Seed:
    token: str
    probe: EndpointProbe
    param: str


class StoredSqliDetector:
    """Batch detector — seeds writable params, then harvests sink pages for a late error."""

    name = "sqli"
    severity = "high"

    async def detect_all(self, probes: list[EndpointProbe], sink_urls: list[str],
                         http: DetectorHttp) -> list[tuple[EndpointProbe, Candidate]]:
        seeds = await self._seed(probes, http)
        if not seeds:
            return []
        logger.info("Stored SQLi: seeded %d marker(s); harvesting %d sink page(s)",
                    len(seeds), len(sink_urls))
        return await self._harvest(seeds, sink_urls, http)

    async def _seed(self, probes, http) -> list[_Seed]:
        seeds: list[_Seed] = []
        for probe in probes:
            for param in probe.testable_params:
                token = secrets.token_hex(5)
                try:
                    await http.send(probe.method, probe.url,
                                    probe.inject(param, stored_sqli_payload(token)))
                except Exception as e:
                    logger.debug("Stored SQLi seed failed %s?%s: %s", probe.url, param, e)
                    continue
                seeds.append(_Seed(token=token, probe=probe, param=param))
        return seeds

    async def _harvest(self, seeds, sink_urls, http) -> list:
        pending = {s.token: s for s in seeds}
        found: list[tuple[EndpointProbe, Candidate]] = []
        for sink in sink_urls:
            if not pending:
                break
            try:
                resp = await http.send("GET", sink, None)
            except Exception:
                continue
            for token, seed in list(pending.items()):
                signal = stored_sqli_signal(token)
                if _path_key(sink) == _path_key(seed.probe.url):
                    continue  # same page it was submitted to — not second-order
                sig = _marker_errors(resp.text, signal)  # error localised to OUR marker
                if not sig:
                    continue  # marker absent, or present but no DB error (just stored)
                del pending[token]
                found.append((seed.probe, self._candidate(seed, sink, resp.text, signal, sig)))
        return found

    def _candidate(self, seed, sink, body, signal, sig) -> Candidate:
        probe = seed.probe
        inj_path = urlparse(probe.url).path or "/"
        sink_path = urlparse(sink).path or "/"
        payload = stored_sqli_payload(seed.token)
        return Candidate(
            type="sqli", severity=self.severity, param=seed.param, payload=payload,
            title=f"Second-order SQL injection via '{seed.param}' ({inj_path} -> {sink_path})",
            description=(
                f"Input to '{seed.param}' at {probe.method} {inj_path} is stored and later "
                f"concatenated into a SQL query on a different page ({sink_path}): a stored "
                f"value containing a quote produced a database error there ('{sig}') that is "
                f"not in that page's normal response. This is a second-order SQL injection. "
                f"Verification re-stores a breaking vs a benign value to confirm the error "
                f"tracks the stored input."
            ),
            remediation=REMEDIATION,
            technique="second-order",
            evidence=[
                (SINK_EVIDENCE_TYPE, sink),
                ("curl", build_curl(probe.method, probe.url,
                                    probe.inject(seed.param, payload), probe.auth_required)),
                ("response", f"Stored value surfaced as a SQL error on {sink_path}:\n"
                             f"  marker: {signal}\n  DB error signature: '{sig}'"),
            ],
        )
