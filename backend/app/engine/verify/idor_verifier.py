"""
IDOR verifier — confirm the enumeration is deterministic, not page noise.

Detection saw one neighbouring identifier return a distinct, same-shaped record
while an out-of-range identifier was rejected. To *confirm*, the winning neighbour
and the out-of-range control are re-requested several times and the IDOR oracle is
required to hold on every repeat: the neighbour is consistently a different valid
record, and the out-of-range id is consistently rejected. Response behaviour being
a deterministic function of the identifier is the proof the reference is honoured
with no access-control gate.

Pure HTTP (no browser), like the SQLi verifier, so verification always runs; the
outcome is confirmed (deterministic) or rejected (not reproducible).
"""

from __future__ import annotations

import logging
from urllib.parse import urlencode

from app.engine.detect.base import DetectorHttp, EndpointProbe
from app.engine.detect.idor import (
    _absent,
    _is_reference,
    _neighbors,
    idor_oracle,
    _MIN_BODY,
)
from app.engine.verify.xss_verifier import VerifyResult

logger = logging.getLogger("proofstrike.verify.idor")

DEFAULT_REPEATS = 3


class IdorVerifier:
    async def verify(self, http: DetectorHttp, probe: EndpointProbe, param: str,
                     repeats: int = DEFAULT_REPEATS) -> VerifyResult:
        value = probe.baseline.get(param, "")
        if not _is_reference(param, value):
            return VerifyResult(False, attempted=True,
                                note="parameter is not an enumerable object reference")
        try:
            base = await http.send(probe.method, probe.url, probe.baseline)
        except Exception as e:
            logger.debug("IDOR verify baseline failed for %s: %s", probe.url, e)
            return VerifyResult(False, attempted=False,
                                note="could not reach the endpoint to verify; try manually")
        if base.status != 200 or len(base.text) < _MIN_BODY:
            return VerifyResult(False, attempted=True,
                                note="baseline is not a stable object page; cannot verify enumeration")

        absent_val = _absent(value)
        for nbr_val in _neighbors(value):
            stable = True
            last = None  # (sim_nb, sim_abs, nbr_status, absent_status)
            for _ in range(repeats):
                try:
                    r = await http.send(probe.method, probe.url, probe.inject(param, nbr_val))
                    a = await http.send(probe.method, probe.url, probe.inject(param, absent_val))
                except Exception:
                    stable = False
                    break
                hit, (sim_nb, sim_abs) = idor_oracle(
                    base.text, value, r.text, nbr_val, r.status,
                    a.text, absent_val, a.status,
                )
                if not hit:
                    stable = False
                    break
                last = (sim_nb, sim_abs, r.status, a.status)
            if stable and last:
                sim_nb, sim_abs, nbr_status, absent_status = last
                absent_desc = (f"HTTP {absent_status}" if absent_status >= 400
                               else f"distinct 'not found' page (similarity {sim_abs:.3f})")
                detail = (
                    f"Deterministic object enumeration over {repeats} repeats:\n"
                    f"  baseline id:  {value}\n"
                    f"  neighbour id: {nbr_val}  -> distinct same-shaped record every time\n"
                    f"  out-of-range: {absent_val}  -> rejected every time ({absent_desc})\n"
                    f"  neighbour-vs-baseline similarity: {sim_nb:.3f} (same template, different data)\n"
                    f"  absent-vs-baseline similarity:    {sim_abs:.3f}"
                )
                req = (f"{probe.method} {probe.url}  (param '{param}')\n"
                       f"baseline:  {urlencode(probe.baseline)}\n"
                       f"neighbour: {urlencode(probe.inject(param, nbr_val))}\n"
                       f"absent:    {urlencode(probe.inject(param, absent_val))}")
                return VerifyResult(True, attempted=True, payload=nbr_val,
                                    url=probe.url, request_desc=req, dom_snippet=detail)
        return VerifyResult(
            False, attempted=True,
            note="object enumeration did not reproduce deterministically under verification",
        )
