"""
SQL-injection verifier — boolean-blind, error-based, and time-based techniques.

Detection only showed a one-off signal. To *confirm*, each technique is re-run and
required to behave deterministically, which is what separates a real injection from
page noise:

  - boolean : the TRUE/FALSE response split must hold on every repeat.
  - error   : the same syntax break must raise a DB-error signature every time,
              and that signature must be absent from the untouched response.
  - time    : the response time must track the *injected* delay — a 1s sleep gives
              ~1s, a longer sleep gives proportionally longer. Response time being a
              function of our payload is the proof the DB ran it.

All three are pure HTTP checks (no browser), so verification always runs; the
outcome is confirmed (deterministic) or rejected (not reproducible).
"""

from __future__ import annotations

import logging
from urllib.parse import urlencode

from app.engine.detect.base import DetectorHttp, EndpointProbe
from app.engine.detect.payloads import (
    sqli_boolean_pairs,
    sqli_error_payloads,
    sqli_time_payloads,
)
from app.engine.detect.sqli import boolean_oracle, find_error_signature
from app.engine.verify.xss_verifier import VerifyResult

logger = logging.getLogger("proofstrike.verify.sqli")

DEFAULT_REPEATS = 3
# Time-based confirmation: inject two different delays and require the response
# time to scale with them.
_TIME_SHORT = 1
_TIME_LONG = 4
_TIME_RATIO = 0.6


class SqliVerifier:
    async def verify(self, http: DetectorHttp, probe: EndpointProbe, param: str,
                     repeats: int = DEFAULT_REPEATS) -> VerifyResult:
        value = probe.baseline.get(param, "")
        try:
            base = await http.send(probe.method, probe.url, probe.baseline)
        except Exception as e:
            logger.debug("SQLi verify baseline failed for %s: %s", probe.url, e)
            return VerifyResult(False, attempted=False,
                                note="could not reach the endpoint to verify; try manually")

        # Cheapest/strongest first; time-based (slow) only if the others don't confirm.
        result = (
            await self._verify_boolean(http, probe, param, value, base, repeats)
            or await self._verify_error(http, probe, param, value, base, repeats)
            or await self._verify_time(http, probe, param, value, base)
        )
        if result:
            return result
        return VerifyResult(
            False, attempted=True,
            note="no SQLi technique (boolean/error/time) reproduced deterministically "
                 "under verification",
        )

    # ── boolean ────────────────────────────────────────────────────────────
    async def _verify_boolean(self, http, probe, param, value, base, repeats) -> VerifyResult | None:
        for label, true_p, false_p in sqli_boolean_pairs(value):
            ratios = None
            stable = True
            for _ in range(repeats):
                try:
                    t = await http.send(probe.method, probe.url, probe.inject(param, true_p))
                    f = await http.send(probe.method, probe.url, probe.inject(param, false_p))
                except Exception:
                    stable = False
                    break
                if t.status >= 500 or f.status >= 500:
                    stable = False
                    break
                hit, ratios = boolean_oracle(base.text, t.text, f.text, true_p, false_p)
                if not hit:
                    stable = False
                    break
            if stable and ratios:
                r_true, r_false, r_tf = ratios
                detail = (
                    f"Deterministic boolean oracle ({label}) over {repeats} repeats:\n"
                    f"  TRUE  payload: {true_p}\n"
                    f"  FALSE payload: {false_p}\n"
                    f"  true-vs-false similarity:    {r_tf:.3f} (consistently differ)\n"
                    f"  true-vs-baseline similarity: {r_true:.3f} (consistently normal)\n"
                    f"  false-vs-baseline similarity:{r_false:.3f} (consistently suppressed)"
                )
                req = (f"{probe.method} {probe.url}  (param '{param}')\n"
                       f"TRUE:  {urlencode(probe.inject(param, true_p))}\n"
                       f"FALSE: {urlencode(probe.inject(param, false_p))}")
                return VerifyResult(True, attempted=True, payload=true_p,
                                    url=probe.url, request_desc=req, dom_snippet=detail)
        return None

    # ── error-based ──────────────────────────────────────────────────────────
    async def _verify_error(self, http, probe, param, value, base, repeats) -> VerifyResult | None:
        for label, payload in sqli_error_payloads(value):
            sig = ""
            stable = True
            for _ in range(repeats):
                try:
                    r = await http.send(probe.method, probe.url, probe.inject(param, payload))
                except Exception:
                    stable = False
                    break
                found = find_error_signature(r.text, base.text)
                if not found or (sig and found != sig):
                    stable = False
                    break
                sig = found
            if stable and sig:
                detail = (
                    f"Deterministic DB error ({label}) over {repeats} repeats:\n"
                    f"  payload: {payload}\n"
                    f"  error signature (every time, absent from baseline): '{sig}'"
                )
                req = f"{probe.method} {probe.url}  (param '{param}')\n{urlencode(probe.inject(param, payload))}"
                return VerifyResult(True, attempted=True, payload=payload,
                                    url=probe.url, request_desc=req, dom_snippet=detail)
        return None

    # ── time-based ─────────────────────────────────────────────────────────────
    async def _verify_time(self, http, probe, param, value, base) -> VerifyResult | None:
        if base.elapsed_ms > _TIME_SHORT * 1000 * 0.8:
            return None  # endpoint not reliably fast enough to measure a 1s delta
        # Each dialect uses the same payload shape with different delays; confirm the
        # response time scales with the requested delay.
        labels = [lbl for lbl, _ in sqli_time_payloads(value, _TIME_SHORT)]
        for label in labels:
            short_p = _payload_for(value, _TIME_SHORT, label)
            long_p = _payload_for(value, _TIME_LONG, label)
            try:
                rs = await http.send(probe.method, probe.url, probe.inject(param, short_p))
                rl = await http.send(probe.method, probe.url, probe.inject(param, long_p))
            except Exception:
                continue
            short_ok = rs.elapsed_ms >= _TIME_SHORT * 1000 * _TIME_RATIO
            long_ok = rl.elapsed_ms >= _TIME_LONG * 1000 * _TIME_RATIO
            scales = (rl.elapsed_ms - rs.elapsed_ms) >= (_TIME_LONG - _TIME_SHORT) * 1000 * _TIME_RATIO
            if short_ok and long_ok and scales:
                detail = (
                    f"Response time scales with the injected delay ({label}):\n"
                    f"  baseline:          {base.elapsed_ms:.0f} ms\n"
                    f"  inject SLEEP({_TIME_SHORT}): {rs.elapsed_ms:.0f} ms\n"
                    f"  inject SLEEP({_TIME_LONG}): {rl.elapsed_ms:.0f} ms\n"
                    f"  delta ~{(rl.elapsed_ms - rs.elapsed_ms) / 1000:.1f}s for a "
                    f"{_TIME_LONG - _TIME_SHORT}s increase — the DB ran the sleep"
                )
                req = (f"{probe.method} {probe.url}  (param '{param}')\n"
                       f"SLEEP({_TIME_SHORT}): {urlencode(probe.inject(param, short_p))}\n"
                       f"SLEEP({_TIME_LONG}): {urlencode(probe.inject(param, long_p))}")
                return VerifyResult(True, attempted=True, payload=long_p,
                                    url=probe.url, request_desc=req, dom_snippet=detail)
        return None


def _payload_for(value: str, delay: int, label: str) -> str:
    """The time payload for a given dialect label at a given delay."""
    for lbl, payload in sqli_time_payloads(value, delay):
        if lbl == label:
            return payload
    return ""
