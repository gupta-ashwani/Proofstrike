"""
SQL-injection detector — boolean (blind) technique.

Many injectable parameters never echo a database error and never reflect input,
so error-string matching misses them. The boolean technique instead proves the
database is *evaluating* attacker-controlled logic: we send two requests that are
identical except that one carries a condition that is always TRUE and the other a
condition that is always FALSE.

  - In a vulnerable query the condition is folded into the SQL, so the TRUE request
    returns the normal result set (looks like the untouched request) while the
    FALSE request suppresses it — the two responses differ in a structured way.
  - In a safe (parameterised) query both payloads are treated as literal data, so
    both responses are identical and nothing is raised.

Detection only shows the difference exists. The verifier re-runs the pair several
times and confirms the split is *deterministic* (not page noise) before a finding
is confirmed.
"""

from __future__ import annotations

import difflib
import logging
from urllib.parse import urlparse

from app.engine.detect.base import Candidate, DetectorHttp, EndpointProbe, build_curl
from app.engine.detect.payloads import (
    SQL_ERROR_SIGNATURES,
    sqli_boolean_pairs,
    sqli_error_payloads,
    sqli_time_payloads,
)

logger = logging.getLogger("proofstrike.detect.sqli")

# Body size cap for similarity comparison (HTML tails rarely change the verdict).
_MAX_CMP = 20_000

# Oracle thresholds (ratios are difflib similarity, 0..1):
#   TRUE vs FALSE must differ, TRUE must look like the untouched request, and
#   TRUE must be meaningfully closer to the baseline than FALSE is.
_TF_MAX = 0.95      # true vs false: below this they are "different"
_TRUE_MIN = 0.90    # true vs baseline: above this true "looks normal"
_MARGIN = 0.05      # how much closer true must be to baseline than false

# Time-based: inject this many seconds; the endpoint must normally respond in well
# under it, and the injected request must be slow by at least DELAY*RATIO.
TIME_DELAY = 3
_TIME_RATIO = 0.6


def find_error_signature(text: str, baseline_text: str) -> str:
    """Return the first DBMS error fragment present in `text` but not in the baseline."""
    low = text.lower()
    base_low = baseline_text.lower()
    for sig in SQL_ERROR_SIGNATURES:
        if sig in low and sig not in base_low:
            return sig
    return ""

REMEDIATION = (
    "Use parameterised queries / prepared statements so untrusted input is always "
    "treated as data, never concatenated into SQL. Apply least-privilege database "
    "accounts and validate/allow-list inputs as defence in depth. Object-relational "
    "mappers parameterise by default — avoid raw string-built queries."
)


def _norm(text: str, *strip: str) -> str:
    """Trim to a cap, remove the given substrings (e.g. the reflected payload), and
    collapse whitespace so cosmetic differences don't drive the comparison."""
    t = text[:_MAX_CMP]
    for s in strip:
        if s:
            t = t.replace(s, "")
    return " ".join(t.split())


def _ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def _strip_common_framing(*strings: str) -> list[str]:
    """
    Remove the longest prefix and suffix shared by *all* the given strings.

    Pages are mostly shared chrome (header, nav, footer) with a small body that
    actually changes. On a heavily-framed page the boolean difference — a row vs an
    empty result — can be only a few percent of the bytes, so a whole-page
    similarity ratio sits right on the threshold and the injection is missed. By
    discarding the identical framing first, the ratios reflect the part that really
    varies, while responses that are genuinely identical reduce to empty cores and
    still compare as identical (so safe/parameterised endpoints stay clean).
    """
    if not strings:
        return []
    shortest = min(strings, key=len)
    pre = 0
    for i, ch in enumerate(shortest):
        if any(s[i] != ch for s in strings):
            break
        pre = i + 1
    suf = 0
    limit = len(shortest) - pre
    for i in range(1, limit + 1):
        ch = shortest[-i]
        if any(s[-i] != ch for s in strings):
            break
        suf = i
    return [s[pre: len(s) - suf] if suf else s[pre:] for s in strings]


def boolean_oracle(
    base_text: str, true_text: str, false_text: str,
    true_payload: str, false_payload: str,
) -> tuple[bool, tuple[float, float, float]]:
    """
    Decide whether (base, true, false) show the boolean-SQLi signature.

    The injected payload is stripped from each variant first, so a parameter that
    merely *reflects* its input (same structural page, different echoed text) does
    not look like a data-set change. The framing shared by all three responses (the
    page's static chrome) is then removed so the comparison focuses on the body that
    actually varies — otherwise the signal is swamped on heavily-templated pages.
    """
    b, t, f = _strip_common_framing(
        _norm(base_text),
        _norm(true_text, true_payload),
        _norm(false_text, false_payload),
    )
    r_true = _ratio(b, t)    # TRUE vs untouched request
    r_false = _ratio(b, f)   # FALSE vs untouched request
    r_tf = _ratio(t, f)      # TRUE vs FALSE
    hit = (r_tf < _TF_MAX) and (r_true >= _TRUE_MIN) and (r_true - r_false > _MARGIN)
    return hit, (r_true, r_false, r_tf)


class SqliDetector:
    name = "sqli"
    severity = "high"

    async def detect(self, probe: EndpointProbe, http: DetectorHttp) -> list[Candidate]:
        candidates: list[Candidate] = []
        for param in probe.testable_params:
            value = probe.baseline.get(param, "")
            try:
                base = await http.send(probe.method, probe.url, probe.baseline)
            except Exception as e:
                logger.debug("SQLi baseline failed for %s?%s: %s", probe.url, param, e)
                continue

            # Try techniques cheapest/strongest first; one candidate per param is enough.
            cand = (
                await self._boolean(probe, http, param, value, base)
                or await self._error(probe, http, param, value, base)
                or await self._time(probe, http, param, value, base)
            )
            if cand:
                candidates.append(cand)
        return candidates

    # ── boolean-blind ─────────────────────────────────────────────────────
    async def _boolean(self, probe, http, param, value, base) -> Candidate | None:
        for label, true_p, false_p in sqli_boolean_pairs(value):
            try:
                t = await http.send(probe.method, probe.url, probe.inject(param, true_p))
                f = await http.send(probe.method, probe.url, probe.inject(param, false_p))
            except Exception as e:
                logger.debug("SQLi boolean probe failed %s?%s (%s): %s", probe.url, param, label, e)
                continue
            # A 5xx on only one variant is error-based noise, not a clean boolean split.
            if t.status >= 500 or f.status >= 500:
                continue
            hit, (r_true, r_false, r_tf) = boolean_oracle(base.text, t.text, f.text, true_p, false_p)
            if hit:
                return self._candidate(
                    probe, param, payload=true_p, technique="boolean-blind",
                    title_tech="boolean-blind",
                    detail=(f"A TRUE condition returns the normal response while a FALSE "
                            f"condition suppresses it ({label} context), so the database is "
                            f"evaluating injected SQL rather than treating the value as data."),
                    evidence_note=(
                        f"Boolean oracle ({label}):\n"
                        f"  TRUE  payload: {true_p}\n"
                        f"  FALSE payload: {false_p}\n"
                        f"  similarity true-vs-false: {r_tf:.3f} (differ)\n"
                        f"  similarity true-vs-baseline: {r_true:.3f} (looks normal)\n"
                        f"  similarity false-vs-baseline: {r_false:.3f} (suppressed)\n"
                        f"  response sizes  baseline={len(base.text)}  "
                        f"true={len(t.text)}  false={len(f.text)} bytes"),
                )
        return None

    # ── error-based ────────────────────────────────────────────────────────
    async def _error(self, probe, http, param, value, base) -> Candidate | None:
        for label, payload in sqli_error_payloads(value):
            try:
                r = await http.send(probe.method, probe.url, probe.inject(param, payload))
            except Exception as e:
                logger.debug("SQLi error probe failed %s?%s (%s): %s", probe.url, param, label, e)
                continue
            sig = find_error_signature(r.text, base.text)
            if sig:
                return self._candidate(
                    probe, param, payload=payload, technique="error-based",
                    title_tech="error-based",
                    detail=(f"Injecting an unbalanced {label} made the server return a "
                            f"database error ('{sig}'), which means the input reached the SQL "
                            f"engine verbatim. The error itself is not in the normal response."),
                    evidence_note=(
                        f"Error-based ({label}):\n"
                        f"  payload: {payload}\n"
                        f"  DB error signature matched: '{sig}'\n"
                        f"  response snippet:\n...{self._snippet(r.text, sig)}..."),
                )
        return None

    # ── time-based (fully blind) ─────────────────────────────────────────────
    async def _time(self, probe, http, param, value, base) -> Candidate | None:
        delay_ms = TIME_DELAY * 1000
        # Only worth trying if the endpoint is normally much faster than the delay.
        if base.elapsed_ms > delay_ms * 0.5:
            return None
        for label, payload in sqli_time_payloads(value, TIME_DELAY):
            try:
                r = await http.send(probe.method, probe.url, probe.inject(param, payload))
            except Exception as e:
                logger.debug("SQLi time probe failed %s?%s (%s): %s", probe.url, param, label, e)
                continue
            if r.elapsed_ms >= delay_ms * _TIME_RATIO and \
               r.elapsed_ms >= base.elapsed_ms + delay_ms * _TIME_RATIO:
                return self._candidate(
                    probe, param, payload=payload, technique="time-based",
                    title_tech="time-based blind",
                    detail=(f"Injecting a {TIME_DELAY}s conditional sleep ({label}) delayed the "
                            f"response from {base.elapsed_ms:.0f}ms to {r.elapsed_ms:.0f}ms, with "
                            f"identical content — the database executed the injected sleep. This "
                            f"is a fully-blind injection (no visible output or error)."),
                    evidence_note=(
                        f"Time-based ({label}):\n"
                        f"  payload: {payload}\n"
                        f"  baseline response: {base.elapsed_ms:.0f} ms\n"
                        f"  injected response: {r.elapsed_ms:.0f} ms (delay ~{TIME_DELAY}s requested)"),
                )
        return None

    # ── shared ───────────────────────────────────────────────────────────────
    def _candidate(self, probe, param, *, payload, technique, title_tech,
                   detail, evidence_note) -> Candidate:
        path = urlparse(probe.url).path or "/"
        return Candidate(
            type="sqli",
            severity=self.severity,
            param=param,
            payload=payload,
            title=f"SQL injection ({title_tech}) in '{param}' ({path})",
            description=(
                f"The '{param}' parameter of {probe.method} {path} appears to be "
                f"injectable ({technique}). {detail} Verification re-runs the probe to "
                f"confirm the behaviour is deterministic."
            ),
            remediation=REMEDIATION,
            technique=technique,
            evidence=[
                ("curl", build_curl(probe.method, probe.url,
                                    probe.inject(param, payload), probe.auth_required)),
                ("response", evidence_note),
            ],
        )

    @staticmethod
    def _snippet(text: str, needle: str, pad: int = 120) -> str:
        low = text.lower()
        idx = low.find(needle.lower())
        if idx < 0:
            return text[:400]
        return text[max(0, idx - pad): idx + len(needle) + pad]
