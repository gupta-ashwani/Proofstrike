"""
Second-order SQLi verifier.

Confirms deterministically that a stored value reaches a SQL query on the sink page:
store a benign value → the sink must be error-free; store a value with a quote → the
sink must raise the *same* DB error every time, and our marker must be present. The
error tracking the stored input (and not appearing for a benign value) is the proof.
"""

from __future__ import annotations

import logging
import secrets

from app.engine.detect.base import DetectorHttp, EndpointProbe
from app.engine.detect.payloads import (
    SECOND_ORDER_SQLI_PREFIX,
    stored_sqli_payload,
    stored_sqli_signal,
)
from app.engine.detect.payloads import SQL_ERROR_SIGNATURES
from app.engine.verify.xss_verifier import VerifyResult

logger = logging.getLogger("proofstrike.verify.stored_sqli")

DEFAULT_REPEATS = 2
_WINDOW = 300  # chars after our marker to scan for the error it caused


def _marker_errors(text: str, signal: str) -> str:
    """Return a DB-error signature that appears right after our marker, else ''.

    Localising the error to *our* freshly-stored token makes verification robust to
    other values already stored on the sink (state persists across detect + verify)."""
    idx = text.find(signal)
    if idx < 0:
        return ""
    window = text[idx: idx + len(signal) + _WINDOW].lower()
    return next((s for s in SQL_ERROR_SIGNATURES if s in window), "")


class StoredSqliVerifier:
    async def verify_stored(self, http: DetectorHttp, inject_probe: EndpointProbe,
                            param: str, sink_url: str,
                            repeats: int = DEFAULT_REPEATS) -> VerifyResult:
        confirmed_sig = None
        for _ in range(repeats):
            # A breaking value (quote) and a benign value, each with a unique marker.
            bad, good = secrets.token_hex(5), secrets.token_hex(5)
            try:
                await http.send(inject_probe.method, inject_probe.url,
                                inject_probe.inject(param, stored_sqli_payload(bad)))
                await http.send(inject_probe.method, inject_probe.url,
                                inject_probe.inject(param, f"{SECOND_ORDER_SQLI_PREFIX}{good}"))
                r = await http.send("GET", sink_url, None)
            except Exception as e:
                logger.debug("Stored SQLi verify request failed: %s", e)
                return VerifyResult(False, attempted=False,
                                    note="could not reach the endpoints to verify; try manually")
            bad_sig = _marker_errors(r.text, stored_sqli_signal(bad))
            good_sig = _marker_errors(r.text, stored_sqli_signal(good))
            if not bad_sig:
                return VerifyResult(False, attempted=True,
                                    note="the stored breaking value did not raise a DB error on the sink")
            if good_sig:
                return VerifyResult(False, attempted=True,
                                    note="the sink errors even for a benign stored value — not attributable")
            if confirmed_sig and bad_sig != confirmed_sig:
                return VerifyResult(False, attempted=True, note="the DB error was not consistent")
            confirmed_sig = bad_sig

        detail = (
            f"Second-order SQLi confirmed over {repeats} repeats:\n"
            f"  a stored value containing a quote raised '{confirmed_sig}' at its entry on {sink_url},\n"
            f"  while a benign stored value at the same sink did not — the stored input reaches SQL there."
        )
        return VerifyResult(True, attempted=True, payload="(stored value containing a quote)",
                            url=sink_url, dom_snippet=detail,
                            request_desc=f"store at {inject_probe.method} {inject_probe.url} "
                                         f"-> SQL error at GET {sink_url}")
