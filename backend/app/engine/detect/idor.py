"""
IDOR detector — insecure direct object reference via identifier enumeration.

An IDOR exists when a request selects a back-end object straight from an
attacker-controlled identifier (``/account?acct=1001``) with no check that the
caller is allowed that object. The tell is behavioural, not textual:

  - the identifier directly indexes a record, so *neighbouring* identifiers return
    **distinct but same-shaped** objects (same page template, different data);
  - an *out-of-range* identifier is rejected (a "not found" / denial page, or a
    non-200), which proves the endpoint is really doing a per-record lookup rather
    than returning one page for everything.

A safe endpoint that enforces ownership returns the *same* object (or a denial)
whatever identifier you pass, so neighbours are identical to the baseline and
nothing is raised.

Scope note: this is a precision-first default. Bare ``id`` parameters are **not**
treated as object references, because public catalogues (``/product?id=``) key on
``id`` and would otherwise flag as medium-severity IDOR on every scan. Named
references (``acct``, ``user``, ``doc``, ``order``…) and ``*_id`` / ``*id`` names
are tested. Detection only shows the enumeration signal exists; the verifier
re-runs it and confirms the behaviour is deterministic before anything is confirmed.
"""

from __future__ import annotations

import difflib
import logging
import re
from urllib.parse import urlparse

from app.engine.detect.base import Candidate, DetectorHttp, EndpointProbe, build_curl

logger = logging.getLogger("proofstrike.detect.idor")

_INT_RE = re.compile(r"^-?\d+$")

# Parameter names that denote an object reference (besides the generic *_id / *id
# suffix rule below). Bare "id" is deliberately excluded — see the module docstring.
_REFERENCE_NAMES = {
    "uid", "user", "username", "account", "acct", "customer", "custid", "cust",
    "member", "owner", "order", "invoice", "profile", "doc", "document", "file",
    "record", "msg", "message", "ticket", "oid", "object", "objectid", "ref", "no",
}

# Body-comparison tuning (ratios are difflib similarity, 0..1).
_MAX_CMP = 20_000
_MIN_BODY = 64        # baseline must carry real content to be a "record page"
_STRUCT_MIN = 0.55    # a neighbour shares the baseline's template…
_DISTINCT_MAX = 0.985 # …but differs enough to be a *different* record
_ABSENT_MARGIN = 0.04 # a neighbour must look more baseline-like than an absent id

REMEDIATION = (
    "Enforce an authorisation check on every object access: confirm the current "
    "session owns (or may view) the requested object before returning it, server-side, "
    "on every request. Do not rely on unguessable identifiers alone. Prefer indirect "
    "references (per-session object maps) or scoped queries (…WHERE id = ? AND owner = "
    "current_user) so an identifier can never reach another tenant's data."
)


def _is_reference(name: str, value: str) -> bool:
    """A param worth testing for IDOR: an enumerable (integer) object identifier."""
    if not _INT_RE.match(str(value or "")):
        return False
    low = name.lower()
    if low == "id":
        return False  # precision-first default (public catalogues key on bare id)
    if low in _REFERENCE_NAMES:
        return True
    return low.endswith("id") or low.endswith("_no")


def _neighbors(value: str) -> list[str]:
    """Nearby identifiers to try — small deltas either side of the baseline id."""
    n = int(value)
    out: list[str] = []
    seen: set[int] = set()
    for delta in (1, -1, 2, -2, 3):
        m = n + delta
        if m >= 0 and m != n and m not in seen:
            seen.add(m)
            out.append(str(m))
    return out


def _absent(value: str) -> str:
    """A clearly out-of-range identifier that should not resolve to any record."""
    return str(max(int(value) + 10_000_000, 999_999_999))


def _norm(text: str, *strip: str) -> str:
    """Cap, remove the echoed identifier(s), and collapse whitespace so a page that
    merely echoes the id back isn't mistaken for a different record."""
    t = text[:_MAX_CMP]
    for s in strip:
        if s:
            t = t.replace(s, "")
    return " ".join(t.split())


def _ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def idor_oracle(
    base_text: str, base_val: str,
    nbr_text: str, nbr_val: str, nbr_status: int,
    absent_text: str, absent_val: str, absent_status: int,
) -> tuple[bool, tuple[float, float]]:
    """
    Decide whether (baseline, neighbour, absent) show the IDOR signature.

    Returns (hit, (sim_neighbour_vs_base, sim_absent_vs_base)). A hit requires the
    neighbour to share the template, be a *different* record, and look more like the
    baseline than an out-of-range id does (or the out-of-range id is outright rejected).
    """
    b = _norm(base_text, base_val)
    nb = _norm(nbr_text, nbr_val)
    sim_nb = _ratio(b, nb)
    shares = sim_nb >= _STRUCT_MIN
    distinct = sim_nb < _DISTINCT_MAX

    if absent_status >= 400:
        absent_rejected = True
        sim_abs = 0.0
    else:
        ab = _norm(absent_text, absent_val)
        sim_abs = _ratio(b, ab)
        # the valid neighbour must be meaningfully closer to the baseline than the
        # out-of-range id, AND the neighbour must not just be the "not found" page.
        absent_rejected = (sim_nb - sim_abs) >= _ABSENT_MARGIN and _ratio(nb, ab) < _DISTINCT_MAX

    hit = shares and distinct and absent_rejected and nbr_status == 200
    return hit, (sim_nb, sim_abs)


class IdorDetector:
    name = "idor"
    severity = "medium"

    async def detect(self, probe: EndpointProbe, http: DetectorHttp) -> list[Candidate]:
        candidates: list[Candidate] = []
        for param in probe.testable_params:
            value = probe.baseline.get(param, "")
            if not _is_reference(param, value):
                continue
            try:
                base = await http.send(probe.method, probe.url, probe.baseline)
            except Exception as e:
                logger.debug("IDOR baseline failed for %s?%s: %s", probe.url, param, e)
                continue
            if base.status != 200 or len(base.text) < _MIN_BODY:
                continue

            absent_val = _absent(value)
            try:
                absent = await http.send(probe.method, probe.url, probe.inject(param, absent_val))
            except Exception:
                absent = None
            absent_text = absent.text if absent else ""
            absent_status = absent.status if absent else 0

            cand = await self._enumerate(probe, http, param, value, base,
                                         absent_text, absent_val, absent_status)
            if cand is not None:
                candidates.append(cand)
        return candidates

    async def _enumerate(self, probe, http, param, value, base,
                         absent_text, absent_val, absent_status) -> Candidate | None:
        for nbr_val in _neighbors(value):
            try:
                r = await http.send(probe.method, probe.url, probe.inject(param, nbr_val))
            except Exception as e:
                logger.debug("IDOR neighbour probe failed %s?%s=%s: %s",
                             probe.url, param, nbr_val, e)
                continue
            hit, (sim_nb, sim_abs) = idor_oracle(
                base.text, value, r.text, nbr_val, r.status,
                absent_text, absent_val, absent_status,
            )
            if hit:
                return self._candidate(
                    probe, param, value=value, nbr_val=nbr_val,
                    absent_val=absent_val, absent_status=absent_status,
                    sim_nb=sim_nb, sim_abs=sim_abs,
                    base_len=len(base.text), nbr_len=len(r.text),
                )
        return None

    def _candidate(self, probe, param, *, value, nbr_val, absent_val, absent_status,
                   sim_nb, sim_abs, base_len, nbr_len) -> Candidate:
        path = urlparse(probe.url).path or "/"
        absent_desc = (f"HTTP {absent_status}" if absent_status >= 400
                       else f"a distinct 'not found' page (similarity {sim_abs:.3f})")
        return Candidate(
            type="idor",
            severity=self.severity,
            param=param,
            payload=nbr_val,
            title=f"Insecure direct object reference in '{param}' ({path})",
            description=(
                f"The '{param}' parameter of {probe.method} {path} selects an object "
                f"directly from the supplied identifier with no visible authorisation "
                f"check. Changing it from '{value}' to a neighbour '{nbr_val}' returned a "
                f"different but same-shaped record (template similarity {sim_nb:.3f}), while "
                f"an out-of-range identifier '{absent_val}' was rejected ({absent_desc}). "
                f"That means the identifier indexes records directly — an attacker can "
                f"enumerate other objects. Verification re-runs the enumeration to confirm "
                f"the behaviour is deterministic."
            ),
            remediation=REMEDIATION,
            technique="object-enumeration",
            evidence=[
                ("curl", build_curl(probe.method, probe.url,
                                    probe.inject(param, nbr_val), probe.auth_required)),
                ("response",
                 f"Object enumeration on '{param}':\n"
                 f"  baseline id:   {value}  (record page, {base_len} bytes)\n"
                 f"  neighbour id:  {nbr_val}  (distinct record, {nbr_len} bytes)\n"
                 f"  out-of-range:  {absent_val}  ({absent_desc})\n"
                 f"  similarity neighbour-vs-baseline: {sim_nb:.3f} (same template)\n"
                 f"  similarity absent-vs-baseline:    {sim_abs:.3f} (rejected)"),
            ],
        )
