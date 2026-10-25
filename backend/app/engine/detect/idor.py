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


def _is_reference_name(name: str) -> bool:
    """A parameter name that denotes an object reference (so worth an access-control look)."""
    low = name.lower()
    if low == "id":
        return False  # precision-first default (public catalogues key on bare id)
    if low in _REFERENCE_NAMES:
        return True
    return low.endswith("id") or low.endswith("_no")


def _is_reference(name: str, value: str) -> bool:
    """A param worth the single-session ENUMERATION test: an *integer* object identifier."""
    if not _INT_RE.match(str(value or "")):
        return False
    return _is_reference_name(name)


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


# ── cross-session (two-user) IDOR ────────────────────────────────────────────
# A direct access-control proof: if User B, using B's own session, can fetch the
# object that belongs to User A (A's identifier returns A's content to B), the
# endpoint is missing an ownership check. Needs two authenticated sessions.

_CROSS_MIN = 0.90       # B's view of A's object must be ~identical to A's own view
_DENY_HINTS = (
    "login", "log in", "sign in", "signin", "access denied", "forbidden",
    "unauthorized", "unauthorised", "not authorized", "not allowed",
    "permission denied", "please authenticate", "403", "401",
)

CROSS_REMEDIATION = (
    "Scope every object lookup to the authenticated principal: resolve the owner from "
    "the session, not from a client-supplied identifier, and reject (404/403) when the "
    "requested object is not owned by (or shared with) the caller. Add server-side "
    "authorization checks on every read and write, and cover them with tests."
)


def _looks_denied(text: str) -> bool:
    low = text[:_MAX_CMP].lower()
    return any(h in low for h in _DENY_HINTS)


def cross_session_oracle(
    a_text: str, b_text: str, b_status: int, value: str,
) -> tuple[bool, float]:
    """
    Decide whether User B received User A's object.

    `a_text` is A's own response for A's identifier; `b_text` is B's response to the
    *same* request (B's session, A's identifier). A hit means B got a successful,
    non-denial page essentially identical to A's — i.e. B read A's data.
    Returns (hit, similarity).
    """
    if b_status != 200 or _looks_denied(b_text):
        return False, 0.0
    a = _norm(a_text, value)
    b = _norm(b_text, value)
    sim = _ratio(a, b)
    return sim >= _CROSS_MIN, sim


class CrossSessionIdorDetector:
    """Batch pass: replay each reference-param endpoint under a second user's session."""

    name = "idor"
    severity = "high"  # unauthorized cross-user data access outranks mere enumeration

    async def detect_all(self, probes, http_a, http_b) -> list:
        """Return [(probe, Candidate)] for endpoints where B could read A's object."""
        found = []
        for probe in probes:
            for param in probe.testable_params:
                value = probe.baseline.get(param, "")
                if not value or not _is_reference_name(param):
                    continue
                try:
                    a = await http_a.send(probe.method, probe.url, probe.baseline)
                    b = await http_b.send(probe.method, probe.url, probe.baseline)
                except Exception as e:
                    logger.debug("Cross-session IDOR probe failed %s?%s: %s", probe.url, param, e)
                    continue
                if a.status != 200 or len(a.text) < _MIN_BODY:
                    continue
                hit, sim = cross_session_oracle(a.text, b.text, b.status, value)
                if hit:
                    found.append((probe, self._candidate(probe, param, value, sim,
                                                          len(a.text), len(b.text))))
                    break  # one candidate per endpoint is enough
        return found

    def _candidate(self, probe, param, value, sim, a_len, b_len) -> Candidate:
        path = urlparse(probe.url).path or "/"
        return Candidate(
            type="idor",
            severity=self.severity,
            param=param,
            payload=value,
            title=f"Broken access control (cross-user) in '{param}' ({path})",
            description=(
                f"A second authenticated user requested {probe.method} {path} with another "
                f"user's '{param}' value ('{value}') and received that user's object "
                f"(response similarity {sim:.3f}, not an access-denied page). The endpoint "
                f"does not check that the caller owns the requested object, so any logged-in "
                f"user can read another's data. Verification re-runs both sessions to confirm "
                f"the cross-user access is reproducible."
            ),
            remediation=CROSS_REMEDIATION,
            technique="cross-session",
            evidence=[
                ("curl", build_curl(probe.method, probe.url, probe.baseline, auth_required=True)),
                ("response",
                 f"Cross-user access on '{param}':\n"
                 f"  identifier (owned by user A): {value}\n"
                 f"  user A's own response:  {a_len} bytes\n"
                 f"  user B's response to A's id: {b_len} bytes, HTTP 200, not a denial\n"
                 f"  A-vs-B similarity: {sim:.3f} (B received A's object)"),
            ],
        )


# ── function-level access control: missing auth + privilege escalation ───────
# Same engine as cross-session IDOR, but the "attacker" is a session that should
# have NO access to the endpoint at all:
#   - anonymous  → the endpoint requires login yet serves content without a session
#                  (missing authentication / auth bypass)
#   - lower-priv → a privileged-looking endpoint serves its content to an ordinary
#                  user (broken function-level authorization / privilege escalation)

_PRIVILEGED_HINTS = (
    "admin", "manage", "internal", "console", "staff", "superuser",
    "/config", "/settings", "/root", "/mod", "privileged",
)

ACCESS_REMEDIATION = (
    "Enforce authentication and role/permission checks server-side on every request, "
    "including APIs and XHR endpoints — not just the HTML pages that link to them. Deny "
    "by default and verify the caller's identity and role before returning data."
)


def _looks_privileged(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return any(h in path for h in _PRIVILEGED_HINTS)


def access_oracle(owner_text: str, owner_status: int,
                  attacker_text: str, attacker_status: int) -> tuple[bool, float]:
    """Owner must return real content; attacker (who shouldn't) must get ~the same page."""
    if owner_status != 200 or len(owner_text) < _MIN_BODY:
        return False, 0.0
    return cross_session_oracle(owner_text, attacker_text, attacker_status, "")


class AccessControlDetector:
    """Batch pass: can a no-access session reach a protected endpoint's content?"""

    name = "auth_bypass"

    async def detect_all(self, probes, http_auth, http_anon=None, http_b=None) -> list:
        found = []
        for probe in probes:
            try:
                owner = await http_auth.send(probe.method, probe.url, probe.baseline)
            except Exception as e:
                logger.debug("Access-control owner fetch failed %s: %s", probe.url, e)
                continue
            if owner.status != 200 or len(owner.text) < _MIN_BODY:
                continue

            # 1) Missing authentication: endpoint needs a login, anon still reads it.
            if probe.auth_required and http_anon is not None:
                try:
                    anon = await http_anon.send(probe.method, probe.url, probe.baseline)
                except Exception:
                    anon = None
                if anon is not None:
                    hit, sim = access_oracle(owner.text, owner.status, anon.text, anon.status)
                    if hit:
                        found.append((probe, self._candidate(
                            probe, kind="unauthenticated-access", sim=sim,
                            title=f"Missing authentication (unauthenticated access) "
                                  f"({urlparse(probe.url).path or '/'})",
                            detail=("This endpoint was reached behind login during the "
                                    "authenticated crawl, yet an anonymous request (no "
                                    "session) returned the same protected content "
                                    f"(similarity {sim:.3f}).")))
                        )
                        continue  # already an auth bypass; no need to also test priv-esc

            # 2) Privilege escalation: privileged-looking endpoint served to a lower user.
            if http_b is not None and _looks_privileged(probe.url):
                try:
                    b = await http_b.send(probe.method, probe.url, probe.baseline)
                except Exception:
                    b = None
                if b is not None:
                    hit, sim = access_oracle(owner.text, owner.status, b.text, b.status)
                    if hit:
                        found.append((probe, self._candidate(
                            probe, kind="privilege-escalation", sim=sim,
                            title=f"Broken function-level authorization "
                                  f"({urlparse(probe.url).path or '/'})",
                            detail=("This privileged-looking endpoint returned its content "
                                    "to a second, lower-privilege user session "
                                    f"(similarity {sim:.3f}) — no role/permission check.")))
                        )
        return found

    def _candidate(self, probe, *, kind, sim, title, detail) -> Candidate:
        return Candidate(
            type="auth_bypass",
            severity="high",
            param="",
            payload="(no payload — the request itself is unauthorized)",
            title=title,
            description=(f"{detail} Verification re-issues the request from the "
                         f"unauthorized session to confirm the access is reproducible."),
            remediation=ACCESS_REMEDIATION,
            technique=kind,
            evidence=[
                ("curl", build_curl(probe.method, probe.url, probe.baseline, auth_required=False)),
                ("response",
                 f"Access-control check ({kind}):\n"
                 f"  endpoint: {probe.method} {probe.url}\n"
                 f"  an unauthorized session received the protected content "
                 f"(similarity {sim:.3f}, HTTP 200, not a denial page)"),
            ],
        )
