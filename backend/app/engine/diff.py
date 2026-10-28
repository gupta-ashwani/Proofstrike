"""
Differential engine — compare a completed scan against the target's previous one.

ProofStrike re-runs the same VAPT on a schedule; this turns each run into a delta so
the user sees *what changed*, not the whole list again:

  NEW        confirmed this run, absent last run   (a regression / freshly introduced)
  FIXED      confirmed last run, absent this run    (remediated, or no longer reproducible)
  UNCHANGED  confirmed in both                      (still open)

Only CONFIRMED findings are diffed — the verification-first proof set, never the
rejected/candidate noise.

Fingerprint
-----------
Two findings are "the same issue" when they share a stable fingerprint. Every
detector builds its finding title deterministically from (vuln type, parameter,
URL path, technique) and nothing volatile — payloads, neighbour ids and markers
live in the description, not the title — so `type + normalized(title)` is a stable,
collision-free identity across runs. We hash it to a short hex string for storage.
"""

from __future__ import annotations

import hashlib
import logging
import re

from sqlalchemy import delete, select

from app.models.finding import Finding, FindingStatus
from app.models.scan import Scan, ScanStatus
from app.models.scan_diff import ScanDiff

logger = logging.getLogger("proofstrike.engine.diff")

_WS = re.compile(r"\s+")


def finding_fingerprint(finding: Finding) -> str:
    """Stable identity for a finding across scans (see module docstring)."""
    title = _WS.sub(" ", (finding.title or "").strip().lower())
    basis = f"{(finding.type or '').lower()}::{title}"
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]


def _summarize(finding: Finding) -> dict:
    return {
        "fingerprint": finding_fingerprint(finding),
        "type": finding.type,
        "severity": finding.severity,
        "title": finding.title,
        "finding_id": finding.id,
    }


async def _confirmed_findings(db, scan_id: str) -> list[Finding]:
    result = await db.execute(
        select(Finding).where(
            Finding.scan_id == scan_id,
            Finding.status == FindingStatus.CONFIRMED.value,
        )
    )
    return list(result.scalars().all())


async def _previous_completed_scan(db, scan: Scan) -> Scan | None:
    """The target's most recent scan that completed before `scan` did."""
    conds = [
        Scan.target_id == scan.target_id,
        Scan.id != scan.id,
        Scan.status == ScanStatus.COMPLETED.value,
    ]
    # Only scans finished before this one — a scan that completed later is not a
    # predecessor (matters when an older scan is re-run after newer ones exist).
    if scan.completed_at is not None:
        conds.append(Scan.completed_at < scan.completed_at)
    result = await db.execute(
        select(Scan).where(*conds).order_by(Scan.completed_at.desc()).limit(1)
    )
    return result.scalar_one_or_none()


async def compute_scan_diff(session_factory, scan_id: str) -> ScanDiff | None:
    """
    Compute and persist the diff for a just-completed scan. Idempotent: an existing
    ScanDiff for this scan is replaced (so a re-run recomputes cleanly). Returns the
    stored ScanDiff, or None if the scan is missing / not completed.
    """
    async with session_factory() as db:
        scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
        if not scan or scan.status != ScanStatus.COMPLETED.value:
            return None

        current = {_summarize(f)["fingerprint"]: _summarize(f)
                   for f in await _confirmed_findings(db, scan_id)}

        prev_scan = await _previous_completed_scan(db, scan)
        previous: dict[str, dict] = {}
        if prev_scan:
            previous = {_summarize(f)["fingerprint"]: _summarize(f)
                        for f in await _confirmed_findings(db, prev_scan.id)}

        new_items = [v for k, v in current.items() if k not in previous]
        unchanged_items = [v for k, v in current.items() if k in previous]
        # FIXED comes from the previous scan (it no longer exists this run).
        fixed_items = [v for k, v in previous.items() if k not in current]

        # Replace any prior diff for this scan (idempotent on re-run).
        await db.execute(delete(ScanDiff).where(ScanDiff.scan_id == scan_id))

        diff = ScanDiff(
            scan_id=scan_id,
            target_id=scan.target_id,
            previous_scan_id=prev_scan.id if prev_scan else None,
            is_baseline=prev_scan is None,
            new_count=len(new_items),
            fixed_count=len(fixed_items),
            unchanged_count=len(unchanged_items),
            data={"new": new_items, "fixed": fixed_items, "unchanged": unchanged_items},
        )
        db.add(diff)
        await db.commit()
        await db.refresh(diff)

    logger.info(
        "Diff for scan %s: +%d new / -%d fixed / =%d unchanged%s",
        scan_id[:8], diff.new_count, diff.fixed_count, diff.unchanged_count,
        " (baseline)" if diff.is_baseline else "",
    )
    return diff
