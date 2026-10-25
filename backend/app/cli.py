"""
ProofStrike CLI — run a full verification-first scan from the terminal, no dashboard.

    python -m proofstrike scan https://target.example
    python -m proofstrike scan https://target.example \
        --detectors xss,sqli,idor,passive --depth 3 --max-requests 150 \
        --report-dir ./out --formats json,html,pdf --fail-on high

It reuses the exact scan pipeline the API server runs (crawl -> detect -> verify),
writes findings to an isolated SQLite database (a throwaway temp file by default, so
your real proofstrike.db is never touched), prints a summary, exports reports, and
sets an exit code for CI:

    0  clean — no confirmed finding at or above --fail-on
    1  confirmed finding(s) meet the --fail-on threshold
    2  the scan could not complete (unreachable target, crash, bad usage)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import tempfile
from pathlib import Path

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_DEFAULT_DETECTORS = "xss,sqli,idor,passive"

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="proofstrike", description="Verification-first web scanner")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="crawl, detect, and verify a target")
    s.add_argument("url", nargs="?", help="target base URL (or supply target.base_url via --config)")
    s.add_argument("--depth", "--max-depth", type=int, dest="depth", help="max crawl depth")
    s.add_argument("--max-requests", "--budget", type=int, dest="budget", help="max pages to crawl")
    s.add_argument("--detectors", default=_DEFAULT_DETECTORS,
                   help=f"comma list (default: {_DEFAULT_DETECTORS})")
    s.add_argument("--request-delay", type=float, default=None, help="seconds between requests")
    s.add_argument("--max-concurrency", type=int, default=None, help="concurrent requests")
    s.add_argument("--no-sitemap", action="store_true", help="skip robots.txt / sitemap.xml seeding")
    s.add_argument("--report-dir", default="./proofstrike-reports", help="where to write reports")
    s.add_argument("--formats", default="json,html", help="report formats: json,html,pdf")
    s.add_argument("--fail-on", default="high",
                   choices=["critical", "high", "medium", "low", "info", "none"],
                   help="exit 1 if a confirmed finding is at/above this severity (default: high)")
    s.add_argument("--db", default=None,
                   help="SQLite path for scan data (default: a throwaway temp file)")
    s.add_argument("--config", default=None,
                   help="JSON file with optional 'auth' (login/second_user) and 'scan' config")
    s.add_argument("-q", "--quiet", action="store_true", help="only print the summary")
    return p


def _load_config(path: str | None) -> dict:
    if not path:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("--config must be a JSON object")
    return data


def _scan_config(args, file_cfg: dict) -> dict:
    cfg = dict(file_cfg.get("scan") or {})
    cfg["detectors"] = [d.strip() for d in args.detectors.split(",") if d.strip()]
    if args.depth is not None:
        cfg["max_depth"] = args.depth
    if args.budget is not None:
        cfg["max_pages"] = args.budget
    if args.request_delay is not None:
        cfg["request_delay"] = args.request_delay
    if args.max_concurrency is not None:
        cfg["max_concurrency"] = args.max_concurrency
    if args.no_sitemap:
        cfg["use_sitemap"] = False
    return cfg


async def _run_scan(args) -> int:
    file_cfg = _load_config(args.config)
    auth_cfg = file_cfg.get("auth")
    target_url = args.url or (file_cfg.get("target") or {}).get("base_url")
    if not target_url:
        print("error: provide a target URL (positional) or target.base_url in --config",
              file=sys.stderr)
        return EXIT_ERROR

    # Isolated database — a throwaway temp file unless --db is given, so the user's
    # real proofstrike.db is never touched.
    tmp_db = None
    if args.db:
        db_path = os.path.abspath(args.db)
    else:
        fd, tmp_db = tempfile.mkstemp(suffix=".db", prefix="proofstrike-cli-")
        os.close(fd)
        db_path = tmp_db
    db_url = f"sqlite+aiosqlite:///{db_path.replace(os.sep, '/')}"

    # Build an engine bound to THIS loop (async connections are loop-bound).
    from sqlalchemy.ext.asyncio import create_async_engine
    from app.database import Base, make_session_factory
    import app.models  # noqa: F401  (register all tables on Base.metadata)
    from app.models.target import Target
    from app.models.scan import Scan, ScanStatus
    from app.models.finding import Finding
    from app.engine.pipeline import ScanPipeline
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    engine = create_async_engine(db_url, connect_args={"timeout": 30})
    session_factory = make_session_factory(engine)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with session_factory() as db:
            target = Target(name=target_url, base_url=target_url, auth_config=auth_cfg)
            db.add(target)
            await db.flush()
            scan = Scan(target_id=target.id, status=ScanStatus.QUEUED.value,
                        config=_scan_config(args, file_cfg))
            db.add(scan)
            await db.commit()
            scan_id, target_id = scan.id, target.id

        print(f"Scanning {target_url}  (scan {scan_id[:8]}, db {db_path})", file=sys.stderr)
        await ScanPipeline(scan_id, session_factory).run()

        async with session_factory() as db:
            scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            target = (await db.execute(select(Target).where(Target.id == target_id))).scalar_one()
            findings = (await db.execute(
                select(Finding).options(selectinload(Finding.evidence_items))
                .where(Finding.scan_id == scan_id).order_by(Finding.created_at)
            )).scalars().all()

        report_paths = await _write_reports(args, scan, findings, target)
        return _summarize(scan, findings, report_paths, args.fail_on)
    finally:
        await engine.dispose()
        if tmp_db and os.path.exists(tmp_db):
            try:
                os.unlink(tmp_db)
            except OSError:
                pass


async def _write_reports(args, scan, findings, target) -> list[str]:
    from app.services import report_service
    formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    out_dir = Path(args.report_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"proofstrike-report-{scan.id[:8]}"
    report = report_service.build_report(scan, findings, target)
    written: list[str] = []

    if "json" in formats:
        path = out_dir / f"{stem}.json"
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        written.append(str(path))

    html_doc = report_service.render_html(report) if {"html", "pdf"} & set(formats) else None
    if "html" in formats:
        path = out_dir / f"{stem}.html"
        path.write_text(html_doc, encoding="utf-8")
        written.append(str(path))
    if "pdf" in formats:
        try:
            pdf = await report_service.render_pdf_async(html_doc)
            path = out_dir / f"{stem}.pdf"
            path.write_bytes(pdf)
            written.append(str(path))
        except Exception as e:
            print(f"warning: PDF export failed ({type(e).__name__}: {e}); "
                  f"run 'python -m playwright install chromium'", file=sys.stderr)
    return written


def _summarize(scan, findings, report_paths, fail_on) -> int:
    confirmed = [f for f in findings if f.status == "confirmed"]
    candidates = [f for f in findings if f.status == "candidate"]
    rejected = [f for f in findings if f.status in ("rejected", "false_positive")]
    stats = scan.stats or {}

    print("\n" + "=" * 64)
    print(f"ProofStrike scan {scan.id[:8]} - {scan.status}")
    dur = stats.get("duration_seconds")
    print(f"  endpoints: {stats.get('endpoints_found', '?')}   "
          f"confirmed: {len(confirmed)}   candidates: {len(candidates)}   "
          f"rejected: {len(rejected)}" + (f"   ({dur:.1f}s)" if dur else ""))

    if confirmed:
        print("\nConfirmed findings:")
        for f in sorted(confirmed, key=lambda x: -_SEVERITY_RANK.get(x.severity, 0)):
            print(f"  [{(f.severity or '').upper():8}] {f.type:12} {f.title}")
    else:
        print("\nNo confirmed findings.")
    if report_paths:
        print("\nReports:")
        for p in report_paths:
            print(f"  {p}")

    if scan.status not in ("completed", "stopped"):
        errs = (scan.stats or {}).get("errors") or []
        print(f"\nScan did not complete cleanly: {errs[-1] if errs else scan.status}",
              file=sys.stderr)
        return EXIT_ERROR

    if fail_on != "none":
        threshold = _SEVERITY_RANK.get(fail_on, 3)
        worst = [f for f in confirmed if _SEVERITY_RANK.get(f.severity, 0) >= threshold]
        if worst:
            print(f"\nFAIL: {len(worst)} confirmed finding(s) at or above '{fail_on}'.")
            return EXIT_FINDINGS
    print("\nPASS: no confirmed finding meets the fail-on threshold.")
    return EXIT_CLEAN


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.WARNING if getattr(args, "quiet", False) else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr,
    )
    if args.command == "scan":
        try:
            return asyncio.run(_run_scan(args))
        except KeyboardInterrupt:
            print("interrupted", file=sys.stderr)
            return EXIT_ERROR
        except Exception as e:
            logging.getLogger("proofstrike.cli").error("scan failed: %s", e, exc_info=True)
            return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
