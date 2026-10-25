"""
Report generation (Phase 6) — turn a scan's findings into a shareable report.

Three formats share one data shape (`build_report`):
  - JSON : the raw dict, machine-readable (served directly by the router).
  - HTML : a self-contained, print-friendly document (`render_html`) — all CSS and
           screenshots are inlined, so it opens and prints anywhere with no assets.
  - PDF  : the same HTML rendered by headless Chromium (`render_pdf`). Chromium is
           already a dependency (the verifier uses it), so no extra PDF library or
           native toolchain is needed.

Everything user- or target-derived is HTML-escaped before it reaches the page, so a
stored payload like `<script>…</script>` is shown as text in the report, never run.
Credential values are already masked upstream (never persisted), so nothing secret
reaches here.
"""

from __future__ import annotations

import asyncio
import html
import sys
from datetime import datetime, timezone

# Severity ordering + palette (matches the dashboard design system).
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}
_STATUS_COLOR = {
    "confirmed": "#16a34a",
    "candidate": "#ca8a04",
    "rejected": "#6b7280",
    "false_positive": "#6b7280",
}
_EVIDENCE_LABEL = {
    "screenshot": "Screenshot",
    "request": "Request",
    "response": "Response",
    "curl": "Reproduction (curl)",
    "dom_snapshot": "DOM context",
    "stored_sink": "Stored sink URL",
}


# ── data ─────────────────────────────────────────────────────────────────────
def build_report(scan, findings, target=None) -> dict:
    """Assemble the machine-readable report dict (also the source for HTML/PDF)."""
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan.id,
        "target_id": scan.target_id,
        "target_name": getattr(target, "name", None),
        "target_url": getattr(target, "base_url", None),
        "status": scan.status,
        "started_at": str(scan.started_at) if scan.started_at else None,
        "completed_at": str(scan.completed_at) if scan.completed_at else None,
        "stats": scan.stats or {},
        "findings": [
            {
                "id": f.id,
                "type": f.type,
                "severity": f.severity,
                "status": f.status,
                "title": f.title,
                "description": f.description,
                "reproduction_steps": f.reproduction_steps,
                "remediation": f.remediation,
                "evidence": [
                    {"type": e.type, "content": e.content, "file_path": e.file_path}
                    for e in f.evidence_items
                ],
            }
            for f in findings
        ],
        "total_findings": len(findings),
    }


# ── HTML ───────────────────────────────────────────────────────────────────────
def render_html(report: dict) -> str:
    """Render the report dict as a self-contained, print-ready HTML document."""
    findings = report["findings"]
    by_status: dict[str, list] = {}
    for f in findings:
        by_status.setdefault(f["status"], []).append(f)

    confirmed = by_status.get("confirmed", [])
    candidates = by_status.get("candidate", [])
    rejected = by_status.get("rejected", [])
    false_pos = by_status.get("false_positive", [])

    # Severity breakdown over CONFIRMED findings (what the report is really about).
    sev_counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in confirmed:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1

    parts: list[str] = []
    parts.append(_doc_head())
    parts.append(_cover(report, len(confirmed), len(candidates), len(rejected) + len(false_pos)))
    parts.append(_summary(sev_counts, len(confirmed), len(candidates), len(rejected) + len(false_pos)))

    if confirmed:
        parts.append('<section class="section"><h2>Confirmed findings</h2>')
        for i, f in enumerate(_sort_by_severity(confirmed), 1):
            parts.append(_finding_block(i, f, detailed=True))
        parts.append("</section>")
    else:
        parts.append('<section class="section"><h2>Confirmed findings</h2>'
                     '<p class="muted">No vulnerabilities were confirmed in this scan.</p></section>')

    if candidates:
        parts.append('<section class="section"><h2>Unconfirmed candidates</h2>'
                     '<p class="muted">Detected but not provable automatically '
                     '(e.g. a POST blocked by CSRF/session). Worth a manual check.</p>')
        parts.append(_candidate_table(candidates))
        parts.append("</section>")

    if rejected or false_pos:
        parts.append(
            '<section class="section"><h2>Verification filtering</h2>'
            f'<p class="muted">{len(rejected) + len(false_pos)} candidate(s) were '
            "re-tested and <strong>rejected as false positives</strong> — detected as "
            "possible, but the payload did not actually execute / the behaviour did not "
            "reproduce. They are excluded from the findings above. This is the "
            "verification-first filter that separates proof from noise.</p></section>"
        )

    parts.append(_footer())
    parts.append("</body></html>")
    return "".join(parts)


def _doc_head() -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>ProofStrike Security Report</title><style>"
        ":root{--ink:#111827;--muted:#6b7280;--line:#e5e7eb;--bg:#f9fafb;--accent:#4f46e5}"
        "*{box-sizing:border-box}"
        "body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;"
        "color:var(--ink);margin:0;padding:0;background:#fff;line-height:1.5;font-size:14px}"
        ".page{max-width:900px;margin:0 auto;padding:32px}"
        "h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:28px 0 12px;"
        "padding-bottom:6px;border-bottom:2px solid var(--line)}"
        "h3{font-size:15px;margin:0}"
        ".muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}"
        ".cover{border-bottom:3px solid var(--accent);padding-bottom:20px;margin-bottom:8px}"
        ".brand{color:var(--accent);font-weight:700;letter-spacing:.5px;font-size:13px;text-transform:uppercase}"
        ".meta{display:grid;grid-template-columns:repeat(2,1fr);gap:6px 24px;margin-top:16px;font-size:13px}"
        ".meta div span{color:var(--muted);display:inline-block;min-width:92px}"
        ".tiles{display:flex;gap:12px;flex-wrap:wrap;margin:8px 0 4px}"
        ".tile{flex:1;min-width:120px;border:1px solid var(--line);border-radius:10px;padding:14px 16px;background:var(--bg)}"
        ".tile .n{font-size:26px;font-weight:700}.tile .l{font-size:12px;color:var(--muted)}"
        ".chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px}"
        ".chip{border-radius:999px;padding:3px 11px;color:#fff;font-size:12px;font-weight:600}"
        ".finding{border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:16px 0;"
        "page-break-inside:avoid}"
        ".finding .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:4px}"
        ".badge{border-radius:6px;padding:2px 9px;color:#fff;font-size:11px;font-weight:700;text-transform:uppercase}"
        ".kv{font-size:13px;margin:10px 0}.kv b{display:inline-block;min-width:92px;color:var(--muted);font-weight:500}"
        ".block{margin-top:12px}.block .bh{font-size:12px;font-weight:700;text-transform:uppercase;"
        "color:var(--muted);margin-bottom:4px}"
        "pre{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:12px;overflow:auto;"
        "font-size:12px;white-space:pre-wrap;word-break:break-word;margin:0}"
        "img.shot{max-width:100%;border:1px solid var(--line);border-radius:8px;margin-top:4px}"
        "table{width:100%;border-collapse:collapse;font-size:13px}"
        "th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}"
        "th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase}"
        ".footer{margin-top:36px;padding-top:14px;border-top:1px solid var(--line);"
        "color:var(--muted);font-size:12px}"
        "@media print{.finding{break-inside:avoid}h2{break-after:avoid}}"
        "</style></head><body><div class='page'>"
    )


def _cover(report: dict, n_conf: int, n_cand: int, n_rej: int) -> str:
    name = html.escape(report.get("target_name") or "Unnamed target")
    url = html.escape(report.get("target_url") or "—")
    gen = _fmt_dt(report.get("generated_at"))
    started = _fmt_dt(report.get("started_at"))
    completed = _fmt_dt(report.get("completed_at"))
    return (
        "<div class='cover'>"
        "<div class='brand'>ProofStrike · Verification-First Security Validation</div>"
        "<h1>Security Validation Report</h1>"
        f"<div class='muted'>{name} &nbsp;·&nbsp; <span class='mono'>{url}</span></div>"
        "<div class='meta'>"
        f"<div><span>Scan ID</span><span class='mono'>{html.escape(report['scan_id'])}</span></div>"
        f"<div><span>Status</span>{html.escape(report.get('status') or '—')}</div>"
        f"<div><span>Started</span>{started}</div>"
        f"<div><span>Completed</span>{completed}</div>"
        f"<div><span>Generated</span>{gen}</div>"
        f"<div><span>Findings</span>{n_conf} confirmed · {n_cand} candidate · {n_rej} rejected</div>"
        "</div></div>"
    )


def _summary(sev_counts: dict, n_conf: int, n_cand: int, n_rej: int) -> str:
    chips = "".join(
        f"<span class='chip' style='background:{_SEVERITY_COLOR[s]}'>"
        f"{s.title()} {sev_counts[s]}</span>"
        for s in _SEVERITY_ORDER if sev_counts.get(s)
    ) or "<span class='muted'>No confirmed findings to rank.</span>"
    return (
        "<section class='section'><h2>Executive summary</h2>"
        "<p class='muted'>Every finding below was re-executed after detection and is "
        "included only because the vulnerability was <strong>proven</strong> — the payload "
        "actually ran, or the behaviour reproduced deterministically. Candidates that could "
        "not be proven were rejected, not reported as issues.</p>"
        "<div class='tiles'>"
        f"<div class='tile'><div class='n' style='color:#16a34a'>{n_conf}</div><div class='l'>Confirmed</div></div>"
        f"<div class='tile'><div class='n' style='color:#ca8a04'>{n_cand}</div><div class='l'>Unconfirmed candidates</div></div>"
        f"<div class='tile'><div class='n' style='color:#6b7280'>{n_rej}</div><div class='l'>Rejected (false positives)</div></div>"
        "</div>"
        "<div class='block'><div class='bh'>Confirmed by severity</div>"
        f"<div class='chips'>{chips}</div></div>"
        "</section>"
    )


def _finding_block(index: int, f: dict, detailed: bool) -> str:
    sev = f.get("severity", "info")
    status = f.get("status", "candidate")
    sev_c = _SEVERITY_COLOR.get(sev, "#6b7280")
    status_c = _STATUS_COLOR.get(status, "#6b7280")
    out = [
        "<div class='finding'>",
        "<div class='top'>",
        f"<h3>{index}. {html.escape(f.get('title') or 'Finding')}</h3>",
        f"<span class='badge' style='background:{sev_c}'>{html.escape(sev)}</span>",
        f"<span class='badge' style='background:{status_c}'>{html.escape(status)}</span>",
        f"<span class='badge' style='background:#374151'>{html.escape(f.get('type') or '')}</span>",
        "</div>",
    ]
    if f.get("description"):
        out.append(f"<div class='kv'>{_text(f['description'])}</div>")
    if detailed and f.get("reproduction_steps"):
        out.append("<div class='block'><div class='bh'>Reproduction</div>"
                   f"<pre>{html.escape(f['reproduction_steps'])}</pre></div>")
    if detailed and f.get("remediation"):
        out.append("<div class='block'><div class='bh'>Remediation</div>"
                   f"<div class='kv'>{_text(f['remediation'])}</div></div>")
    if detailed:
        for ev in f.get("evidence", []):
            out.append(_evidence_block(ev))
    out.append("</div>")
    return "".join(out)


def _evidence_block(ev: dict) -> str:
    etype = ev.get("type") or ""
    label = _EVIDENCE_LABEL.get(etype, etype.title() or "Evidence")
    content = ev.get("content") or ""
    if etype == "screenshot" and content:
        src = content if content.startswith("data:") else f"data:image/png;base64,{content}"
        return (f"<div class='block'><div class='bh'>{html.escape(label)}</div>"
                f"<img class='shot' src='{html.escape(src, quote=True)}' alt='screenshot'></div>")
    if not content:
        return ""
    return (f"<div class='block'><div class='bh'>{html.escape(label)}</div>"
            f"<pre>{html.escape(content)}</pre></div>")


def _candidate_table(cands: list[dict]) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(c.get('type') or '')}</td>"
        f"<td><span class='badge' style='background:{_SEVERITY_COLOR.get(c.get('severity','info'),'#6b7280')}'>"
        f"{html.escape(c.get('severity') or 'info')}</span></td>"
        f"<td>{html.escape(c.get('title') or '')}</td>"
        "</tr>"
        for c in _sort_by_severity(cands)
    )
    return f"<table><thead><tr><th>Type</th><th>Severity</th><th>Finding</th></tr></thead><tbody>{rows}</tbody></table>"


def _footer() -> str:
    return (
        "<div class='footer'>Generated by ProofStrike — a verification-first web "
        "security validation platform. Findings marked <em>confirmed</em> were reproduced "
        "with the evidence shown above. Intended for authorised testing only.</div></div>"
    )


# ── PDF (via headless Chromium — already a dependency) ───────────────────────────
def render_pdf(html_doc: str) -> bytes:
    """
    Render the HTML to PDF bytes with headless Chromium.

    Playwright launches a browser subprocess, which needs a subprocess-capable event
    loop — on Windows that is a ProactorEventLoop, not the server's SelectorEventLoop.
    This runs on its own fresh loop, so the router calls it via asyncio.to_thread to
    keep it off (and not block) the server loop.
    """
    loop = asyncio.ProactorEventLoop() if sys.platform == "win32" else asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(render_pdf_async(html_doc))
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            loop.close()
            asyncio.set_event_loop(None)


async def render_pdf_async(html_doc: str) -> bytes:
    """Render HTML to PDF with headless Chromium. Call this directly from code that
    is already on a subprocess-capable loop (e.g. the CLI); the sync `render_pdf`
    wrapper is for the API server, which is on a non-subprocess loop."""
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.set_content(html_doc, wait_until="networkidle")
            return await page.pdf(
                format="A4",
                print_background=True,
                margin={"top": "16mm", "bottom": "16mm", "left": "12mm", "right": "12mm"},
            )
        finally:
            await browser.close()


# ── helpers ──────────────────────────────────────────────────────────────────
def _sort_by_severity(items: list[dict]) -> list[dict]:
    rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    return sorted(items, key=lambda f: rank.get(f.get("severity", "info"), len(_SEVERITY_ORDER)))


def _text(value: str) -> str:
    """Escape, then turn blank lines into paragraph breaks for readable prose."""
    escaped = html.escape(value or "")
    return escaped.replace("\n\n", "<br><br>").replace("\n", "<br>")


def _fmt_dt(value: str | None) -> str:
    if not value:
        return "—"
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, AttributeError):
        return html.escape(str(value))
