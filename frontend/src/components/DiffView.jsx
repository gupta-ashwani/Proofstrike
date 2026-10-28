import React from 'react';
import { Link } from 'react-router-dom';
import { CheckCircle2, Flag } from 'lucide-react';
import './DiffView.css';

// One labelled block of diff rows (new / fixed / unchanged).
function DiffGroup({ title, kind, items, bare = false }) {
  const sign = kind === 'new' ? '+' : kind === 'fixed' ? '−' : '=';
  const linkable = kind !== 'fixed'; // fixed findings live on the previous scan
  return (
    <div className={`diff-group diff-group-${kind}`}>
      {!bare && <div className="diff-group-title">{title}</div>}
      <div className="diff-rows">
        {items.map((it) => {
          const body = (
            <>
              <span className="diff-sign">{sign}</span>
              <span className={`diff-type type-${it.type}`}>{it.type}</span>
              <span className={`diff-sev sev-${it.severity}`}>{it.severity}</span>
              <span className="diff-title">{it.title}</span>
            </>
          );
          return linkable && it.finding_id ? (
            <Link key={it.fingerprint} to={`/findings/${it.finding_id}`} className="diff-row linkable">{body}</Link>
          ) : (
            <div key={it.fingerprint} className="diff-row">{body}</div>
          );
        })}
      </div>
    </div>
  );
}

/**
 * Renders a scan-to-scan differential (the ScanDiffResponse shape) — used by the
 * scan detail page and the target hub.
 */
export default function DiffView({ diff }) {
  if (!diff) return null;

  if (diff.is_baseline) {
    return (
      <div className="diff-baseline">
        <Flag size={18} />
        <div>
          <h4 className="text-subheading">Baseline scan</h4>
          <p className="text-secondary text-body">
            First completed scan for this target — nothing to compare against yet. It
            establishes a baseline of <strong>{diff.new_count}</strong> confirmed
            finding{diff.new_count === 1 ? '' : 's'}; the next scan shows only what changed.
          </p>
        </div>
      </div>
    );
  }

  const quiet = diff.new_count === 0 && diff.fixed_count === 0;

  return (
    <div className="diff-view">
      <div className="diff-summary-bar">
        <div className="diff-stat new"><span className="diff-n">{diff.new_count}</span><span className="diff-l">New</span></div>
        <div className="diff-stat fixed"><span className="diff-n">{diff.fixed_count}</span><span className="diff-l">Fixed</span></div>
        <div className="diff-stat unchanged"><span className="diff-n">{diff.unchanged_count}</span><span className="diff-l">Still open</span></div>
      </div>

      {quiet ? (
        <div className="diff-nochange">
          <CheckCircle2 size={18} />
          <span>No change since the previous scan — {diff.unchanged_count} confirmed finding{diff.unchanged_count === 1 ? '' : 's'} carried over.</span>
        </div>
      ) : (
        <>
          {diff.new.length > 0 && <DiffGroup title="New since last scan" kind="new" items={diff.new} />}
          {diff.fixed.length > 0 && <DiffGroup title="Fixed / no longer reproducible" kind="fixed" items={diff.fixed} />}
        </>
      )}

      {diff.unchanged.length > 0 && (
        <details className="diff-unchanged-wrap">
          <summary>{diff.unchanged.length} unchanged finding{diff.unchanged.length === 1 ? '' : 's'} (still open)</summary>
          <DiffGroup kind="unchanged" items={diff.unchanged} bare />
        </details>
      )}
    </div>
  );
}
