import React, { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid,
} from 'recharts';
import {
  Zap, ShieldAlert, ShieldCheck, AlertTriangle, Activity, RefreshCw,
  ArrowRight, ArrowUpRight, Target as TargetIcon, TrendingUp, Repeat,
} from 'lucide-react';
import api from '../hooks/useApi';
import {
  SEVERITY_ORDER, SEVERITY_COLOR, formatAgo, formatCountdown, isActiveStatus,
} from '../lib/format';
import './Dashboard.css';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState([]);
  const [diffs, setDiffs] = useState({}); // target_id -> latest diff (or null)
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  const fetchData = async () => {
    setError(null);
    try {
      const [statsData, scansData, targetsData] = await Promise.all([
        api.get('/dashboard/stats').catch(() => null),
        api.get('/scans').catch(() => ({ scans: [] })),
        api.get('/targets').catch(() => ({ targets: [] })),
      ]);
      setStats(statsData);
      setScans(scansData?.scans || []);
      const tgs = targetsData?.targets || [];
      setTargets(tgs);

      // Per-target posture comes from the latest completed scan's diff.
      const diffEntries = await Promise.all(
        tgs.map((t) =>
          api.get(`/targets/${t.id}/diff/latest`).then(
            (d) => [t.id, d],
            () => [t.id, null],
          ),
        ),
      );
      setDiffs(Object.fromEntries(diffEntries));
    } catch (err) {
      setError(err.message || 'Failed to load dashboard');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    return () => clearInterval(pollRef.current);
  }, []);

  // Live refresh while any scan is running.
  const anyActive = scans.some((s) => isActiveStatus(s.status));
  useEffect(() => {
    clearInterval(pollRef.current);
    if (anyActive) pollRef.current = setInterval(fetchData, 5000);
    return () => clearInterval(pollRef.current);
  }, [anyActive]);

  const confirmed = stats?.confirmed_findings ?? 0;
  const totalDetected = stats?.total_findings ?? 0;
  const filtered = Math.max(totalDetected - confirmed, 0);
  const sev = stats?.severity_breakdown || {};
  const criticalHigh = (sev.critical ?? 0) + (sev.high ?? 0);
  const verifiedPct = totalDetected ? Math.round((confirmed / totalDetected) * 100) : 0;

  // Trend: confirmed findings per completed scan, oldest -> newest.
  const trend = scans
    .filter((s) => s.status === 'completed' && s.completed_at)
    .sort((a, b) => new Date(a.completed_at) - new Date(b.completed_at))
    .map((s) => ({
      label: new Date(s.completed_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
      confirmed: s.stats?.confirmed_findings ?? 0,
    }));

  const recent = [...scans]
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 6);
  const targetName = (id) => targets.find((t) => t.id === id)?.name || id?.slice(0, 8);

  const maxSev = Math.max(1, ...SEVERITY_ORDER.map((s) => sev[s] ?? 0));

  // Per-target posture rows.
  const targetRows = targets.map((t) => {
    const d = diffs[t.id];
    const open = d ? (d.new_count + d.unchanged_count) : null;
    const lastScan = scans
      .filter((s) => s.target_id === t.id && s.completed_at)
      .sort((a, b) => new Date(b.completed_at) - new Date(a.completed_at))[0];
    return { t, d, open, lastScan };
  });

  if (loading && !stats) {
    return <div className="loading-container"><div className="spinner" /></div>;
  }

  return (
    <div className="dashboard-page animate-slide-up">
      <div className="page-header">
        <div>
          <h1 className="page-title">Overview</h1>
          <p className="text-secondary text-body">
            Security posture across every monitored target — and what changed since last scan.
          </p>
        </div>
        <div className="header-actions">
          <button className="btn btn-secondary btn-sm" onClick={fetchData} title="Refresh">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <Link to="/scans/new" className="btn btn-primary">
            <Zap size={15} /><span>New Scan</span>
          </Link>
        </div>
      </div>

      {error && (
        <div className="card dash-error">
          <AlertTriangle size={18} /><span>{error}</span>
        </div>
      )}

      {/* ── Posture KPIs ── */}
      <div className="kpi-row">
        <div className="card kpi">
          <div className="kpi-top">
            <span className="kpi-label">Open confirmed</span>
            <ShieldAlert size={16} className="kpi-ic" />
          </div>
          <div className="kpi-value">{confirmed}</div>
          <div className="kpi-sub text-muted">across {stats?.total_targets ?? 0} targets</div>
        </div>

        <div className={`card kpi ${criticalHigh > 0 ? 'kpi-alert' : ''}`}>
          <div className="kpi-top">
            <span className="kpi-label">Critical + High</span>
            <AlertTriangle size={16} className="kpi-ic" />
          </div>
          <div className="kpi-value">{criticalHigh}</div>
          <div className="kpi-sub text-muted">{sev.critical ?? 0} critical · {sev.high ?? 0} high</div>
        </div>

        <div className="card kpi">
          <div className="kpi-top">
            <span className="kpi-label">Verified</span>
            <ShieldCheck size={16} className="kpi-ic" />
          </div>
          <div className="kpi-value">{verifiedPct}<span className="kpi-unit">%</span></div>
          <div className="kpi-sub text-muted">{confirmed} proven · {filtered} filtered out</div>
        </div>

        <div className={`card kpi ${anyActive ? 'kpi-live' : ''}`}>
          <div className="kpi-top">
            <span className="kpi-label">Active scans</span>
            <Activity size={16} className={`kpi-ic ${anyActive ? 'icon-pulse' : ''}`} />
          </div>
          <div className="kpi-value">{stats?.active_scans ?? 0}</div>
          <div className="kpi-sub text-muted">{anyActive ? 'running now' : 'idle'}</div>
        </div>
      </div>

      {/* ── Trend + Verification ── */}
      <div className="dash-grid-2">
        <div className="card chart-card">
          <div className="card-head">
            <div className="card-head-title"><TrendingUp size={16} /><h3 className="text-subheading">Confirmed findings over time</h3></div>
            <span className="text-caption text-muted">per completed scan</span>
          </div>
          {trend.length >= 2 ? (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={trend} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#C86618" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#C86618" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="label" tick={{ fill: '#777', fontSize: 11 }} tickLine={false} axisLine={false} />
                <YAxis allowDecimals={false} tick={{ fill: '#777', fontSize: 11 }} tickLine={false} axisLine={false} width={34} />
                <Tooltip
                  contentStyle={{ background: '#171717', border: '1px solid rgba(200,102,24,0.35)', borderRadius: 6, fontSize: 12 }}
                  labelStyle={{ color: '#A0A0A0' }} itemStyle={{ color: '#EFEFEF' }}
                />
                <Area type="monotone" dataKey="confirmed" stroke="#DE7E2E" strokeWidth={2} fill="url(#trendFill)" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="mini-empty">
              <TrendingUp size={28} className="text-muted" />
              <p className="text-secondary text-body">Not enough history yet</p>
              <span className="text-caption text-muted">Run at least two scans on a target to see the trend.</span>
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-head">
            <div className="card-head-title"><ShieldAlert size={16} /><h3 className="text-subheading">Confirmed by severity</h3></div>
          </div>
          {confirmed > 0 ? (
            <div className="sev-bars">
              {SEVERITY_ORDER.map((s) => {
                const v = sev[s] ?? 0;
                return (
                  <Link to={`/findings?severity=${s}&status=confirmed`} key={s} className="sev-bar-row">
                    <span className="sev-bar-label">{s}</span>
                    <div className="sev-bar-track">
                      <div className="sev-bar-fill" style={{ width: `${(v / maxSev) * 100}%`, background: SEVERITY_COLOR[s] }} />
                    </div>
                    <span className="sev-bar-count text-mono">{v}</span>
                  </Link>
                );
              })}
            </div>
          ) : (
            <div className="mini-empty">
              <ShieldCheck size={28} className="text-muted" />
              <p className="text-secondary text-body">No confirmed vulnerabilities</p>
              <span className="text-caption text-muted">Proven issues will be ranked here by severity.</span>
            </div>
          )}
          <Link to="/findings?status=confirmed" className="card-foot-link">
            View all confirmed findings <ArrowRight size={13} />
          </Link>
        </div>
      </div>

      {/* ── Targets posture ── */}
      <div className="card targets-panel">
        <div className="card-head">
          <div className="card-head-title"><TargetIcon size={16} /><h3 className="text-subheading">Targets</h3></div>
          <Link to="/targets" className="card-head-link">Manage <ArrowRight size={13} /></Link>
        </div>

        {targets.length === 0 ? (
          <div className="mini-empty">
            <TargetIcon size={28} className="text-muted" />
            <p className="text-secondary text-body">No targets yet</p>
            <Link to="/targets" className="btn btn-sm btn-primary mt-sm">Add a target</Link>
          </div>
        ) : (
          <div className="target-rows">
            {targetRows.map(({ t, d, open, lastScan }) => (
              <Link to={`/targets/${t.id}`} key={t.id} className="target-row">
                <div className="tr-name">
                  <span className="tr-title">{t.name}</span>
                  <span className="tr-url text-mono text-muted">{t.base_url}</span>
                </div>

                <div className="tr-open">
                  {open === null ? (
                    <span className="text-muted text-caption">not scanned</span>
                  ) : open === 0 ? (
                    <span className="tr-clean"><ShieldCheck size={13} /> clean</span>
                  ) : (
                    <span className="tr-open-count"><ShieldAlert size={13} /> {open} open</span>
                  )}
                </div>

                <div className="tr-delta">
                  {d && !d.is_baseline && (d.new_count > 0 || d.fixed_count > 0) ? (
                    <>
                      {d.new_count > 0 && <span className="delta-new">+{d.new_count} new</span>}
                      {d.fixed_count > 0 && <span className="delta-fixed">−{d.fixed_count} fixed</span>}
                    </>
                  ) : d?.is_baseline ? (
                    <span className="text-caption text-muted">baseline</span>
                  ) : (
                    <span className="text-caption text-muted">no change</span>
                  )}
                </div>

                <div className="tr-sched text-caption text-muted">
                  {t.schedule_enabled ? (
                    <span className="tr-sched-on"><Repeat size={12} /> next {formatCountdown(t.next_scan_at) || '—'}</span>
                  ) : (
                    <span>manual</span>
                  )}
                </div>

                <div className="tr-last text-caption text-muted">
                  {lastScan ? formatAgo(lastScan.completed_at) : '—'}
                </div>

                <ArrowUpRight size={15} className="tr-arrow" />
              </Link>
            ))}
          </div>
        )}
      </div>

      {/* ── Recent activity ── */}
      <div className="card">
        <div className="card-head">
          <div className="card-head-title"><Activity size={16} /><h3 className="text-subheading">Recent activity</h3></div>
          <Link to="/scans" className="card-head-link">All scans <ArrowRight size={13} /></Link>
        </div>
        {recent.length === 0 ? (
          <div className="mini-empty">
            <Activity size={28} className="text-muted" />
            <p className="text-secondary text-body">No scans yet</p>
            <Link to="/scans/new" className="btn btn-sm btn-primary mt-sm">Run first scan</Link>
          </div>
        ) : (
          <div className="activity-rows">
            {recent.map((s) => (
              <Link to={`/scans/${s.id}`} key={s.id} className="activity-row">
                <span className={`act-dot act-${s.status}`} />
                <span className="act-target">{targetName(s.target_id)}</span>
                <span className="act-status text-caption">{s.status}</span>
                <span className="act-findings text-caption text-muted">
                  {s.stats?.confirmed_findings != null ? `${s.stats.confirmed_findings} confirmed` : ''}
                </span>
                <span className="act-time text-caption text-muted">{formatAgo(s.created_at)}</span>
                <ArrowUpRight size={14} className="tr-arrow" />
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
