import React, { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  ArrowLeft, ExternalLink, Zap, Settings2, CalendarClock, Repeat, AlertTriangle,
  ShieldAlert, ShieldCheck, Clock, GitCompare, Activity, ArrowUpRight, Play,
} from 'lucide-react';
import api from '../hooks/useApi';
import DiffView from '../components/DiffView';
import ScheduleModal from '../components/ScheduleModal';
import StatusBadge from '../components/StatusBadge';
import SeverityBadge from '../components/SeverityBadge';
import { formatAgo, formatCountdown, formatInterval, isActiveStatus } from '../lib/format';
import './TargetDetail.css';

export default function TargetDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [target, setTarget] = useState(null);
  const [scans, setScans] = useState([]);
  const [diff, setDiff] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [scheduleOpen, setScheduleOpen] = useState(false);
  const [launching, setLaunching] = useState(false);
  const pollRef = useRef(null);

  const fetchData = async () => {
    setError(null);
    try {
      const [targetData, scansData, diffData] = await Promise.all([
        api.get(`/targets/${id}`),
        api.get(`/scans?target_id=${id}`).catch(() => ({ scans: [] })),
        api.get(`/targets/${id}/diff/latest`).catch(() => null),
      ]);
      setTarget(targetData);
      const scanList = scansData?.scans || [];
      setScans(scanList);
      setDiff(diffData);

      const latestCompleted = scanList
        .filter((s) => s.status === 'completed' && s.completed_at)
        .sort((a, b) => new Date(b.completed_at) - new Date(a.completed_at))[0];
      if (latestCompleted) {
        const f = await api.get(`/scans/${latestCompleted.id}/findings`).catch(() => ({ findings: [] }));
        setFindings((f?.findings || []).filter((x) => x.status === 'confirmed'));
      } else {
        setFindings([]);
      }
    } catch (err) {
      setError(err.message || 'Failed to load target');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); return () => clearInterval(pollRef.current); }, [id]);

  const anyActive = scans.some((s) => isActiveStatus(s.status));
  useEffect(() => {
    clearInterval(pollRef.current);
    if (anyActive) pollRef.current = setInterval(fetchData, 4000);
    return () => clearInterval(pollRef.current);
  }, [anyActive]);

  const runScan = async () => {
    setLaunching(true);
    try {
      const scan = await api.post('/scans', { target_id: id });
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      alert(err.message || 'Failed to start scan');
      setLaunching(false);
    }
  };

  if (loading && !target) {
    return <div className="loading-container"><div className="spinner" /></div>;
  }
  if (error || !target) {
    return (
      <div className="card td-error">
        <AlertTriangle size={24} />
        <div>
          <h3>Target not found</h3>
          <p className="text-secondary">{error || 'Unable to load this target.'}</p>
          <Link to="/targets" className="btn btn-secondary btn-sm mt-sm"><ArrowLeft size={14} /><span>Back to Targets</span></Link>
        </div>
      </div>
    );
  }

  const sevCounts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, {});
  const criticalHigh = (sevCounts.critical || 0) + (sevCounts.high || 0);
  const lastCompleted = scans
    .filter((s) => s.status === 'completed' && s.completed_at)
    .sort((a, b) => new Date(b.completed_at) - new Date(a.completed_at))[0];

  return (
    <div className="target-detail-page animate-slide-up">
      <div className="back-bar">
        <Link to="/targets" className="back-link"><ArrowLeft size={15} /><span>Targets</span></Link>
      </div>

      {/* ── Header ── */}
      <div className="card td-header">
        <div className="td-header-main">
          <div className="td-title-row">
            <h1 className="td-name">{target.name}</h1>
            {target.schedule_enabled && (
              <span className="td-sched-badge"><Repeat size={12} /> {formatInterval(target.scan_interval_minutes)}</span>
            )}
            {anyActive && <StatusBadge status={scans.find((s) => isActiveStatus(s.status))?.status} size="sm" />}
          </div>
          <a href={target.base_url} target="_blank" rel="noreferrer" className="td-url text-mono">
            <span>{target.base_url}</span><ExternalLink size={12} />
          </a>
        </div>
        <div className="td-header-actions">
          <button className="btn btn-primary" onClick={runScan} disabled={launching}>
            <Play size={15} /><span>{launching ? 'Starting…' : 'Run scan'}</span>
          </button>
          <Link to={`/scans/new?target_id=${id}`} className="btn btn-secondary" title="Configure a scan">
            <Settings2 size={15} /><span>Configure</span>
          </Link>
          <button className="btn btn-secondary" onClick={() => setScheduleOpen(true)} title="Schedule continuous scans">
            <CalendarClock size={15} /><span>Schedule</span>
          </button>
        </div>
      </div>

      {/* ── Posture KPIs ── */}
      <div className="td-kpis">
        <div className="card td-kpi">
          <span className="td-kpi-label">Open confirmed</span>
          <span className="td-kpi-value">{findings.length}</span>
          <span className="td-kpi-sub text-muted">{lastCompleted ? `as of ${formatAgo(lastCompleted.completed_at)}` : 'no scans yet'}</span>
        </div>
        <div className={`card td-kpi ${criticalHigh ? 'td-kpi-alert' : ''}`}>
          <span className="td-kpi-label">Critical + High</span>
          <span className="td-kpi-value">{criticalHigh}</span>
          <span className="td-kpi-sub text-muted">{sevCounts.critical || 0} critical · {sevCounts.high || 0} high</span>
        </div>
        <div className="card td-kpi">
          <span className="td-kpi-label">Last scan</span>
          <span className="td-kpi-value-sm">{lastCompleted ? formatAgo(lastCompleted.completed_at) : '—'}</span>
          <span className="td-kpi-sub text-muted">{scans.length} total run{scans.length === 1 ? '' : 's'}</span>
        </div>
        <div className="card td-kpi">
          <span className="td-kpi-label">Next scan</span>
          <span className="td-kpi-value-sm">
            {target.schedule_enabled ? (formatCountdown(target.next_scan_at) || 'soon') : 'manual'}
          </span>
          <span className="td-kpi-sub text-muted">
            {target.schedule_enabled ? formatInterval(target.scan_interval_minutes) : 'no schedule'}
          </span>
        </div>
      </div>

      {/* ── Changes since last scan ── */}
      <div className="card">
        <div className="card-head">
          <div className="card-head-title"><GitCompare size={16} /><h3 className="text-subheading">Changes since last scan</h3></div>
          {lastCompleted && <Link to={`/scans/${lastCompleted.id}`} className="card-head-link">Latest scan <ArrowUpRight size={13} /></Link>}
        </div>
        {diff ? <DiffView diff={diff} /> : (
          <div className="td-empty">
            <GitCompare size={28} className="text-muted" />
            <p className="text-secondary text-body">No completed scan yet</p>
            <span className="text-caption text-muted">Run a scan to establish a baseline; the next run shows the diff.</span>
          </div>
        )}
      </div>

      {/* ── Open findings ── */}
      <div className="card">
        <div className="card-head">
          <div className="card-head-title"><ShieldAlert size={16} /><h3 className="text-subheading">Open confirmed findings</h3></div>
          <Link to={`/findings?status=confirmed`} className="card-head-link">All findings <ArrowUpRight size={13} /></Link>
        </div>
        {findings.length === 0 ? (
          <div className="td-empty">
            <ShieldCheck size={28} className="text-muted" />
            <p className="text-secondary text-body">No confirmed vulnerabilities</p>
            <span className="text-caption text-muted">Proven issues from the latest scan appear here.</span>
          </div>
        ) : (
          <div className="td-findings">
            {findings.map((f) => (
              <Link to={`/findings/${f.id}`} key={f.id} className="td-finding-row">
                <SeverityBadge severity={f.severity} size="sm" />
                <span className="tdf-type text-mono">{f.type?.toUpperCase()}</span>
                <span className="tdf-title">{f.title}</span>
                <ArrowUpRight size={14} className="tr-arrow" />
              </Link>
            ))}
          </div>
        )}
      </div>

      {/* ── Scan history ── */}
      <div className="card">
        <div className="card-head">
          <div className="card-head-title"><Activity size={16} /><h3 className="text-subheading">Scan history</h3></div>
        </div>
        {scans.length === 0 ? (
          <div className="td-empty">
            <Clock size={28} className="text-muted" />
            <p className="text-secondary text-body">No scans run yet</p>
            <button className="btn btn-sm btn-primary mt-sm" onClick={runScan} disabled={launching}>
              <Zap size={13} /><span>Run first scan</span>
            </button>
          </div>
        ) : (
          <div className="td-history">
            {[...scans].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).map((s) => (
              <Link to={`/scans/${s.id}`} key={s.id} className="td-history-row">
                <StatusBadge status={s.status} size="sm" />
                <span className="tdh-id text-mono text-muted">#{s.id.slice(0, 8)}</span>
                <span className="tdh-findings text-caption text-muted">
                  {s.stats?.confirmed_findings != null ? `${s.stats.confirmed_findings} confirmed` : ''}
                </span>
                <span className="tdh-time text-caption text-muted">{formatAgo(s.created_at)}</span>
                <ArrowUpRight size={14} className="tr-arrow" />
              </Link>
            ))}
          </div>
        )}
      </div>

      {scheduleOpen && (
        <ScheduleModal
          target={target}
          onClose={() => setScheduleOpen(false)}
          onSaved={(updated) => setTarget((prev) => ({ ...prev, ...updated }))}
        />
      )}
    </div>
  );
}
