import React, { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Activity, Plus, RotateCcw, ArrowUpRight } from 'lucide-react';
import api from '../hooks/useApi';
import StatusBadge from '../components/StatusBadge';
import { formatAgo, isActiveStatus } from '../lib/format';
import './Scans.css';

const STATUSES = ['queued', 'crawling', 'testing', 'verifying', 'completed', 'failed', 'stopped'];

export default function Scans() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState({});
  const [targetList, setTargetList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || '');
  const [targetFilter, setTargetFilter] = useState(searchParams.get('target_id') || '');

  const fetchScans = async () => {
    setError(null);
    try {
      const q = [];
      if (statusFilter) q.push(`status=${statusFilter}`);
      if (targetFilter) q.push(`target_id=${targetFilter}`);
      const qs = q.length ? `?${q.join('&')}` : '';
      const [scansData, targetsData] = await Promise.all([
        api.get(`/scans${qs}`),
        api.get('/targets').catch(() => ({ targets: [] })),
      ]);
      setScans(scansData.scans || []);
      setTargetList(targetsData.targets || []);
      setTargets(Object.fromEntries((targetsData.targets || []).map((t) => [t.id, t.name])));
    } catch (err) {
      setError(err.message || 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchScans(); return () => clearInterval(pollRef.current); }, [statusFilter, targetFilter]);

  const anyActive = scans.some((s) => isActiveStatus(s.status));
  useEffect(() => {
    clearInterval(pollRef.current);
    if (anyActive) pollRef.current = setInterval(fetchScans, 4000);
    return () => clearInterval(pollRef.current);
  }, [anyActive, statusFilter, targetFilter]);

  const resetFilters = () => { setStatusFilter(''); setTargetFilter(''); setSearchParams({}); };
  const hasFilters = statusFilter || targetFilter;

  const duration = (s) => {
    const d = s.stats?.duration_seconds;
    if (d == null) return '—';
    if (d < 60) return `${Math.round(d)}s`;
    return `${Math.floor(d / 60)}m ${Math.round(d % 60)}s`;
  };

  return (
    <div className="scans-page animate-slide-up">
      <div className="page-header">
        <div>
          <h1 className="page-title">Scans</h1>
          <p className="text-secondary text-body">Every scan run across all targets, newest first.</p>
        </div>
        <Link to="/scans/new" className="btn btn-primary"><Plus size={16} /><span>New Scan</span></Link>
      </div>

      <div className="card filter-bar">
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="filter-select">
          <option value="">All statuses</option>
          {STATUSES.map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
        </select>
        <select value={targetFilter} onChange={(e) => setTargetFilter(e.target.value)} className="filter-select">
          <option value="">All targets</option>
          {targetList.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>
        {hasFilters && (
          <button className="btn btn-sm btn-secondary" onClick={resetFilters}><RotateCcw size={13} /><span>Reset</span></button>
        )}
        {anyActive && <span className="live-tag"><span className="live-dot" /> live</span>}
      </div>

      {error && <div className="card scans-error">{error}</div>}

      {loading && scans.length === 0 ? (
        <div className="loading-container"><div className="spinner" /></div>
      ) : (
        <div className="card table-card">
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Status</th><th>Target</th><th>Scan</th><th>Confirmed</th><th>Duration</th><th>Started</th><th></th>
                </tr>
              </thead>
              <tbody>
                {scans.length === 0 ? (
                  <tr className="empty-row">
                    <td colSpan={7}>
                      <div className="empty-state">
                        <Activity size={40} />
                        <h3 className="text-subheading">No scans found</h3>
                        <p className="text-muted">{hasFilters ? 'No scans match these filters.' : 'Launch a scan against a target.'}</p>
                        {!hasFilters && <Link to="/scans/new" className="btn btn-sm btn-primary mt-sm"><Plus size={14} /><span>New Scan</span></Link>}
                      </div>
                    </td>
                  </tr>
                ) : (
                  scans.map((s) => (
                    <tr key={s.id} className="scan-tr">
                      <td><StatusBadge status={s.status} size="sm" /></td>
                      <td>
                        <Link to={`/targets/${s.target_id}`} className="scan-target-cell" onClick={(e) => e.stopPropagation()}>
                          {targets[s.target_id] || `${s.target_id.slice(0, 8)}`}
                        </Link>
                      </td>
                      <td><span className="text-mono text-muted">#{s.id.slice(0, 8)}</span></td>
                      <td>
                        {s.stats?.confirmed_findings != null
                          ? <span className={s.stats.confirmed_findings > 0 ? 'conf-count has' : 'conf-count'}>{s.stats.confirmed_findings}</span>
                          : <span className="text-muted">—</span>}
                      </td>
                      <td className="text-caption text-muted">{duration(s)}</td>
                      <td className="text-caption text-muted">{formatAgo(s.started_at || s.created_at)}</td>
                      <td>
                        <Link to={`/scans/${s.id}`} className="scan-open"><ArrowUpRight size={15} /></Link>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
