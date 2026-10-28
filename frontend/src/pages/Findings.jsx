import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  ShieldAlert, Search, ShieldCheck, HelpCircle, XCircle, RotateCcw, ArrowUpRight,
} from 'lucide-react';
import api from '../hooks/useApi';
import SeverityBadge from '../components/SeverityBadge';
import { SEVERITY_ORDER } from '../lib/format';
import './Findings.css';

const STATUS_ICON = { confirmed: ShieldCheck };
const STATUS_RANK = { confirmed: 0, candidate: 1, rejected: 2, false_positive: 3 };

export default function Findings() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);

  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState(searchParams.get('severity') || '');
  const [typeFilter, setTypeFilter] = useState(searchParams.get('type') || '');
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || '');

  const fetchFindings = async () => {
    setLoading(true); setFetchError(null);
    try {
      const q = [];
      if (severityFilter) q.push(`severity=${severityFilter}`);
      if (typeFilter) q.push(`type=${typeFilter}`);
      if (statusFilter) q.push(`status=${statusFilter}`);
      const data = await api.get(`/findings${q.length ? `?${q.join('&')}` : ''}`);
      setFindings(data.findings || []);
    } catch (err) {
      setFetchError(err.message || 'Failed to load findings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchFindings(); }, [severityFilter, typeFilter, statusFilter]);

  const resetFilters = () => {
    setSearchQuery(''); setSeverityFilter(''); setTypeFilter(''); setStatusFilter(''); setSearchParams({});
  };
  const hasFilters = severityFilter || typeFilter || statusFilter || searchQuery;

  const rows = findings
    .filter((f) => {
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase();
      return f.title?.toLowerCase().includes(q) || f.description?.toLowerCase().includes(q) || f.type?.toLowerCase().includes(q);
    })
    .sort((a, b) => {
      const s = (STATUS_RANK[a.status] ?? 9) - (STATUS_RANK[b.status] ?? 9);
      if (s !== 0) return s;
      return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    });

  return (
    <div className="findings-page animate-slide-up">
      <div className="page-header">
        <div>
          <h1 className="page-title">Findings</h1>
          <p className="text-secondary text-body">
            Every vulnerability across all targets — proven findings first, candidates and filtered ones below.
          </p>
        </div>
      </div>

      <div className="card filter-card">
        <div className="search-box">
          <Search size={16} className="search-icon" />
          <input type="text" placeholder="Search title, type, or description…" value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)} />
          {searchQuery && <button className="clear-search" onClick={() => setSearchQuery('')}><XCircle size={14} /></button>}
        </div>
        <div className="filter-dropdowns">
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="filter-select">
            <option value="">All severities</option>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
          </select>
          <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className="filter-select">
            <option value="">All types</option>
            <option value="xss">XSS</option>
            <option value="sqli">SQL Injection</option>
            <option value="idor">IDOR</option>
            <option value="csrf">CSRF</option>
            <option value="auth_bypass">Auth Bypass</option>
            <option value="security_headers">Security Headers</option>
            <option value="insecure_cookie">Insecure Cookie</option>
            <option value="info_disclosure">Info Disclosure</option>
            <option value="open_redirect">Open Redirect</option>
          </select>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="filter-select">
            <option value="">All statuses</option>
            <option value="confirmed">Confirmed</option>
            <option value="candidate">Candidate</option>
            <option value="rejected">Rejected</option>
            <option value="false_positive">False Positive</option>
          </select>
          {hasFilters && <button className="btn btn-sm btn-secondary" onClick={resetFilters}><RotateCcw size={13} /><span>Reset</span></button>}
        </div>
      </div>

      {fetchError && <div className="card scans-error">{fetchError}</div>}

      {loading && findings.length === 0 ? (
        <div className="loading-container"><div className="spinner" /></div>
      ) : (
        <div className="card table-card">
          <div className="table-wrapper">
            <table>
              <thead>
                <tr><th>Severity</th><th>Type</th><th>Finding</th><th>Status</th><th>Found</th><th></th></tr>
              </thead>
              <tbody>
                {rows.length === 0 ? (
                  <tr className="empty-row">
                    <td colSpan={6}>
                      <div className="empty-state">
                        <ShieldAlert size={40} />
                        <h3 className="text-subheading">No findings</h3>
                        <p className="text-muted">{hasFilters ? 'Try clearing your filters.' : 'Run a scan to discover vulnerabilities.'}</p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  rows.map((f) => {
                    const Icon = STATUS_ICON[f.status] || HelpCircle;
                    return (
                      <tr key={f.id} className="finding-tr">
                        <td><SeverityBadge severity={f.severity} size="sm" /></td>
                        <td><span className="type-tag text-mono">{f.type?.toUpperCase()}</span></td>
                        <td>
                          <Link to={`/findings/${f.id}`} className="finding-title-link">{f.title}</Link>
                        </td>
                        <td><span className={`status-pill pill-${f.status}`}><Icon size={12} /><span>{f.status.replace('_', ' ')}</span></span></td>
                        <td className="text-caption text-muted">
                          {new Date(f.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                        </td>
                        <td><Link to={`/findings/${f.id}`} className="scan-open"><ArrowUpRight size={15} /></Link></td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
