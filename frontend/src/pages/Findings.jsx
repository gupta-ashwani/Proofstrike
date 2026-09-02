import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  Filter,
  ArrowUpRight,
  ShieldCheck,
  HelpCircle,
  XCircle,
  RotateCcw,
} from 'lucide-react';
import api from '../hooks/useApi';
import SeverityBadge from '../components/SeverityBadge';
import './Findings.css';

export default function Findings() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState(searchParams.get('severity') || '');
  const [typeFilter, setTypeFilter] = useState(searchParams.get('type') || '');
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || '');

  const fetchFindings = async () => {
    setLoading(true);
    setError(null);
    try {
      let queryParams = [];
      if (severityFilter) queryParams.push(`severity=${severityFilter}`);
      if (typeFilter) queryParams.push(`type=${typeFilter}`);
      if (statusFilter) queryParams.push(`status=${statusFilter}`);

      const qs = queryParams.length ? `?${queryParams.join('&')}` : '';
      const data = await api.get(`/findings${qs}`);
      setFindings(data.findings || []);
    } catch (err) {
      setError(err.message || 'Failed to load findings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [severityFilter, typeFilter, statusFilter]);

  const resetFilters = () => {
    setSearchQuery('');
    setSeverityFilter('');
    setTypeFilter('');
    setStatusFilter('');
    setSearchParams({});
  };

  // Client-side text filter for search query
  const filteredFindings = findings.filter((f) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.title?.toLowerCase().includes(q) ||
      f.description?.toLowerCase().includes(q) ||
      f.type?.toLowerCase().includes(q)
    );
  });

  return (
    <div className="findings-page animate-slide-up">
      <div className="page-header">
        <div>
          <h1 className="page-title">Vulnerability Findings</h1>
          <p className="text-secondary text-body">
            Search, filter, and inspect verified security findings and active candidates across all scopes.
          </p>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="card filter-card">
        <div className="search-box">
          <Search size={16} className="search-icon" />
          <input
            type="text"
            placeholder="Search by title, payload, or description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          {searchQuery && (
            <button className="clear-search" onClick={() => setSearchQuery('')}>
              <XCircle size={14} />
            </button>
          )}
        </div>

        <div className="filter-dropdowns">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="filter-select"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="filter-select"
          >
            <option value="">All Categories</option>
            <option value="xss">Cross-Site Scripting (XSS)</option>
            <option value="sqli">SQL Injection (SQLi)</option>
            <option value="idor">IDOR / Access Control</option>
            <option value="csrf">CSRF</option>
            <option value="auth_bypass">Auth Bypass</option>
            <option value="info_disclosure">Info Disclosure</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="filter-select"
          >
            <option value="">All Statuses</option>
            <option value="candidate">Candidate</option>
            <option value="confirmed">Confirmed</option>
            <option value="rejected">Rejected</option>
            <option value="false_positive">False Positive</option>
          </select>

          {(severityFilter || typeFilter || statusFilter || searchQuery) && (
            <button className="btn btn-sm btn-secondary" onClick={resetFilters}>
              <RotateCcw size={13} />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* Findings Table */}
      {loading ? (
        <div className="loading-container">
          <div className="spinner" />
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="card empty-state">
          <ShieldAlert size={48} />
          <h3 className="text-subheading">No Findings Found</h3>
          <p className="text-muted">
            {severityFilter || typeFilter || statusFilter || searchQuery
              ? 'Try changing or clearing your search filters.'
              : 'Launch a security scan to start discovering vulnerabilities.'}
          </p>
        </div>
      ) : (
        <div className="card table-card">
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Category</th>
                  <th>Finding Title</th>
                  <th>Verification Status</th>
                  <th>Discovered</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map((finding) => {
                  const isConfirmed = finding.status === 'confirmed';
                  return (
                    <tr key={finding.id}>
                      <td>
                        <SeverityBadge severity={finding.severity} size="sm" />
                      </td>
                      <td>
                        <span className="type-tag text-mono">{finding.type?.toUpperCase()}</span>
                      </td>
                      <td>
                        <Link to={`/findings/${finding.id}`} className="finding-table-title">
                          {finding.title}
                        </Link>
                      </td>
                      <td>
                        <span className={`status-pill pill-${finding.status}`}>
                          {isConfirmed ? (
                            <ShieldCheck size={12} />
                          ) : (
                            <HelpCircle size={12} />
                          )}
                          <span>{finding.status}</span>
                        </span>
                      </td>
                      <td className="text-caption text-muted">
                        {new Date(finding.created_at).toLocaleDateString(undefined, {
                          month: 'short',
                          day: 'numeric',
                        })}
                      </td>
                      <td>
                        <Link to={`/findings/${finding.id}`} className="inspect-btn">
                          <span>Evidence</span>
                          <ArrowUpRight size={13} />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
