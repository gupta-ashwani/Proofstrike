import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Activity, Plus, Filter, RotateCcw, AlertCircle } from 'lucide-react';
import api from '../hooks/useApi';
import ScanCard from '../components/ScanCard';
import './Scans.css';

export default function Scans() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || '');
  const [targetFilter, setTargetFilter] = useState(searchParams.get('target_id') || '');
  const [targetList, setTargetList] = useState([]);

  const fetchScans = async () => {
    setLoading(true);
    setError(null);
    try {
      let qParams = [];
      if (statusFilter) qParams.push(`status=${statusFilter}`);
      if (targetFilter) qParams.push(`target_id=${targetFilter}`);

      const qs = qParams.length ? `?${qParams.join('&')}` : '';
      const [scansData, targetsData] = await Promise.all([
        api.get(`/scans${qs}`),
        api.get('/targets').catch(() => ({ targets: [] })),
      ]);

      setScans(scansData.scans || []);
      setTargetList(targetsData.targets || []);

      const targetMap = {};
      (targetsData.targets || []).forEach((t) => {
        targetMap[t.id] = t.name;
      });
      setTargets(targetMap);
    } catch (err) {
      setError(err.message || 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [statusFilter, targetFilter]);

  const resetFilters = () => {
    setStatusFilter('');
    setTargetFilter('');
    setSearchParams({});
  };

  return (
    <div className="scans-page animate-slide-up">
      <div className="page-header">
        <div>
          <h1 className="page-title">Scan Management</h1>
          <p className="text-secondary text-body">
            Audit history, running crawlers, and vulnerability test telemetry.
          </p>
        </div>
        <Link to="/scans/new" className="btn btn-primary">
          <Plus size={16} />
          <span>Launch New Scan</span>
        </Link>
      </div>

      {/* Filter Bar */}
      <div className="card filter-bar">
        <div className="filter-controls">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="filter-select"
          >
            <option value="">All Statuses</option>
            <option value="queued">Queued</option>
            <option value="crawling">Crawling</option>
            <option value="testing">Testing</option>
            <option value="verifying">Verifying</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="stopped">Stopped</option>
          </select>

          <select
            value={targetFilter}
            onChange={(e) => setTargetFilter(e.target.value)}
            className="filter-select"
          >
            <option value="">All Targets</option>
            {targetList.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </select>

          {(statusFilter || targetFilter) && (
            <button className="btn btn-sm btn-secondary" onClick={resetFilters}>
              <RotateCcw size={13} />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {loading ? (
        <div className="loading-container">
          <div className="spinner" />
        </div>
      ) : scans.length === 0 ? (
        <div className="card empty-state">
          <Activity size={48} />
          <h3 className="text-subheading">No Scans Found</h3>
          <p className="text-muted">
            {statusFilter || targetFilter
              ? 'No scans match the selected criteria.'
              : 'Launch a security scan against a registered target.'}
          </p>
          <Link to="/scans/new" className="btn btn-primary mt-sm">
            <Plus size={15} />
            <span>Launch Scan</span>
          </Link>
        </div>
      ) : (
        <div className="scans-list">
          {scans.map((scan) => (
            <ScanCard key={scan.id} scan={scan} targetName={targets[scan.target_id]} />
          ))}
        </div>
      )}
    </div>
  );
}
