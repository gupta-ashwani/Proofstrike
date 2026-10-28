import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  Clock,
  Compass,
  ShieldAlert,
  StopCircle,
  Download,
  AlertCircle,
  CheckCircle2,
  ExternalLink,
  Lock,
  ArrowLeft,
} from 'lucide-react';
import api from '../hooks/useApi';
import StatusBadge from '../components/StatusBadge';
import FindingCard from '../components/FindingCard';
import DiffView from '../components/DiffView';
import './ScanDetails.css';

const PHASES = ['queued', 'crawling', 'testing', 'verifying', 'completed'];

export default function ScanDetails() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [target, setTarget] = useState(null);
  const [endpoints, setEndpoints] = useState([]);
  const [findings, setFindings] = useState([]);
  const [diff, setDiff] = useState(null);
  const [progress, setProgress] = useState(null);
  const [activeTab, setActiveTab] = useState('endpoints');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [stopping, setStopping] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);

  const fetchScanData = async () => {
    try {
      const [scanData, progressData, endpointsData, findingsData, diffData] =
        await Promise.all([
          api.get(`/scans/${id}`),
          api.get(`/scans/${id}/progress`).catch(() => null),
          api.get(`/scans/${id}/endpoints`).catch(() => ({ endpoints: [] })),
          api.get(`/scans/${id}/findings`).catch(() => ({ findings: [] })),
          // 404 until the scan has completed and a diff exists.
          api.get(`/scans/${id}/diff`).catch(() => null),
        ]);

      setScan(scanData);
      setProgress(progressData);
      setEndpoints(endpointsData?.endpoints || []);
      setFindings(findingsData?.findings || []);
      setDiff(diffData);

      if (scanData?.target_id) {
        const targetData = await api.get(`/targets/${scanData.target_id}`).catch(() => null);
        setTarget(targetData);
      }
    } catch (err) {
      setError(err.message || 'Failed to fetch scan details');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScanData();

    // Auto-poll progress if scan is actively running
    const interval = setInterval(() => {
      if (
        scan &&
        ['queued', 'crawling', 'testing', 'verifying'].includes(scan.status)
      ) {
        fetchScanData();
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [id, scan?.status]);

  const handleStop = async () => {
    if (!window.confirm('Are you sure you want to stop this scan?')) return;
    setStopping(true);
    try {
      const updated = await api.post(`/scans/${id}/stop`);
      setScan(updated);
    } catch (err) {
      alert(err.message || 'Failed to stop scan');
    } finally {
      setStopping(false);
    }
  };

  const handleExport = (format) => {
    setExportOpen(false);
    window.open(`/api/scans/${id}/report?format=${format}`, '_blank');
  };

  if (loading && !scan) {
    return (
      <div className="loading-container">
        <div className="spinner" />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="card scan-error-card">
        <AlertCircle size={24} />
        <div>
          <h3>Scan Error</h3>
          <p className="text-secondary">{error || 'Scan not found'}</p>
          <Link to="/scans" className="btn btn-secondary btn-sm mt-sm">
            Back to Scans
          </Link>
        </div>
      </div>
    );
  }

  const isActive = ['queued', 'crawling', 'testing', 'verifying'].includes(scan.status);
  const currentPhaseIndex = PHASES.indexOf(scan.status);

  return (
    <div className="scan-details-page animate-slide-up">
      <div className="back-bar">
        <Link to={`/targets/${scan.target_id}`} className="back-link">
          <ArrowLeft size={15} /><span>{target?.name || 'Target'}</span>
        </Link>
      </div>

      {/* Header Banner */}
      <div className="scan-details-header card">
        <div className="header-left">
          <div className="scan-title-row">
            <span className="text-mono scan-id-tag">Scan #{scan.id.substring(0, 8)}</span>
            <StatusBadge status={scan.status} size="lg" />
          </div>
          <h2 className="scan-target-title">
            <Link to={`/targets/${scan.target_id}`} className="scan-target-link">
              {target?.name || 'Target Scope'}
            </Link>{' '}
            {target?.base_url && (
              <a
                href={target.base_url}
                target="_blank"
                rel="noreferrer"
                className="target-external-link text-mono"
              >
                <span>{target.base_url}</span>
                <ExternalLink size={12} />
              </a>
            )}
          </h2>
          <div className="scan-timestamps text-caption text-muted">
            <span>Started: {scan.started_at ? new Date(scan.started_at).toLocaleString() : 'Pending'}</span>
            {scan.completed_at && (
              <span>• Completed: {new Date(scan.completed_at).toLocaleString()}</span>
            )}
            {progress?.elapsed_seconds && (
              <span>• Runtime: {Math.round(progress.elapsed_seconds)}s</span>
            )}
          </div>
        </div>

        <div className="header-actions">
          {isActive && (
            <button
              className="btn btn-danger"
              onClick={handleStop}
              disabled={stopping}
            >
              <StopCircle size={16} />
              <span>{stopping ? 'Stopping...' : 'Stop Scan'}</span>
            </button>
          )}
          <div className="export-menu-wrap">
            <button className="btn btn-secondary" onClick={() => setExportOpen((o) => !o)}>
              <Download size={16} />
              <span>Export Report</span>
            </button>
            {exportOpen && (
              <>
                <div className="export-backdrop" onClick={() => setExportOpen(false)} />
                <div className="export-menu">
                  <button onClick={() => handleExport('pdf')}>PDF report</button>
                  <button onClick={() => handleExport('html')}>HTML report</button>
                  <button onClick={() => handleExport('json')}>JSON (raw data)</button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Progress Stepper */}
      <div className="card stepper-card">
        <div className="stepper-title text-caption text-muted">Scan Execution Pipeline</div>
        <div className="stepper">
          {PHASES.map((phase, idx) => {
            const isPassed = currentPhaseIndex > idx || scan.status === 'completed';
            const isCurrent = scan.status === phase;
            return (
              <div
                key={phase}
                className={`step-item ${isPassed ? 'passed' : ''} ${isCurrent ? 'current' : ''}`}
              >
                <div className="step-circle">
                  {isPassed ? <CheckCircle2 size={16} /> : idx + 1}
                </div>
                <span className="step-name">{phase}</span>
                {idx < PHASES.length - 1 && <div className="step-line" />}
              </div>
            );
          })}
        </div>
      </div>

      {/* Quick Telemetry Bar */}
      <div className="telemetry-bar">
        <div className="card telemetry-card">
          <Compass size={20} />
          <div>
            <span className="telemetry-val text-mono">{endpoints.length}</span>
            <span className="telemetry-lbl text-caption text-muted">Discovered Endpoints</span>
          </div>
        </div>

        <div className="card telemetry-card">
          <ShieldAlert size={20} />
          <div>
            <span className="telemetry-val text-mono">{findings.length}</span>
            <span className="telemetry-lbl text-caption text-muted">Detected Findings</span>
          </div>
        </div>

        <div className="card telemetry-card">
          <Clock size={20} />
          <div>
            <span className="telemetry-val text-mono">
              {scan.stats?.max_depth ?? scan.config?.crawl_depth ?? scan.config?.max_depth ?? 5}
            </span>
            <span className="telemetry-lbl text-caption text-muted">Configured Depth</span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="scan-tabs">
        <div className="tabs">
          <button
            className={`tab ${activeTab === 'endpoints' ? 'active' : ''}`}
            onClick={() => setActiveTab('endpoints')}
          >
            Discovered Endpoints ({endpoints.length})
          </button>
          <button
            className={`tab ${activeTab === 'findings' ? 'active' : ''}`}
            onClick={() => setActiveTab('findings')}
          >
            Findings & Candidates ({findings.length})
          </button>
          {diff && (
            <button
              className={`tab ${activeTab === 'changes' ? 'active' : ''}`}
              onClick={() => setActiveTab('changes')}
            >
              Changes{' '}
              {diff.is_baseline
                ? '(baseline)'
                : `(+${diff.new_count} / -${diff.fixed_count})`}
            </button>
          )}
          <button
            className={`tab ${activeTab === 'config' ? 'active' : ''}`}
            onClick={() => setActiveTab('config')}
          >
            Job Configuration
          </button>
        </div>

        {/* Endpoints Tab */}
        {activeTab === 'endpoints' && (
          <div className="card tab-pane">
            {endpoints.length === 0 ? (
              <div className="empty-state">
                <Compass size={40} />
                <p className="text-secondary">No endpoints discovered yet</p>
                <span className="text-caption text-muted">
                  The crawler will stream discovered routes and forms here.
                </span>
              </div>
            ) : (
              <div className="table-wrapper">
                <table>
                  <thead>
                    <tr>
                      <th>Method</th>
                      <th>Discovered URL</th>
                      <th>Source</th>
                      <th>Auth Required</th>
                      <th>Params</th>
                    </tr>
                  </thead>
                  <tbody>
                    {endpoints.map((ep) => (
                      <tr key={ep.id}>
                        <td>
                          <span className={`method-badge method-${ep.method.toLowerCase()} text-mono`}>
                            {ep.method}
                          </span>
                        </td>
                        <td className="text-mono ep-url">{ep.url}</td>
                        <td className="text-caption text-secondary">{ep.source}</td>
                        <td>
                          {ep.auth_required ? (
                            <span className="auth-lock text-caption">
                              <Lock size={12} /> Yes
                            </span>
                          ) : (
                            <span className="text-caption text-muted">No</span>
                          )}
                        </td>
                        <td className="text-caption text-muted">
                          {ep.params ? Object.keys(ep.params).join(', ') : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Findings Tab */}
        {activeTab === 'findings' && (
          <div className="findings-tab-pane">
            {findings.length === 0 ? (
              <div className="card empty-state">
                <ShieldAlert size={40} />
                <p className="text-secondary">No vulnerabilities identified</p>
                <span className="text-caption text-muted">
                  Vulnerability candidates generated by detectors will appear here.
                </span>
              </div>
            ) : (
              <div className="findings-grid">
                {findings.map((finding) => (
                  <FindingCard key={finding.id} finding={finding} />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Changes (differential) Tab */}
        {activeTab === 'changes' && diff && (
          <div className="card">
            <DiffView diff={diff} />
          </div>
        )}

        {/* Configuration Tab */}
        {activeTab === 'config' && (
          <div className="card config-pane">
            <h4 className="text-subheading mb-md">Scan Execution Parameters</h4>
            <pre className="code-block text-mono">
              <code>{JSON.stringify(scan.config, null, 2) || '{}'}</code>
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
