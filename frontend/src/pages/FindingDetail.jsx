import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileText,
  Wrench,
  RotateCcw,
  CheckCircle,
  ExternalLink,
  HelpCircle,
} from 'lucide-react';
import api from '../hooks/useApi';
import SeverityBadge from '../components/SeverityBadge';
import EvidenceViewer from '../components/EvidenceViewer';
import './FindingDetail.css';

export default function FindingDetail() {
  const { id } = useParams();
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [updating, setUpdating] = useState(false);

  const fetchFinding = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get(`/findings/${id}`);
      setFinding(data);
    } catch (err) {
      setError(err.message || 'Failed to load finding');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFinding();
  }, [id]);

  const handleStatusChange = async (newStatus) => {
    setUpdating(true);
    try {
      const updated = await api.patch(`/findings/${id}`, { status: newStatus });
      setFinding(updated);
    } catch (err) {
      alert(err.message || 'Failed to update finding status');
    } finally {
      setUpdating(false);
    }
  };

  const handleSeverityChange = async (newSeverity) => {
    setUpdating(true);
    try {
      const updated = await api.patch(`/findings/${id}`, { severity: newSeverity });
      setFinding(updated);
    } catch (err) {
      alert(err.message || 'Failed to update severity');
    } finally {
      setUpdating(false);
    }
  };

  if (loading && !finding) {
    return (
      <div className="loading-container">
        <div className="spinner" />
      </div>
    );
  }

  if (error || !finding) {
    return (
      <div className="card finding-error-card">
        <AlertTriangle size={24} />
        <div>
          <h3>Finding Not Found</h3>
          <p className="text-secondary">{error || 'Unable to locate finding data.'}</p>
          <Link to="/findings" className="btn btn-secondary btn-sm mt-sm">
            <ArrowLeft size={14} />
            <span>Return to Findings</span>
          </Link>
        </div>
      </div>
    );
  }

  const isFalsePositive = finding.status === 'false_positive';

  return (
    <div className="finding-detail-page animate-slide-up">
      {/* Back breadcrumb */}
      <div className="back-bar">
        <Link to="/findings" className="back-link">
          <ArrowLeft size={15} />
          <span>Back to Findings</span>
        </Link>
        {finding.scan_id && (
          <Link to={`/scans/${finding.scan_id}`} className="scan-ref-link">
            <span>View Parent Scan</span>
            <ExternalLink size={13} />
          </Link>
        )}
      </div>

      {/* Main Header Card */}
      <div className="card finding-header-card">
        <div className="finding-header-top">
          <div className="badges-row">
            <SeverityBadge severity={finding.severity} size="lg" />
            <span className="type-badge-lg text-mono">{finding.type?.toUpperCase()}</span>
            <span className={`status-pill-lg pill-${finding.status}`}>
              {finding.status === 'confirmed' ? (
                <ShieldCheck size={14} />
              ) : (
                <HelpCircle size={14} />
              )}
              <span>{finding.status}</span>
            </span>
          </div>

          <div className="finding-actions">
            {isFalsePositive ? (
              <button
                className="btn btn-sm btn-secondary"
                onClick={() => handleStatusChange('confirmed')}
                disabled={updating}
              >
                <RotateCcw size={14} />
                <span>Mark as Valid Finding</span>
              </button>
            ) : (
              <button
                className="btn btn-sm btn-danger"
                onClick={() => handleStatusChange('false_positive')}
                disabled={updating}
              >
                <AlertTriangle size={14} />
                <span>Mark False Positive</span>
              </button>
            )}

            <select
              value={finding.severity}
              onChange={(e) => handleSeverityChange(e.target.value)}
              disabled={updating}
              className="severity-select"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
        </div>

        <h1 className="finding-main-title">{finding.title}</h1>

        <div className="finding-timestamp-row text-caption text-muted">
          <span>Finding ID: <span className="text-mono">{finding.id}</span></span>
          <span>• Discovered: {new Date(finding.created_at).toLocaleString()}</span>
        </div>
      </div>

      {/* Content Layout */}
      <div className="finding-content-grid">
        <div className="detail-sections">
          {/* Description Section */}
          <div className="card detail-section">
            <div className="section-head">
              <FileText size={18} />
              <h3 className="text-subheading">Vulnerability Description</h3>
            </div>
            <p className="detail-text text-body">
              {finding.description || 'No detailed vulnerability description provided.'}
            </p>
          </div>

          {/* Reproduction Steps */}
          <div className="card detail-section">
            <div className="section-head">
              <ShieldAlert size={18} />
              <h3 className="text-subheading">Reproduction Steps</h3>
            </div>
            <div className="detail-text text-body">
              {finding.reproduction_steps ? (
                <pre className="repro-pre text-mono">{finding.reproduction_steps}</pre>
              ) : (
                <p className="text-muted">No explicit reproduction narrative provided.</p>
              )}
            </div>
          </div>

          {/* Remediation */}
          <div className="card detail-section">
            <div className="section-head">
              <Wrench size={18} />
              <h3 className="text-subheading">Remediation Guidance</h3>
            </div>
            <p className="detail-text text-body">
              {finding.remediation || 'Sanitize untrusted user input, enforce parameter binding, or encode output in strict context.'}
            </p>
          </div>
        </div>

        {/* Evidence Pipeline Artifacts */}
        <div className="evidence-section">
          <h3 className="text-subheading evidence-title">Proof of Exploitability</h3>
          <EvidenceViewer evidenceItems={finding.evidence_items || []} />
        </div>
      </div>
    </div>
  );
}
