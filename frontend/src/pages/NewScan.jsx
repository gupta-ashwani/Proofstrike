import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { Zap, Sliders, Shield, AlertCircle, Plus, Check } from 'lucide-react';
import api from '../hooks/useApi';
import './NewScan.css';

export default function NewScan() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const preselectedTargetId = searchParams.get('target_id') || '';

  const [targets, setTargets] = useState([]);
  const [targetId, setTargetId] = useState(preselectedTargetId);
  const [depth, setDepth] = useState(3);
  const [budget, setBudget] = useState(250);
  const [detectors, setDetectors] = useState({
    xss: true,
    sqli: true,
    idor: true,
    csrf: false,
  });
  const [loadingTargets, setLoadingTargets] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function loadTargets() {
      try {
        const data = await api.get('/targets');
        setTargets(data.targets || []);
        if (!targetId && data.targets?.length > 0) {
          setTargetId(data.targets[0].id);
        }
      } catch (err) {
        setError('Failed to load targets. Please register one first.');
      } finally {
        setLoadingTargets(false);
      }
    }
    loadTargets();
  }, []);

  const toggleDetector = (key) => {
    setDetectors((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!targetId) {
      setError('Please select a target application');
      return;
    }

    const selectedDetectors = Object.keys(detectors).filter((k) => detectors[k]);
    if (selectedDetectors.length === 0) {
      setError('Please select at least one security detector module');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const scan = await api.post('/scans', {
        target_id: targetId,
        config: {
          crawl_depth: Number(depth),
          request_budget: Number(budget),
          detectors: selectedDetectors,
        },
      });

      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError(err.message || 'Failed to start scan');
      setSubmitting(false);
    }
  };

  return (
    <div className="new-scan-page animate-slide-up">
      <div className="page-header">
        <div>
          <h1 className="page-title">Configure & Launch Scan</h1>
          <p className="text-secondary text-body">
            Set up crawler limits, differential detection modules, and execution boundaries.
          </p>
        </div>
      </div>

      <div className="new-scan-container">
        <form onSubmit={handleSubmit} className="card new-scan-card">
          {error && (
            <div className="scan-form-error">
              <AlertCircle size={18} />
              <span>{error}</span>
            </div>
          )}

          {/* Target Selection */}
          <div className="form-section">
            <div className="section-title-bar">
              <span className="section-number">1</span>
              <h3 className="text-subheading">Target Application</h3>
            </div>

            {loadingTargets ? (
              <div className="spinner" />
            ) : targets.length === 0 ? (
              <div className="no-targets-notice">
                <p className="text-muted text-body">
                  No targets found in database. Create one to begin.
                </p>
                <Link to="/targets" className="btn btn-sm btn-secondary mt-sm">
                  <Plus size={14} />
                  <span>Create Target</span>
                </Link>
              </div>
            ) : (
              <div className="form-group">
                <label className="form-label">Select Target</label>
                <select
                  value={targetId}
                  onChange={(e) => setTargetId(e.target.value)}
                  className="target-select"
                >
                  {targets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name} — {t.base_url}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Crawler Configuration */}
          <div className="form-section">
            <div className="section-title-bar">
              <span className="section-number">2</span>
              <h3 className="text-subheading">Crawler Engine Limits</h3>
            </div>

            <div className="crawler-controls">
              <div className="form-group">
                <div className="slider-label-row">
                  <label className="form-label">Crawl Depth</label>
                  <span className="slider-val text-mono">{depth} levels</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="5"
                  value={depth}
                  onChange={(e) => setDepth(e.target.value)}
                  className="range-input"
                />
                <span className="form-hint">
                  Maximum link hop depth from the base URL.
                </span>
              </div>

              <div className="form-group">
                <label className="form-label">Request Budget</label>
                <input
                  type="number"
                  min="50"
                  max="2000"
                  step="50"
                  value={budget}
                  onChange={(e) => setBudget(e.target.value)}
                />
                <span className="form-hint">
                  Safety budget to prevent infinite crawling on large apps.
                </span>
              </div>
            </div>
          </div>

          {/* Active Security Detectors */}
          <div className="form-section">
            <div className="section-title-bar">
              <span className="section-number">3</span>
              <h3 className="text-subheading">Differential Detectors</h3>
            </div>

            <div className="detectors-list">
              <div
                className={`detector-item ${detectors.xss ? 'selected' : ''}`}
                onClick={() => toggleDetector('xss')}
              >
                <div className="detector-check">
                  {detectors.xss && <Check size={14} />}
                </div>
                <div className="detector-info">
                  <div className="detector-name">Cross-Site Scripting (XSS)</div>
                  <div className="detector-desc text-caption text-secondary">
                    Marker reflection & safe context escape confirmation in DOM
                  </div>
                </div>
              </div>

              <div
                className={`detector-item ${detectors.sqli ? 'selected' : ''}`}
                onClick={() => toggleDetector('sqli')}
              >
                <div className="detector-check">
                  {detectors.sqli && <Check size={14} />}
                </div>
                <div className="detector-info">
                  <div className="detector-name">SQL Injection (SQLi)</div>
                  <div className="detector-desc text-caption text-secondary">
                    Error-based, time-based, and boolean differential response validation
                  </div>
                </div>
              </div>

              <div
                className={`detector-item ${detectors.idor ? 'selected' : ''}`}
                onClick={() => toggleDetector('idor')}
              >
                <div className="detector-check">
                  {detectors.idor && <Check size={14} />}
                </div>
                <div className="detector-info">
                  <div className="detector-name">Insecure Direct Object Reference (IDOR)</div>
                  <div className="detector-desc text-caption text-secondary">
                    Cross-session differential analysis (User A vs User B data leak)
                  </div>
                </div>
              </div>

              <div
                className={`detector-item ${detectors.csrf ? 'selected' : ''}`}
                onClick={() => toggleDetector('csrf')}
              >
                <div className="detector-check">
                  {detectors.csrf && <Check size={14} />}
                </div>
                <div className="detector-info">
                  <div className="detector-name">CSRF & Missing Protection</div>
                  <div className="detector-desc text-caption text-secondary">
                    State-changing request anti-CSRF token verification
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="scan-submit-box">
            <button
              type="submit"
              className="btn btn-lg btn-primary w-full"
              disabled={submitting || targets.length === 0}
            >
              <Zap size={18} />
              <span>{submitting ? 'Initializing Job...' : 'Launch Scan ⚡'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
