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
  const [requestDelay, setRequestDelay] = useState(0);
  const [maxConcurrency, setMaxConcurrency] = useState(1);
  const [scopeHosts, setScopeHosts] = useState('');
  const [useSitemap, setUseSitemap] = useState(true);
  const [detectors, setDetectors] = useState({
    xss: true,
    sqli: true,
    idor: true,
    csrf: true,
    passive: true,
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
          request_delay: Number(requestDelay),
          max_concurrency: Number(maxConcurrency),
          scope_hosts: scopeHosts.split(/[\s,]+/).filter(Boolean),
          use_sitemap: useSitemap,
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
              <h3 className="text-subheading">Crawler Limits & Rate Control</h3>
            </div>

            <div className="crawler-controls">
              <div className="form-group">
                <div className="slider-label-row">
                  <label className="form-label">Crawl Depth</label>
                  <span className="slider-val text-mono">{depth} {depth === 1 ? 'level' : 'levels'}</span>
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
                  How many link-hops to follow from the start URL. 1 = start page + its
                  direct links. Higher = deeper coverage, but slower.
                </span>
              </div>

              <div className="form-group">
                <label className="form-label">Request Budget (max pages)</label>
                <input
                  type="number"
                  min="1"
                  max="2000"
                  step="1"
                  value={budget}
                  onChange={(e) => setBudget(e.target.value)}
                />
                <span className="form-hint">
                  Hard cap on total pages visited. The crawl stops here even if more pages
                  exist within the depth limit.
                </span>
              </div>

              <div className="form-group">
                <label className="form-label">Request Delay</label>
                <select
                  value={requestDelay}
                  onChange={(e) => setRequestDelay(e.target.value)}
                >
                  <option value="0">None — fastest</option>
                  <option value="0.25">0.25s — light</option>
                  <option value="0.5">0.5s — polite</option>
                  <option value="1">1s — gentle</option>
                  <option value="2">2s — very gentle</option>
                </select>
                <span className="form-hint">
                  Minimum gap between requests. Raise it for shared, public, or fragile
                  targets so the scan stays polite and avoids rate-limiting.
                </span>
              </div>

              <div className="form-group">
                <div className="slider-label-row">
                  <label className="form-label">Max Concurrency</label>
                  <span className="slider-val text-mono">
                    {maxConcurrency} {maxConcurrency === 1 ? 'request' : 'requests'}
                  </span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="8"
                  value={maxConcurrency}
                  onChange={(e) => setMaxConcurrency(e.target.value)}
                  className="range-input"
                />
                <span className="form-hint">
                  How many requests may run at once. Crawling is sequential; this mainly
                  speeds up the testing phase. Lower = gentler on the target.
                </span>
              </div>
            </div>

            <div className="form-group scope-group">
              <label className="form-label">Additional In-Scope Hosts (optional)</label>
              <input
                type="text"
                placeholder="api.example.com, staging.example.com"
                value={scopeHosts}
                onChange={(e) => setScopeHosts(e.target.value)}
              />
              <span className="form-hint">
                The target's own host (and its subdomains) is always in scope. Add other
                hosts here — e.g. a separate API subdomain — to crawl them too. Comma or
                space separated.
              </span>
            </div>

            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={useSitemap}
                onChange={(e) => setUseSitemap(e.target.checked)}
              />
              <span>
                <span className="checkbox-title">Discover from sitemap.xml &amp; robots.txt</span>
                <span className="form-hint">
                  Seed the crawl with URLs from the target's sitemap and robots.txt, to
                  reach pages that nothing links to.
                </span>
              </span>
            </label>
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

              <div
                className={`detector-item ${detectors.passive ? 'selected' : ''}`}
                onClick={() => toggleDetector('passive')}
              >
                <div className="detector-check">
                  {detectors.passive && <Check size={14} />}
                </div>
                <div className="detector-info">
                  <div className="detector-name">Passive Checks</div>
                  <div className="detector-desc text-caption text-secondary">
                    Security headers, cookie flags, info disclosure & open redirect
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
