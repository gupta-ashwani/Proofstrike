import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { Zap, AlertCircle, Plus, Check, ChevronDown, ArrowLeft } from 'lucide-react';
import api from '../hooks/useApi';
import './NewScan.css';

const DETECTOR_INFO = [
  { key: 'xss', name: 'Cross-Site Scripting (XSS)', desc: 'Reflected, stored & DOM — confirmed by real browser execution' },
  { key: 'sqli', name: 'SQL Injection (SQLi)', desc: 'Boolean, error, time, UNION & second-order' },
  { key: 'idor', name: 'IDOR & Access Control', desc: 'Object enumeration + cross-session (User A vs User B)' },
  { key: 'csrf', name: 'CSRF', desc: 'State-changing requests with no anti-CSRF token' },
  { key: 'passive', name: 'Passive Checks', desc: 'Security headers, cookie flags, info disclosure, open redirect' },
];

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
  const [detectors, setDetectors] = useState({ xss: true, sqli: true, idor: true, csrf: true, passive: true });
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [loadingTargets, setLoadingTargets] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await api.get('/targets');
        setTargets(data.targets || []);
        if (!preselectedTargetId && data.targets?.length > 0) setTargetId(data.targets[0].id);
      } catch {
        setError('Failed to load targets — register one first.');
      } finally {
        setLoadingTargets(false);
      }
    })();
  }, [preselectedTargetId]);

  const toggleDetector = (key) => setDetectors((p) => ({ ...p, [key]: !p[key] }));
  const selectedCount = Object.values(detectors).filter(Boolean).length;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!targetId) { setError('Select a target to scan.'); return; }
    const selected = Object.keys(detectors).filter((k) => detectors[k]);
    if (selected.length === 0) { setError('Enable at least one detector.'); return; }

    setSubmitting(true); setError(null);
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
          detectors: selected,
        },
      });
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError(err.message || 'Failed to start scan');
      setSubmitting(false);
    }
  };

  const selectedTarget = targets.find((t) => t.id === targetId);

  return (
    <div className="new-scan-page animate-slide-up">
      <div className="back-bar">
        <Link to={preselectedTargetId ? `/targets/${preselectedTargetId}` : '/scans'} className="back-link">
          <ArrowLeft size={15} /><span>Back</span>
        </Link>
      </div>

      <div className="page-header">
        <div>
          <h1 className="page-title">New Scan</h1>
          <p className="text-secondary text-body">Pick a target and what to test. Crawler limits have sensible defaults.</p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="new-scan-form">
        {error && <div className="scan-form-error"><AlertCircle size={18} /><span>{error}</span></div>}

        {/* Target */}
        <div className="card ns-section">
          <label className="form-label" htmlFor="target">Target</label>
          {loadingTargets ? (
            <div className="spinner" />
          ) : targets.length === 0 ? (
            <div className="no-targets-notice">
              <p className="text-muted text-body">No targets yet — create one to begin.</p>
              <Link to="/targets" className="btn btn-sm btn-secondary mt-sm"><Plus size={14} /><span>Create target</span></Link>
            </div>
          ) : (
            <>
              <select id="target" value={targetId} onChange={(e) => setTargetId(e.target.value)}>
                {targets.map((t) => <option key={t.id} value={t.id}>{t.name} — {t.base_url}</option>)}
              </select>
              {selectedTarget && (
                <span className="form-hint">
                  {selectedTarget.auth_config ? 'Authenticated crawl (saved credentials).' : 'Unauthenticated crawl.'}
                </span>
              )}
            </>
          )}
        </div>

        {/* Detectors */}
        <div className="card ns-section">
          <div className="ns-section-head">
            <label className="form-label">What to test</label>
            <span className="text-caption text-muted">{selectedCount} of {DETECTOR_INFO.length} enabled</span>
          </div>
          <div className="detectors-list">
            {DETECTOR_INFO.map((d) => (
              <button type="button" key={d.key}
                className={`detector-item ${detectors[d.key] ? 'selected' : ''}`}
                onClick={() => toggleDetector(d.key)} aria-pressed={detectors[d.key]}>
                <span className="detector-check">{detectors[d.key] && <Check size={14} />}</span>
                <span className="detector-info">
                  <span className="detector-name">{d.name}</span>
                  <span className="detector-desc text-caption text-secondary">{d.desc}</span>
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Advanced (progressive disclosure) */}
        <div className="card ns-section ns-advanced">
          <button type="button" className="ns-advanced-toggle" onClick={() => setShowAdvanced((v) => !v)} aria-expanded={showAdvanced}>
            <span className="form-label">Advanced — crawler limits & scope</span>
            <ChevronDown size={16} className={`chev ${showAdvanced ? 'open' : ''}`} />
          </button>

          {showAdvanced && (
            <div className="ns-advanced-body">
              <div className="crawler-controls">
                <div className="form-group">
                  <div className="slider-label-row">
                    <label className="form-label" htmlFor="depth">Crawl depth</label>
                    <span className="slider-val text-mono">{depth} {depth === '1' || depth === 1 ? 'level' : 'levels'}</span>
                  </div>
                  <input id="depth" type="range" min="1" max="5" value={depth} onChange={(e) => setDepth(e.target.value)} className="range-input" />
                  <span className="form-hint">Link-hops to follow from the start URL. Higher = deeper but slower.</span>
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="budget">Request budget (max pages)</label>
                  <input id="budget" type="number" min="1" max="2000" step="1" value={budget} onChange={(e) => setBudget(e.target.value)} />
                  <span className="form-hint">Hard cap on pages visited.</span>
                </div>

                <div className="form-group">
                  <label className="form-label" htmlFor="delay">Request delay</label>
                  <select id="delay" value={requestDelay} onChange={(e) => setRequestDelay(e.target.value)}>
                    <option value="0">None — fastest</option>
                    <option value="0.25">0.25s — light</option>
                    <option value="0.5">0.5s — polite</option>
                    <option value="1">1s — gentle</option>
                    <option value="2">2s — very gentle</option>
                  </select>
                  <span className="form-hint">Minimum gap between requests. Raise for fragile targets.</span>
                </div>

                <div className="form-group">
                  <div className="slider-label-row">
                    <label className="form-label" htmlFor="conc">Max concurrency</label>
                    <span className="slider-val text-mono">{maxConcurrency} {maxConcurrency === '1' || maxConcurrency === 1 ? 'request' : 'requests'}</span>
                  </div>
                  <input id="conc" type="range" min="1" max="8" value={maxConcurrency} onChange={(e) => setMaxConcurrency(e.target.value)} className="range-input" />
                  <span className="form-hint">Parallel requests during testing. Lower = gentler.</span>
                </div>
              </div>

              <div className="form-group scope-group">
                <label className="form-label" htmlFor="scope">Additional in-scope hosts</label>
                <input id="scope" type="text" placeholder="api.example.com, staging.example.com" value={scopeHosts} onChange={(e) => setScopeHosts(e.target.value)} />
                <span className="form-hint">The target host is always in scope. Add others, comma or space separated.</span>
              </div>

              <label className="checkbox-row">
                <input type="checkbox" checked={useSitemap} onChange={(e) => setUseSitemap(e.target.checked)} />
                <span>
                  <span className="checkbox-title">Discover from sitemap.xml &amp; robots.txt</span>
                  <span className="form-hint">Seed the crawl with URLs nothing links to.</span>
                </span>
              </label>
            </div>
          )}
        </div>

        <div className="ns-submit">
          <button type="submit" className="btn btn-lg btn-primary" disabled={submitting}>
            <Zap size={18} /><span>{submitting ? 'Starting scan…' : 'Launch scan'}</span>
          </button>
        </div>
      </form>
    </div>
  );
}
