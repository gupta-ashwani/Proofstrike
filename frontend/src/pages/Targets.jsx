import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Plus, Globe, Trash2, Edit2, AlertCircle, X,
  CalendarClock, Repeat, ShieldAlert, ShieldCheck, ArrowUpRight,
} from 'lucide-react';
import api from '../hooks/useApi';
import ScheduleModal from '../components/ScheduleModal';
import { formatInterval, formatCountdown } from '../lib/format';
import './Targets.css';

export default function Targets() {
  const [targets, setTargets] = useState([]);
  const [diffs, setDiffs] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Add / edit modal
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingTarget, setEditingTarget] = useState(null);
  const [name, setName] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [authConfigJson, setAuthConfigJson] = useState('');
  const [saving, setSaving] = useState(false);

  // Schedule modal
  const [scheduleTarget, setScheduleTarget] = useState(null);

  const fetchTargets = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get('/targets');
      const tgs = data.targets || [];
      setTargets(tgs);
      const entries = await Promise.all(
        tgs.map((t) => api.get(`/targets/${t.id}/diff/latest`).then((d) => [t.id, d], () => [t.id, null])),
      );
      setDiffs(Object.fromEntries(entries));
    } catch (err) {
      setError(err.message || 'Failed to load targets');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchTargets(); }, []);

  const openAddModal = () => {
    setEditingTarget(null); setName(''); setBaseUrl(''); setAuthConfigJson(''); setIsModalOpen(true);
  };
  const openEditModal = (target) => {
    setEditingTarget(target); setName(target.name); setBaseUrl(target.base_url);
    setAuthConfigJson(target.auth_config ? JSON.stringify(target.auth_config, null, 2) : '');
    setIsModalOpen(true);
  };
  const closeModal = () => { setIsModalOpen(false); setEditingTarget(null); };

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true); setError(null);
    let parsedAuth = null;
    if (authConfigJson.trim()) {
      try { parsedAuth = JSON.parse(authConfigJson); }
      catch { setError('Auth config must be valid JSON'); setSaving(false); return; }
    }
    try {
      if (editingTarget) {
        await api.put(`/targets/${editingTarget.id}`, { name, base_url: baseUrl, auth_config: parsedAuth });
      } else {
        await api.post('/targets', { name, base_url: baseUrl, auth_config: parsedAuth });
      }
      closeModal(); fetchTargets();
    } catch (err) {
      setError(err.message || 'Failed to save target');
    } finally { setSaving(false); }
  };

  const handleDelete = async (id, targetName) => {
    if (!window.confirm(`Remove target "${targetName}" and all its scans? This cannot be undone.`)) return;
    try {
      await api.del(`/targets/${id}`);
      setTargets((prev) => prev.filter((t) => t.id !== id));
    } catch (err) {
      alert(err.message || 'Failed to delete target');
    }
  };

  const onScheduleSaved = (updated) =>
    setTargets((prev) => prev.map((t) => (t.id === updated.id ? { ...t, ...updated } : t)));

  return (
    <div className="targets-page animate-slide-up">
      <div className="page-header">
        <div>
          <h1 className="page-title">Targets</h1>
          <p className="text-secondary text-body">
            Monitored applications — each with its own posture, schedule, and scan history.
          </p>
        </div>
        <button className="btn btn-primary" onClick={openAddModal}>
          <Plus size={16} /><span>Add Target</span>
        </button>
      </div>

      {error && !isModalOpen && (
        <div className="card targets-error-card"><AlertCircle size={18} /><span>{error}</span></div>
      )}

      {loading ? (
        <div className="loading-container"><div className="spinner" /></div>
      ) : targets.length === 0 ? (
        <div className="card empty-state">
          <Globe size={48} />
          <h3 className="text-subheading">No targets yet</h3>
          <p className="text-muted">Add a web application to start continuous, differential scanning.</p>
          <button className="btn btn-primary mt-sm" onClick={openAddModal}><Plus size={15} /><span>Add first target</span></button>
        </div>
      ) : (
        <div className="targets-grid">
          {targets.map((target) => {
            const d = diffs[target.id];
            const open = d ? d.new_count + d.unchanged_count : null;
            return (
              <div key={target.id} className="card target-card">
                <div className="target-card-top">
                  <Link to={`/targets/${target.id}`} className="target-title-area">
                    <h3 className="target-name">{target.name}</h3>
                    <span className="target-url text-mono text-muted">{target.base_url}</span>
                  </Link>
                  <div className="target-actions">
                    <button className={`btn-icon${target.schedule_enabled ? ' btn-icon-active' : ''}`}
                      title={target.schedule_enabled ? 'Continuous scan: on' : 'Schedule scans'}
                      onClick={() => setScheduleTarget(target)}>
                      <CalendarClock size={15} />
                    </button>
                    <button className="btn-icon" title="Edit target" onClick={() => openEditModal(target)}><Edit2 size={15} /></button>
                    <button className="btn-icon btn-icon-danger" title="Delete target" onClick={() => handleDelete(target.id, target.name)}><Trash2 size={15} /></button>
                  </div>
                </div>

                <Link to={`/targets/${target.id}`} className="target-posture">
                  {open === null ? (
                    <span className="posture-chip neutral">Not scanned yet</span>
                  ) : open === 0 ? (
                    <span className="posture-chip clean"><ShieldCheck size={14} /> No open issues</span>
                  ) : (
                    <span className="posture-chip open"><ShieldAlert size={14} /> {open} open confirmed</span>
                  )}
                  {d && !d.is_baseline && (d.new_count > 0 || d.fixed_count > 0) && (
                    <span className="posture-delta">
                      {d.new_count > 0 && <span className="delta-new">+{d.new_count}</span>}
                      {d.fixed_count > 0 && <span className="delta-fixed">−{d.fixed_count}</span>}
                      <span className="text-muted text-caption">since last</span>
                    </span>
                  )}
                </Link>

                <div className="target-foot">
                  <span className="target-foot-item text-caption text-muted">
                    {target.auth_config ? <span className="auth-pill active">Auth</span> : <span className="auth-pill none">No auth</span>}
                  </span>
                  <span className="target-foot-item text-caption text-muted">
                    {target.schedule_enabled
                      ? <span className="sched-on"><Repeat size={12} /> {formatInterval(target.scan_interval_minutes)} · next {formatCountdown(target.next_scan_at) || '—'}</span>
                      : 'Manual scans'}
                  </span>
                  <Link to={`/targets/${target.id}`} className="target-open-link">Open <ArrowUpRight size={13} /></Link>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Add / Edit modal */}
      {isModalOpen && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="text-subheading">{editingTarget ? 'Edit target' : 'Add target'}</h3>
              <button className="btn-ghost" onClick={closeModal}><X size={18} /></button>
            </div>
            <form onSubmit={handleSave} className="target-form">
              {error && <div className="form-error"><AlertCircle size={15} /><span>{error}</span></div>}
              <div className="form-group">
                <label className="form-label">Target name</label>
                <input type="text" required placeholder="e.g. Juice Shop Staging" value={name} onChange={(e) => setName(e.target.value)} />
              </div>
              <div className="form-group">
                <label className="form-label">Base URL</label>
                <input type="url" required placeholder="https://example.com" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
                <span className="form-hint">The crawler stays within this host boundary.</span>
              </div>
              <div className="form-group">
                <label className="form-label">Auth configuration (optional JSON)</label>
                <textarea rows={4} className="text-mono"
                  placeholder='{"login_url": "/login", "username_selector": "#user", "password_selector": "#pass"}'
                  value={authConfigJson} onChange={(e) => setAuthConfigJson(e.target.value)} />
                <span className="form-hint">
                  Used for authenticated crawling.
                  {editingTarget?.auth_config && ' Saved passwords show as ******** — leave them to keep, clear to remove auth.'}
                </span>
              </div>
              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={closeModal}>Cancel</button>
                <button type="submit" className="btn btn-primary" disabled={saving}>
                  {saving ? 'Saving…' : editingTarget ? 'Save changes' : 'Create target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {scheduleTarget && (
        <ScheduleModal target={scheduleTarget} onClose={() => setScheduleTarget(null)} onSaved={onScheduleSaved} />
      )}
    </div>
  );
}
