import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Plus,
  Globe,
  Trash2,
  Edit2,
  Zap,
  Clock,
  ExternalLink,
  Shield,
  AlertCircle,
  X,
  CalendarClock,
  Repeat,
  Power,
} from 'lucide-react';
import api from '../hooks/useApi';
import './Targets.css';

// Interval presets offered in the schedule modal (value in minutes).
const INTERVAL_PRESETS = [
  { label: 'Every 15 minutes', value: 15 },
  { label: 'Hourly', value: 60 },
  { label: 'Every 6 hours', value: 360 },
  { label: 'Daily', value: 1440 },
  { label: 'Weekly', value: 10080 },
];

// Human-readable interval, e.g. 90 -> "1h 30m", 1440 -> "1d".
function formatInterval(mins) {
  if (!mins) return '—';
  const preset = INTERVAL_PRESETS.find((p) => p.value === mins);
  if (preset) return preset.label;
  const d = Math.floor(mins / 1440);
  const h = Math.floor((mins % 1440) / 60);
  const m = mins % 60;
  return [d && `${d}d`, h && `${h}h`, m && `${m}m`].filter(Boolean).join(' ');
}

// Relative time until an ISO timestamp, e.g. "in 42m", "in 3h", "due now".
function formatCountdown(iso) {
  if (!iso) return null;
  const secs = (new Date(iso).getTime() - Date.now()) / 1000;
  if (secs <= 30) return 'due now';
  if (secs < 3600) return `in ${Math.round(secs / 60)}m`;
  if (secs < 86400) return `in ${Math.round(secs / 3600)}h`;
  return `in ${Math.round(secs / 86400)}d`;
}

export default function Targets() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingTarget, setEditingTarget] = useState(null);
  const [name, setName] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [authConfigJson, setAuthConfigJson] = useState('');
  const [saving, setSaving] = useState(false);

  // Schedule modal state
  const [scheduleTarget, setScheduleTarget] = useState(null);
  const [scheduleEnabled, setScheduleEnabled] = useState(false);
  const [intervalMinutes, setIntervalMinutes] = useState(60);
  const [isCustomInterval, setIsCustomInterval] = useState(false);
  const [savingSchedule, setSavingSchedule] = useState(false);
  const [scheduleError, setScheduleError] = useState(null);

  const fetchTargets = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.get('/targets');
      setTargets(data.targets || []);
    } catch (err) {
      setError(err.message || 'Failed to load targets');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTargets();
  }, []);

  const openAddModal = () => {
    setEditingTarget(null);
    setName('');
    setBaseUrl('');
    setAuthConfigJson('');
    setIsModalOpen(true);
  };

  const openEditModal = (target) => {
    setEditingTarget(target);
    setName(target.name);
    setBaseUrl(target.base_url);
    setAuthConfigJson(
      target.auth_config ? JSON.stringify(target.auth_config, null, 2) : ''
    );
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setEditingTarget(null);
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    let parsedAuth = null;
    if (authConfigJson.trim()) {
      try {
        parsedAuth = JSON.parse(authConfigJson);
      } catch (err) {
        setError('Auth config must be valid JSON');
        setSaving(false);
        return;
      }
    }

    try {
      if (editingTarget) {
        await api.put(`/targets/${editingTarget.id}`, {
          name,
          base_url: baseUrl,
          auth_config: parsedAuth,
        });
      } else {
        await api.post('/targets', {
          name,
          base_url: baseUrl,
          auth_config: parsedAuth,
        });
      }
      closeModal();
      fetchTargets();
    } catch (err) {
      setError(err.message || 'Failed to save target');
    } finally {
      setSaving(false);
    }
  };

  const openScheduleModal = (target) => {
    setScheduleTarget(target);
    setScheduleEnabled(target.schedule_enabled || false);
    const mins = target.scan_interval_minutes || 60;
    setIntervalMinutes(mins);
    setIsCustomInterval(!INTERVAL_PRESETS.some((p) => p.value === mins));
    setScheduleError(null);
  };

  const closeScheduleModal = () => {
    setScheduleTarget(null);
    setScheduleError(null);
  };

  const handleSaveSchedule = async (e) => {
    e.preventDefault();
    setSavingSchedule(true);
    setScheduleError(null);

    if (scheduleEnabled && (!intervalMinutes || intervalMinutes < 5)) {
      setScheduleError('Interval must be at least 5 minutes.');
      setSavingSchedule(false);
      return;
    }

    try {
      const updated = await api.put(`/targets/${scheduleTarget.id}/schedule`, {
        enabled: scheduleEnabled,
        interval_minutes: scheduleEnabled ? Number(intervalMinutes) : null,
      });
      // Reflect the change locally without a full refetch.
      setTargets((prev) =>
        prev.map((t) => (t.id === updated.id ? { ...t, ...updated } : t))
      );
      closeScheduleModal();
    } catch (err) {
      setScheduleError(err.message || 'Failed to update schedule');
    } finally {
      setSavingSchedule(false);
    }
  };

  const handleDelete = async (id, targetName) => {
    if (!window.confirm(`Are you sure you want to remove target "${targetName}" and its scans?`)) {
      return;
    }
    try {
      await api.del(`/targets/${id}`);
      setTargets(targets.filter((t) => t.id !== id));
    } catch (err) {
      alert(err.message || 'Failed to delete target');
    }
  };

  return (
    <div className="targets-page animate-slide-up">
      <div className="page-header">
        <div>
          <h1 className="page-title">Target Applications</h1>
          <p className="text-secondary text-body">
            Manage web application scopes, base endpoints, and authenticated session definitions.
          </p>
        </div>
        <button className="btn btn-primary" onClick={openAddModal}>
          <Plus size={16} />
          <span>Add Target</span>
        </button>
      </div>

      {error && !isModalOpen && (
        <div className="card targets-error-card">
          <AlertCircle size={18} />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="loading-container">
          <div className="spinner" />
        </div>
      ) : targets.length === 0 ? (
        <div className="card empty-state">
          <Globe size={48} />
          <h3 className="text-subheading">No Targets Registered</h3>
          <p className="text-muted">
            Add a target web application to start differential vulnerability scans.
          </p>
          <button className="btn btn-primary mt-sm" onClick={openAddModal}>
            <Plus size={15} />
            <span>Add First Target</span>
          </button>
        </div>
      ) : (
        <div className="targets-grid">
          {targets.map((target) => (
            <div key={target.id} className="card target-card">
              <div className="target-card-header">
                <div className="target-title-area">
                  <h3 className="target-name">{target.name}</h3>
                  <a
                    href={target.base_url}
                    target="_blank"
                    rel="noreferrer"
                    className="target-url text-mono"
                  >
                    <span>{target.base_url}</span>
                    <ExternalLink size={12} />
                  </a>
                </div>
                <div className="target-actions">
                  <button
                    className={`btn-icon${target.schedule_enabled ? ' btn-icon-active' : ''}`}
                    title={target.schedule_enabled ? 'Continuous scan: on' : 'Schedule continuous scans'}
                    onClick={() => openScheduleModal(target)}
                  >
                    <CalendarClock size={15} />
                  </button>
                  <button
                    className="btn-icon"
                    title="Edit target"
                    onClick={() => openEditModal(target)}
                  >
                    <Edit2 size={15} />
                  </button>
                  <button
                    className="btn-icon btn-icon-danger"
                    title="Delete target"
                    onClick={() => handleDelete(target.id, target.name)}
                  >
                    <Trash2 size={15} />
                  </button>
                </div>
              </div>

              <div className="target-card-meta">
                <div className="target-stat">
                  <span className="target-stat-label text-caption text-muted">Executed Scans</span>
                  <span className="target-stat-value text-mono">{target.scan_count || 0}</span>
                </div>
                <div className="target-stat">
                  <span className="target-stat-label text-caption text-muted">Authentication</span>
                  <span className="target-stat-value">
                    {target.auth_config ? (
                      <span className="auth-pill active">Configured</span>
                    ) : (
                      <span className="auth-pill none">None</span>
                    )}
                  </span>
                </div>
              </div>

              <div className="target-schedule-row">
                {target.schedule_enabled ? (
                  <span className="schedule-pill on">
                    <Repeat size={12} />
                    {formatInterval(target.scan_interval_minutes)}
                    {target.next_scan_at && (
                      <span className="schedule-next">
                        · next {formatCountdown(target.next_scan_at)}
                      </span>
                    )}
                  </span>
                ) : (
                  <button
                    className="schedule-pill off"
                    onClick={() => openScheduleModal(target)}
                  >
                    <CalendarClock size={12} />
                    Set up continuous scans
                  </button>
                )}
              </div>

              <div className="target-card-footer">
                <span className="target-date text-caption text-muted">
                  <Clock size={12} />
                  Added {new Date(target.created_at).toLocaleDateString()}
                </span>
                <Link
                  to={`/scans/new?target_id=${target.id}`}
                  className="btn btn-sm btn-secondary"
                >
                  <Zap size={13} />
                  <span>Launch Scan</span>
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add / Edit Target Modal */}
      {isModalOpen && (
        <div className="modal-overlay" onClick={closeModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="text-subheading">
                {editingTarget ? 'Update Target Scope' : 'Add Web Target'}
              </h3>
              <button className="btn-ghost" onClick={closeModal}>
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleSave} className="target-form">
              {error && (
                <div className="form-error">
                  <AlertCircle size={15} />
                  <span>{error}</span>
                </div>
              )}

              <div className="form-group">
                <label className="form-label">Target Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Juice Shop Staging"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label">Base URL</label>
                <input
                  type="url"
                  required
                  placeholder="http://localhost:3000 or https://example.com"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                />
                <span className="form-hint">
                  The crawler will respect this base domain boundary.
                </span>
              </div>

              <div className="form-group">
                <label className="form-label">
                  Auth Configuration (Optional JSON)
                </label>
                <textarea
                  rows={4}
                  className="text-mono"
                  placeholder='{"login_url": "/login", "username_selector": "#user", "password_selector": "#pass"}'
                  value={authConfigJson}
                  onChange={(e) => setAuthConfigJson(e.target.value)}
                />
                <span className="form-hint">
                  Crawler engine uses this for automated SPA authenticated session tokens.
                  {editingTarget?.auth_config &&
                    ' Saved passwords are shown as ******** — leave them as-is to keep them, or clear the field to remove authentication.'}
                </span>
              </div>

              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={closeModal}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={saving}>
                  {saving ? 'Saving...' : editingTarget ? 'Update Target' : 'Create Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Continuous Scan Schedule Modal */}
      {scheduleTarget && (
        <div className="modal-overlay" onClick={closeScheduleModal}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="text-subheading">Continuous Scanning</h3>
              <button className="btn-ghost" onClick={closeScheduleModal}>
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleSaveSchedule} className="target-form">
              <p className="text-muted text-caption">
                Re-run a full scan of <strong>{scheduleTarget.name}</strong> on a fixed
                interval. Each run can be compared against the previous one to surface
                only what changed.
              </p>

              {scheduleError && (
                <div className="form-error">
                  <AlertCircle size={15} />
                  <span>{scheduleError}</span>
                </div>
              )}

              <label className="schedule-toggle">
                <input
                  type="checkbox"
                  checked={scheduleEnabled}
                  onChange={(e) => setScheduleEnabled(e.target.checked)}
                />
                <Power size={15} />
                <span>Enable continuous scanning</span>
              </label>

              {scheduleEnabled && (
                <>
                  <div className="form-group">
                    <label className="form-label">Scan interval</label>
                    <select
                      value={isCustomInterval ? 'custom' : String(intervalMinutes)}
                      onChange={(e) => {
                        if (e.target.value === 'custom') {
                          setIsCustomInterval(true);
                        } else {
                          setIsCustomInterval(false);
                          setIntervalMinutes(Number(e.target.value));
                        }
                      }}
                    >
                      {INTERVAL_PRESETS.map((p) => (
                        <option key={p.value} value={String(p.value)}>
                          {p.label}
                        </option>
                      ))}
                      <option value="custom">Custom…</option>
                    </select>
                  </div>

                  {isCustomInterval && (
                    <div className="form-group">
                      <label className="form-label">Custom interval (minutes)</label>
                      <input
                        type="number"
                        min={5}
                        value={intervalMinutes}
                        onChange={(e) => setIntervalMinutes(e.target.value)}
                      />
                      <span className="form-hint">
                        Minimum 5 minutes. First scan starts shortly after you enable.
                      </span>
                    </div>
                  )}

                  {scheduleTarget.next_scan_at && scheduleTarget.schedule_enabled && (
                    <span className="form-hint">
                      Next scheduled run {formatCountdown(scheduleTarget.next_scan_at)}.
                    </span>
                  )}
                </>
              )}

              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={closeScheduleModal}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={savingSchedule}>
                  {savingSchedule
                    ? 'Saving…'
                    : scheduleEnabled
                    ? 'Save Schedule'
                    : 'Turn Off Schedule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
