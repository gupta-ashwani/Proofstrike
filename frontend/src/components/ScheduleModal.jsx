import React, { useState } from 'react';
import { X, Power, AlertCircle } from 'lucide-react';
import api from '../hooks/useApi';
import { INTERVAL_PRESETS, formatCountdown } from '../lib/format';
import './ScheduleModal.css';

/**
 * Configure continuous scanning for a target. Reused by the Targets list and the
 * target hub. Calls onSaved(updatedTarget) on success.
 */
export default function ScheduleModal({ target, onClose, onSaved }) {
  const [enabled, setEnabled] = useState(target.schedule_enabled || false);
  const initialMins = target.scan_interval_minutes || 60;
  const [intervalMinutes, setIntervalMinutes] = useState(initialMins);
  const [isCustom, setIsCustom] = useState(!INTERVAL_PRESETS.some((p) => p.value === initialMins));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const handleSave = async (e) => {
    e.preventDefault();
    if (enabled && (!intervalMinutes || Number(intervalMinutes) < 5)) {
      setError('Interval must be at least 5 minutes.');
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const updated = await api.put(`/targets/${target.id}/schedule`, {
        enabled,
        interval_minutes: enabled ? Number(intervalMinutes) : null,
      });
      onSaved?.(updated);
      onClose?.();
    } catch (err) {
      setError(err.message || 'Failed to update schedule');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3 className="text-subheading">Continuous Scanning</h3>
          <button className="btn-ghost" onClick={onClose}><X size={18} /></button>
        </div>

        <form onSubmit={handleSave} className="schedule-form">
          <p className="text-muted text-caption">
            Re-run a full scan of <strong>{target.name}</strong> on a fixed interval.
            Each run is compared with the previous one to surface only what changed.
          </p>

          {error && (
            <div className="form-error"><AlertCircle size={15} /><span>{error}</span></div>
          )}

          <label className="schedule-toggle">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            <Power size={15} />
            <span>Enable continuous scanning</span>
          </label>

          {enabled && (
            <>
              <div className="form-group">
                <label className="form-label">Scan interval</label>
                <select
                  value={isCustom ? 'custom' : String(intervalMinutes)}
                  onChange={(e) => {
                    if (e.target.value === 'custom') setIsCustom(true);
                    else { setIsCustom(false); setIntervalMinutes(Number(e.target.value)); }
                  }}
                >
                  {INTERVAL_PRESETS.map((p) => (
                    <option key={p.value} value={String(p.value)}>{p.label}</option>
                  ))}
                  <option value="custom">Custom…</option>
                </select>
              </div>

              {isCustom && (
                <div className="form-group">
                  <label className="form-label">Custom interval (minutes)</label>
                  <input type="number" min={5} value={intervalMinutes}
                    onChange={(e) => setIntervalMinutes(e.target.value)} />
                  <span className="form-hint">Minimum 5 minutes. First scan starts shortly after you enable.</span>
                </div>
              )}

              {target.schedule_enabled && target.next_scan_at && (
                <span className="form-hint">Next scheduled run {formatCountdown(target.next_scan_at)}.</span>
              )}
            </>
          )}

          <div className="modal-actions">
            <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? 'Saving…' : enabled ? 'Save Schedule' : 'Turn Off Schedule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
