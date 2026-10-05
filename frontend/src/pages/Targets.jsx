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
} from 'lucide-react';
import api from '../hooks/useApi';
import './Targets.css';

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
    </div>
  );
}
