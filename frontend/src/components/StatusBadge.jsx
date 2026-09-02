import React from 'react';
import './StatusBadge.css';

const ACTIVE_STATUSES = ['crawling', 'testing', 'verifying'];

export default function StatusBadge({ status = 'queued', size = 'md' }) {
  const normStatus = (status || 'queued').toLowerCase();
  const isActive = ACTIVE_STATUSES.includes(normStatus);

  return (
    <span className={`status-badge status-${normStatus} status-size-${size} ${isActive ? 'is-active' : ''}`}>
      <span className={`status-indicator ${isActive ? 'pulse' : ''}`} />
      <span className="status-label">{normStatus}</span>
    </span>
  );
}
