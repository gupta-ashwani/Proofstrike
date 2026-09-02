import React from 'react';
import './SeverityBadge.css';

export default function SeverityBadge({ severity = 'info', size = 'md' }) {
  const normSev = (severity || 'info').toLowerCase();
  
  return (
    <span className={`severity-badge severity-${normSev} badge-${size}`}>
      <span className="severity-dot" />
      {normSev.toUpperCase()}
    </span>
  );
}
