import React from 'react';
import { Link } from 'react-router-dom';
import { Clock, ShieldAlert, ArrowRight, Compass } from 'lucide-react';
import StatusBadge from './StatusBadge';
import './ScanCard.css';

export default function ScanCard({ scan, targetName }) {
  const scanDate = scan.created_at
    ? new Date(scan.created_at).toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      })
    : 'Unknown date';

  return (
    <div className="scan-card">
      <div className="scan-card-main">
        <div className="scan-card-header">
          <span className="scan-id text-mono">#{scan.id.substring(0, 8)}</span>
          <StatusBadge status={scan.status} size="sm" />
        </div>
        
        <h4 className="scan-target-name">{targetName || `Target ${scan.target_id.substring(0, 8)}`}</h4>
        
        <div className="scan-meta">
          <span className="scan-meta-item">
            <Clock size={14} />
            {scanDate}
          </span>
          {scan.stats && (
            <span className="scan-meta-item">
              <Compass size={14} />
              {scan.stats.endpoints_count || 0} endpoints
            </span>
          )}
        </div>
      </div>

      <div className="scan-card-action">
        <Link to={`/scans/${scan.id}`} className="btn-details">
          <span>Inspect</span>
          <ArrowRight size={15} />
        </Link>
      </div>
    </div>
  );
}
