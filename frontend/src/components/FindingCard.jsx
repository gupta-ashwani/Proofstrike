import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpRight, ShieldCheck, HelpCircle } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import './FindingCard.css';

export default function FindingCard({ finding }) {
  const isConfirmed = finding.status === 'confirmed';
  const isCandidate = finding.status === 'candidate';

  return (
    <div className="finding-card">
      <div className="finding-card-top">
        <SeverityBadge severity={finding.severity} size="sm" />
        <span className="finding-type-badge text-mono">{finding.type?.toUpperCase()}</span>
        <span className={`finding-status-tag status-${finding.status}`}>
          {isConfirmed ? <ShieldCheck size={13} /> : <HelpCircle size={13} />}
          {finding.status}
        </span>
      </div>

      <h4 className="finding-title">{finding.title}</h4>

      {finding.description && (
        <p className="finding-snippet">{finding.description}</p>
      )}

      <div className="finding-card-bottom">
        <span className="finding-date text-caption text-muted">
          {new Date(finding.created_at).toLocaleDateString(undefined, {
            month: 'short',
            day: 'numeric',
          })}
        </span>
        <Link to={`/findings/${finding.id}`} className="finding-link">
          View Evidence <ArrowUpRight size={14} />
        </Link>
      </div>
    </div>
  );
}
