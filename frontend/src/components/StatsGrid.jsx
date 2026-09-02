import React from 'react';
import { Target, Activity, ShieldAlert, AlertTriangle } from 'lucide-react';
import './StatsGrid.css';

export default function StatsGrid({ stats }) {
  const items = [
    {
      id: 'targets',
      label: 'Targets',
      value: stats?.total_targets ?? 0,
      icon: Target,
      trend: 'Monitored Scopes',
    },
    {
      id: 'active_scans',
      label: 'Active Scans',
      value: stats?.active_scans ?? 0,
      icon: Activity,
      trend: stats?.active_scans > 0 ? 'Running Now' : 'Idle',
      pulsing: stats?.active_scans > 0,
    },
    {
      id: 'findings',
      label: 'Total Findings',
      value: stats?.total_findings ?? 0,
      icon: ShieldAlert,
      trend: `${stats?.confirmed_findings ?? 0} confirmed`,
    },
    {
      id: 'critical',
      label: 'Critical + High',
      value: (stats?.severity_breakdown?.critical ?? 0) + (stats?.severity_breakdown?.high ?? 0),
      icon: AlertTriangle,
      trend: `${stats?.severity_breakdown?.critical ?? 0} critical`,
    },
  ];

  return (
    <div className="stats-grid">
      {items.map((item) => {
        const Icon = item.icon;
        return (
          <div key={item.id} className="stat-card">
            <div className="stat-header">
              <span className="stat-label">{item.label}</span>
              <div className={`stat-icon-wrapper ${item.pulsing ? 'icon-pulse' : ''}`}>
                <Icon size={17} />
              </div>
            </div>
            <div className="stat-value">{item.value}</div>
            <div className="stat-footer">
              <span className="stat-trend">{item.trend}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
