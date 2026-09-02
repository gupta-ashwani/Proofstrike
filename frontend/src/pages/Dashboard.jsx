import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';
import { Zap, Target, ShieldCheck, ArrowRight, RefreshCw, AlertCircle } from 'lucide-react';
import api from '../hooks/useApi';
import StatsGrid from '../components/StatsGrid';
import ScanCard from '../components/ScanCard';
import './Dashboard.css';

// Muted Saffron & Warm Amber Palette for Chart (Dull, Non-Neon)
const SEVERITY_COLORS = {
  critical: '#C84010',
  high:     '#C86618',
  medium:   '#C88A28',
  low:      '#4A4A4A',
  info:     '#242424',
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [targets, setTargets] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsData, scansData, targetsData] = await Promise.all([
        api.get('/dashboard/stats').catch(() => null),
        api.get('/scans').catch(() => ({ scans: [] })),
        api.get('/targets').catch(() => ({ targets: [] })),
      ]);

      setStats(statsData);
      setRecentScans(scansData?.scans?.slice(0, 5) || []);

      // Map targets by ID for quick name lookup
      const targetMap = {};
      (targetsData?.targets || []).forEach((t) => {
        targetMap[t.id] = t.name;
      });
      setTargets(targetMap);
    } catch (err) {
      setError(err.message || 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Format chart data from severity breakdown
  const chartData = stats?.severity_breakdown
    ? [
        { name: 'Critical', value: stats.severity_breakdown.critical, key: 'critical' },
        { name: 'High', value: stats.severity_breakdown.high, key: 'high' },
        { name: 'Medium', value: stats.severity_breakdown.medium, key: 'medium' },
        { name: 'Low', value: stats.severity_breakdown.low, key: 'low' },
        { name: 'Info', value: stats.severity_breakdown.info, key: 'info' },
      ].filter((item) => item.value > 0)
    : [];

  const totalFindings = stats?.total_findings || 0;

  return (
    <div className="dashboard-page animate-slide-up">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Command Center</h1>
          <p className="text-secondary text-body">
            Continuous verification and differential security validation telemetry.
          </p>
        </div>
        <div className="header-actions">
          <button className="btn btn-secondary btn-sm" onClick={fetchData} title="Refresh Data">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          <Link to="/scans/new" className="btn btn-primary">
            <Zap size={15} />
            <span>New Scan</span>
          </Link>
        </div>
      </div>

      {error && (
        <div className="card dashboard-error-card">
          <AlertCircle size={20} />
          <span>{error}</span>
        </div>
      )}

      {/* Top 4 Metrics */}
      <StatsGrid stats={stats} />

      {/* Middle Grid: Charts & Recent Scans */}
      <div className="dashboard-grid">
        {/* Severity Breakdown Card */}
        <div className="card chart-card">
          <div className="card-header">
            <h3 className="text-subheading">Severity Distribution</h3>
            <span className="text-caption text-muted">Confirmed vs Candidates</span>
          </div>

          <div className="chart-wrapper">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={240}>
                <PieChart>
                  <Pie
                    data={chartData}
                    innerRadius={65}
                    outerRadius={95}
                    paddingAngle={4}
                    dataKey="value"
                    stroke="none"
                  >
                    {chartData.map((entry) => (
                      <Cell
                        key={`cell-${entry.key}`}
                        fill={SEVERITY_COLORS[entry.key] || '#64748B'}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#171717',
                      borderColor: 'rgba(200, 102, 24, 0.35)',
                      borderRadius: '6px',
                      color: '#EFEFEF',
                      fontSize: '12px',
                    }}
                    itemStyle={{ color: '#EFEFEF' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-chart">
                <ShieldCheck size={36} className="text-muted" />
                <p className="text-body text-secondary">No vulnerabilities detected yet</p>
                <span className="text-caption text-muted">
                  Launch a scan to run differential detection
                </span>
              </div>
            )}
          </div>

          {/* Legend */}
          {chartData.length > 0 && (
            <div className="chart-legend">
              {chartData.map((item) => (
                <div key={item.key} className="legend-item">
                  <span
                    className="legend-dot"
                    style={{ backgroundColor: SEVERITY_COLORS[item.key] }}
                  />
                  <span className="legend-label">{item.name}</span>
                  <span className="legend-count text-mono">{item.value}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Scans Card */}
        <div className="card recent-scans-card">
          <div className="card-header">
            <h3 className="text-subheading">Recent Scan Executions</h3>
            <Link to="/scans" className="view-all-link">
              <span>All Scans</span>
              <ArrowRight size={14} />
            </Link>
          </div>

          <div className="recent-scans-list">
            {recentScans.length > 0 ? (
              recentScans.map((scan) => (
                <ScanCard key={scan.id} scan={scan} targetName={targets[scan.target_id]} />
              ))
            ) : (
              <div className="empty-scans">
                <Target size={36} className="text-muted" />
                <p className="text-body text-secondary">No scans have been initiated</p>
                <Link to="/scans/new" className="btn btn-sm btn-primary mt-sm">
                  Run First Scan
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
