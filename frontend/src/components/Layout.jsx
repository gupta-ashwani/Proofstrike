import React, { useState } from 'react';
import { NavLink, Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Target,
  Activity,
  ShieldAlert,
  Zap,
  Menu,
  X,
  Radio,
  ChevronRight,
  ExternalLink,
} from 'lucide-react';
import './Layout.css';

export default function Layout({ children }) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();

  const navItems = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
    { to: '/targets', label: 'Targets', icon: Target },
    { to: '/scans', label: 'Scans', icon: Activity },
    { to: '/findings', label: 'Findings', icon: ShieldAlert },
  ];

  // Helper to determine page title for top bar
  const getPageTitle = () => {
    const path = location.pathname;
    if (path === '/') return 'Dashboard Overview';
    if (path === '/targets') return 'Target Applications';
    if (path === '/scans') return 'Scan Management';
    if (path === '/scans/new') return 'Configure New Scan';
    if (path.startsWith('/scans/')) return 'Scan Details & Live Telemetry';
    if (path === '/findings') return 'Vulnerability Findings';
    if (path.startsWith('/findings/')) return 'Finding Investigation';
    return 'ProofStrike';
  };

  return (
    <div className={`app-shell ${collapsed ? 'sidebar-collapsed' : ''} ${mobileOpen ? 'mobile-open' : ''}`}>
      {/* Mobile Backdrop */}
      {mobileOpen && (
        <div className="mobile-backdrop" onClick={() => setMobileOpen(false)} />
      )}

      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <Link to="/" className="brand-link" onClick={() => setMobileOpen(false)}>
            <div className="brand-logo-icon">
              <Zap size={22} className="logo-svg" />
            </div>
            {!collapsed && (
              <div className="brand-text">
                <span className="brand-name text-gradient">ProofStrike</span>
                <span className="brand-tagline">Security Engine</span>
              </div>
            )}
          </Link>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-label">{!collapsed && 'PLATFORM'}</div>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.exact}
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                onClick={() => setMobileOpen(false)}
                title={collapsed ? item.label : undefined}
              >
                <Icon size={19} className="nav-icon" />
                {!collapsed && <span className="nav-label">{item.label}</span>}
              </NavLink>
            );
          })}
        </nav>

        <div className="sidebar-cta">
          {!collapsed ? (
            <Link
              to="/scans/new"
              className="btn btn-primary btn-new-scan"
              onClick={() => setMobileOpen(false)}
            >
              <Zap size={16} />
              <span>Launch Scan</span>
            </Link>
          ) : (
            <Link
              to="/scans/new"
              className="btn-icon-cta"
              title="Launch Scan"
              onClick={() => setMobileOpen(false)}
            >
              <Zap size={18} />
            </Link>
          )}
        </div>

        <div className="sidebar-footer">
          <div className="system-status">
            <Radio size={14} className="status-ping" />
            {!collapsed && <span className="text-caption text-muted">Backend v0.1.0 • Ready</span>}
          </div>
        </div>
      </aside>

      {/* Main Area */}
      <div className="main-wrapper">
        {/* Top bar */}
        <header className="topbar">
          <button
            className="mobile-toggle btn-ghost"
            onClick={() => setMobileOpen(!mobileOpen)}
            aria-label="Toggle navigation"
          >
            {mobileOpen ? <X size={20} /> : <Menu size={20} />}
          </button>

          <div className="topbar-breadcrumbs">
            <span className="breadcrumb-root">ProofStrike</span>
            <ChevronRight size={14} className="breadcrumb-separator" />
            <span className="breadcrumb-current">{getPageTitle()}</span>
          </div>

          <div className="topbar-actions">
            <Link to="/scans/new" className="btn btn-sm btn-primary">
              <Zap size={14} />
              <span>New Scan</span>
            </Link>
          </div>
        </header>

        {/* Content body */}
        <main className="content-container">{children}</main>
      </div>
    </div>
  );
}
