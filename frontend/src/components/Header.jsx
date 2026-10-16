import React from 'react';
import { Shield, Activity, BarChart3, History, Cpu, BookOpen, CheckCircle2, AlertTriangle } from 'lucide-react';

export default function Header({ activeTab, setActiveTab, systemStatus }) {
  const tabs = [
    { id: 'scanner', label: 'Live Scanner', icon: Shield },
    { id: 'analytics', label: 'Threat Analytics', icon: BarChart3 },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'model', label: 'Model Provenance', icon: Cpu },
    { id: 'education', label: 'Security Academy', icon: BookOpen },
  ];

  return (
    <header className="header-container">
      <div className="header-inner">
        {/* Brand identity */}
        <div className="brand-group">
          <div className="logo-icon-wrapper">
            <Shield className="logo-icon" size={26} />
            <div className="logo-pulse-ring" />
          </div>
          <div className="brand-text">
            <div className="brand-title">
              ScamShield <span className="brand-ai">AI</span>
            </div>
            <div className="brand-sub">ENTERPRISE THREAT INTELLIGENCE</div>
          </div>
        </div>

        {/* Operational Security Badge */}
        <div className="sec-status-badge">
          <div className="status-dot-pulse" />
          <span className="badge-text">STATIC INSPECTION SAFEGUARD ACTIVE</span>
          <span className="badge-divider">•</span>
          <span className="badge-sub">ZERO SSRF / NO OUTBOUND VISITS</span>
        </div>

        {/* System Connectivity Indicator */}
        <div className="system-health-pill">
          {systemStatus?.model_loaded ? (
            <span className="health-online" title="Backend connected & Scikit-learn model ready">
              <CheckCircle2 size={15} />
              <span>Engine v1.0 Ready</span>
            </span>
          ) : (
            <span className="health-degraded" title="Connecting to backend API...">
              <AlertTriangle size={15} />
              <span>{systemStatus?.message || 'Connecting...'}</span>
            </span>
          )}
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav className="header-nav" aria-label="Main Navigation">
        <div className="nav-tabs-wrapper">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`nav-tab-btn ${isActive ? 'nav-tab-active' : ''}`}
                aria-selected={isActive}
                role="tab"
              >
                <Icon size={17} className="tab-icon" />
                <span className="tab-label">{tab.label}</span>
                {isActive && <div className="tab-active-indicator" />}
              </button>
            );
          })}
        </div>
      </nav>
    </header>
  );
}
