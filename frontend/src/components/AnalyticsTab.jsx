import React, { useState, useEffect } from 'react';
import { 
  BarChart3, ShieldAlert, ShieldCheck, AlertTriangle, 
  Activity, ArrowUpRight, TrendingUp, RefreshCw 
} from 'lucide-react';

export default function AnalyticsTab() {
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchAnalytics = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/analytics');
      if (!res.ok) throw new Error('Failed to retrieve analytics data');
      const data = await res.json();
      setAnalytics(data);
    } catch (err) {
      setError(err.message || 'Error loading threat analytics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, []);

  if (loading && !analytics) {
    return (
      <div className="analytics-loading glass-panel">
        <RefreshCw size={24} className="animate-spin text-emerald" />
        <p>Loading threat analytics engine metrics...</p>
      </div>
    );
  }

  const total = analytics?.total_scans || 0;
  const highRisk = analytics?.high_risk_scans || 0;
  const suspicious = analytics?.suspicious_scans || 0;
  const safe = analytics?.safe_scans || 0;
  const avgScore = analytics?.avg_risk_score !== undefined ? analytics.avg_risk_score.toFixed(1) : '0.0';

  const highPct = total > 0 ? ((highRisk / total) * 100).toFixed(1) : 0;
  const suspPct = total > 0 ? ((suspicious / total) * 100).toFixed(1) : 0;
  const safePct = total > 0 ? ((safe / total) * 100).toFixed(1) : 0;

  return (
    <div className="analytics-container animate-fade-in">
      <div className="analytics-header">
        <div>
          <h2 className="tab-heading">Threat Intelligence & Detection Analytics</h2>
          <p className="tab-sub">
            Real-time aggregate telemetry from static URL classification and heuristic inspection models.
          </p>
        </div>
        <button 
          onClick={fetchAnalytics} 
          disabled={loading}
          className="refresh-btn"
          title="Refresh analytics telemetry"
        >
          <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          <span>Refresh Metrics</span>
        </button>
      </div>

      {error && (
        <div className="scan-error-alert" role="alert">
          <AlertTriangle size={18} className="text-rose" />
          <span>{error}</span>
        </div>
      )}

      {/* KPI Stats Grid */}
      <div className="kpi-grid">
        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">TOTAL INSPECTED</span>
            <Activity size={18} className="text-cyan" />
          </div>
          <div className="kpi-body">
            <span className="kpi-number">{total}</span>
            <span className="kpi-tag">Cumulative scans</span>
          </div>
        </div>

        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">HIGH RISK DETECTED</span>
            <ShieldAlert size={18} className="text-rose" />
          </div>
          <div className="kpi-body">
            <span className="kpi-number text-rose">{highRisk}</span>
            <span className="kpi-tag text-rose">{highPct}% of total scans</span>
          </div>
        </div>

        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">SUSPICIOUS URLS</span>
            <AlertTriangle size={18} className="text-amber" />
          </div>
          <div className="kpi-body">
            <span className="kpi-number text-amber">{suspicious}</span>
            <span className="kpi-tag text-amber">{suspPct}% flagged caution</span>
          </div>
        </div>

        <div className="glass-panel kpi-card">
          <div className="kpi-header">
            <span className="kpi-title">BENIGN / CLEAN</span>
            <ShieldCheck size={18} className="text-emerald" />
          </div>
          <div className="kpi-body">
            <span className="kpi-number text-emerald">{safe}</span>
            <span className="kpi-tag text-emerald">{safePct}% safe baseline</span>
          </div>
        </div>
      </div>

      {/* Threat Distribution Bar */}
      <div className="glass-panel analytics-card">
        <h3 className="card-section-title">Risk Classification Distribution</h3>
        <p className="card-section-sub">Proportional volume of scanned links categorized by threat rating</p>

        <div className="stacked-progress-bar">
          <div 
            className="bar-segment bar-rose" 
            style={{ width: `${highPct}%` }}
            title={`High Risk: ${highRisk} (${highPct}%)`}
          />
          <div 
            className="bar-segment bar-amber" 
            style={{ width: `${suspPct}%` }}
            title={`Suspicious: ${suspicious} (${suspPct}%)`}
          />
          <div 
            className="bar-segment bar-emerald" 
            style={{ width: `${safePct}%` }}
            title={`Benign: ${safe} (${safePct}%)`}
          />
        </div>

        <div className="distribution-legend">
          <div className="legend-item">
            <span className="legend-dot dot-rose" />
            <span className="legend-name">High Risk Phishing</span>
            <span className="legend-stat">{highRisk} ({highPct}%)</span>
          </div>
          <div className="legend-item">
            <span className="legend-dot dot-amber" />
            <span className="legend-name">Suspicious / Caution</span>
            <span className="legend-stat">{suspicious} ({suspPct}%)</span>
          </div>
          <div className="legend-item">
            <span className="legend-dot dot-emerald" />
            <span className="legend-name">Benign / Safe</span>
            <span className="legend-stat">{safe} ({safePct}%)</span>
          </div>
        </div>
      </div>

      {/* Top Threat Indicators & Threat Vectors */}
      <div className="analytics-two-col">
        {/* Top Flagged Indicators */}
        <div className="glass-panel analytics-card">
          <h3 className="card-section-title">Top Flagged Heuristic Indicators</h3>
          <p className="card-section-sub">Most frequently triggered static threat rules across scans</p>

          <div className="indicators-breakdown-list">
            {(analytics?.top_indicators && analytics.top_indicators.length > 0) ? (
              analytics.top_indicators.map((ind, idx) => (
                <div key={idx} className="stat-row">
                  <div className="stat-label-wrap">
                    <span className="stat-rank">#{idx + 1}</span>
                    <span className="stat-name">{ind.name}</span>
                  </div>
                  <span className="stat-count-badge">{ind.count} triggers</span>
                </div>
              ))
            ) : (
              <div className="empty-state-notice">
                <span>No heuristic triggers recorded in database yet. Run scans to populate.</span>
              </div>
            )}
          </div>
        </div>

        {/* Average Threat Score & Model Telemetry */}
        <div className="glass-panel analytics-card">
          <h3 className="card-section-title">Telemetry & System Health</h3>
          <p className="card-section-sub">Engine uptime, model inference load, and persistence</p>

          <div className="telemetry-list">
            <div className="telemetry-item">
              <span className="telem-label">Average URL Threat Score</span>
              <span className="telem-val font-mono">{avgScore} / 100</span>
            </div>
            <div className="telemetry-item">
              <span className="telem-label">Engine Security Guard</span>
              <span className="telem-val text-emerald">OFFLINE STATIC ISOLATION</span>
            </div>
            <div className="telemetry-item">
              <span className="telem-label">Model Engine Architecture</span>
              <span className="telem-val">Scikit-learn Random Forest</span>
            </div>
            <div className="telemetry-item">
              <span className="telem-label">Database Persistence</span>
              <span className="telem-val text-cyan">{analytics?.db_type || 'SQLAlchemy Engine'}</span>
            </div>
            <div className="telemetry-item">
              <span className="telem-label">Rate Limiter Protection</span>
              <span className="telem-val text-emerald">SlowAPI Enabled</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
