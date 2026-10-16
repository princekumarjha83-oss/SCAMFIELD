import React, { useState, useEffect } from 'react';
import { 
  History, Search, Trash2, Download, ExternalLink, 
  ShieldAlert, ShieldCheck, AlertTriangle, Eye, RefreshCw 
} from 'lucide-react';

export default function HistoryTab({ onSelectHistoryItem }) {
  const [historyItems, setHistoryItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterRisk, setFilterRisk] = useState('ALL');
  const [selectedItem, setSelectedItem] = useState(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/history');
      if (!res.ok) throw new Error('Failed to retrieve history');
      const data = await res.json();
      setHistoryItems(Array.isArray(data) ? data : (data.items || []));
    } catch (err) {
      setError(err.message || 'Error loading scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const handleDelete = async (id) => {
    try {
      const res = await fetch(`/api/v1/history/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error('Failed to delete history record');
      setHistoryItems(prev => prev.filter(item => item.id !== id));
      if (selectedItem?.id === id) setSelectedItem(null);
    } catch (err) {
      alert(`Error deleting record: ${err.message}`);
    }
  };

  const handleClearAll = async () => {
    if (!window.confirm('Are you sure you want to clear all scan history records?')) return;
    try {
      const res = await fetch('/api/v1/history', { method: 'DELETE' });
      if (!res.ok) throw new Error('Failed to clear history');
      setHistoryItems([]);
      setSelectedItem(null);
    } catch (err) {
      alert(`Error clearing history: ${err.message}`);
    }
  };

  const handleExportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(historyItems, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `scamshield_audit_history_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Filter items
  const filteredItems = historyItems.filter(item => {
    const matchesSearch = item.url.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesRisk = filterRisk === 'ALL' || item.risk_level?.toUpperCase() === filterRisk.toUpperCase();
    return matchesSearch && matchesRisk;
  });

  const getVerdictBadge = (level) => {
    const l = (level || '').toLowerCase();
    if (l === 'high' || l === 'critical') {
      return <span className="badge-critical"><ShieldAlert size={12} /> High Risk</span>;
    }
    if (l === 'suspicious' || l === 'medium') {
      return <span className="badge-warning"><AlertTriangle size={12} /> Suspicious</span>;
    }
    return <span className="badge-safe"><ShieldCheck size={12} /> Benign</span>;
  };

  return (
    <div className="history-container animate-fade-in">
      <div className="history-header">
        <div>
          <h2 className="tab-heading">Historical URL Inspection Logs</h2>
          <p className="tab-sub">
            Audit trail of analyzed links with static risk ratings, timestamps, and detection indicators.
          </p>
        </div>

        <div className="history-actions">
          <button 
            onClick={fetchHistory} 
            disabled={loading}
            className="action-btn"
            title="Refresh history"
          >
            <RefreshCw size={15} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>

          {historyItems.length > 0 && (
            <>
              <button 
                onClick={handleExportJSON}
                className="action-btn action-btn-export"
                title="Export scan logs as JSON"
              >
                <Download size={15} />
                <span>Export JSON</span>
              </button>

              <button 
                onClick={handleClearAll}
                className="action-btn action-btn-danger"
                title="Purge all audit logs"
              >
                <Trash2 size={15} />
                <span>Clear All</span>
              </button>
            </>
          )}
        </div>
      </div>

      {error && (
        <div className="scan-error-alert" role="alert">
          <AlertTriangle size={18} className="text-rose" />
          <span>{error}</span>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="glass-panel filter-panel">
        <div className="search-box">
          <Search size={16} className="text-muted" />
          <input
            type="text"
            placeholder="Search by URL or domain string..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="search-input"
          />
        </div>

        <div className="risk-filter-chips">
          {['ALL', 'HIGH', 'SUSPICIOUS', 'SAFE'].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFilterRisk(lvl)}
              className={`filter-chip ${filterRisk === lvl ? 'filter-chip-active' : ''}`}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Table of records */}
      <div className="glass-panel history-table-card">
        {loading && historyItems.length === 0 ? (
          <div className="table-loading">
            <RefreshCw size={24} className="animate-spin text-emerald" />
            <p>Loading audit logs...</p>
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="empty-history-notice">
            <History size={36} className="text-muted" />
            <p>No inspection logs found matching your criteria.</p>
            <span className="empty-sub">Run a scan on the Live Scanner tab to generate new audit entries.</span>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="history-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Scanned URL</th>
                  <th>Risk Score</th>
                  <th>Verdict</th>
                  <th>Indicators</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredItems.map((item) => (
                  <tr key={item.id} className="history-row">
                    <td className="timestamp-cell">
                      {new Date(item.scanned_at || item.created_at || Date.now()).toLocaleString()}
                    </td>
                    <td className="url-cell" title={item.url}>
                      <span className="mono url-text">{item.url}</span>
                    </td>
                    <td className="score-cell">
                      <span className={`score-badge ${
                        item.risk_score >= 65 ? 'score-high' : item.risk_score >= 35 ? 'score-med' : 'score-low'
                      }`}>
                        {item.risk_score}/100
                      </span>
                    </td>
                    <td className="verdict-cell">
                      {getVerdictBadge(item.risk_level)}
                    </td>
                    <td className="indicators-cell">
                      <span className="indicator-count-pill">
                        {item.indicators ? (Array.isArray(item.indicators) ? item.indicators.length : JSON.parse(item.indicators || '[]').length) : 0} triggers
                      </span>
                    </td>
                    <td className="actions-cell">
                      <div className="row-actions">
                        <button
                          onClick={() => {
                            if (onSelectHistoryItem) {
                              onSelectHistoryItem(item);
                            } else {
                              setSelectedItem(item);
                            }
                          }}
                          className="icon-action-btn"
                          title="Inspect scan telemetry"
                        >
                          <Eye size={16} />
                        </button>
                        <button
                          onClick={() => handleDelete(item.id)}
                          className="icon-action-btn btn-delete"
                          title="Delete record"
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detail Inspection Modal for selected item */}
      {selectedItem && (
        <div className="modal-overlay" onClick={() => setSelectedItem(null)}>
          <div className="glass-panel modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="modal-title">Inspection Audit Record #{selectedItem.id}</h3>
              <button onClick={() => setSelectedItem(null)} className="modal-close-btn">&times;</button>
            </div>
            <div className="modal-body">
              <div className="detail-item">
                <span className="detail-label">Target URL:</span>
                <span className="mono detail-val-url">{selectedItem.url}</span>
              </div>
              <div className="detail-grid">
                <div>
                  <span className="detail-label">Risk Score:</span>
                  <span className="font-bold">{selectedItem.risk_score} / 100</span>
                </div>
                <div>
                  <span className="detail-label">Classification:</span>
                  <span>{selectedItem.risk_level}</span>
                </div>
                <div>
                  <span className="detail-label">Scanned At:</span>
                  <span>{new Date(selectedItem.scanned_at || Date.now()).toLocaleString()}</span>
                </div>
                <div>
                  <span className="detail-label">ML Confidence:</span>
                  <span>{selectedItem.ml_confidence ? `${(selectedItem.ml_confidence * 100).toFixed(1)}%` : 'N/A'}</span>
                </div>
              </div>

              <div className="modal-indicators-section">
                <h4 className="indicators-subheading">Triggered Heuristics:</h4>
                {selectedItem.indicators && (Array.isArray(selectedItem.indicators) ? selectedItem.indicators : JSON.parse(selectedItem.indicators || '[]')).length > 0 ? (
                  <div className="modal-indicators-list">
                    {(Array.isArray(selectedItem.indicators) ? selectedItem.indicators : JSON.parse(selectedItem.indicators || '[]')).map((ind, i) => (
                      <div key={i} className="modal-ind-item">
                        <span className={`severity-tag severity-${ind.severity?.toLowerCase() || 'medium'}`}>
                          {ind.severity || 'WARN'}
                        </span>
                        <div>
                          <strong>{ind.name}</strong>
                          <p className="text-secondary text-sm">{ind.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-muted text-sm">No high-risk heuristics recorded for this entry.</p>
                )}
              </div>
            </div>
            <div className="modal-footer">
              <button onClick={() => setSelectedItem(null)} className="btn-secondary">
                Close Record
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
