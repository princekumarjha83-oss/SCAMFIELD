import React, { useState } from 'react';
import { 
  MessageSquare, AlertTriangle, ShieldAlert, ShieldCheck, 
  Sparkles, RefreshCw, XCircle, CheckCircle2, ArrowRight, ExternalLink, Info, CheckSquare
} from 'lucide-react';
import { api } from '../services/api';

const MESSAGE_PRESETS = [
  {
    label: 'Wells Fargo OTP Lure',
    category: 'Credentials',
    text: 'WELLS FARGO ALERT: Your online banking account has been temporarily restricted due to unauthorized login activity. Immediate action required within 24 hours. Send your one-time password OTP code or verify at https://wellsfargo.com.security-portal.xyz/auth'
  },
  {
    label: 'IRS Arrest Coercion',
    category: 'Extortion',
    text: 'INTERNAL REVENUE SERVICE: A formal arrest warrant and legal summons have been issued under your Social Security Number for unpaid back taxes. You must resolve immediately within 24 hours by purchasing $1,000 in Apple gift cards or wire transfer.'
  },
  {
    label: 'GeekSquad Auto-Renewal',
    category: 'Invoice Scam',
    text: 'Geek Squad Tech Protection: Your annual renewal charge of $499.99 has been debited from your card. If you did not authorize this transaction, call our support line immediately at 1-888-555-0199 to cancel or visit http://geeksquad-refund-center.top/cancel'
  },
  {
    label: 'Crypto Seed Phrase Trap',
    category: 'Crypto Theft',
    text: 'MetaMask Security Alert: Your wallet has encountered an unverified contract state. To prevent total fund liquidation, enter your 12-word secret recovery seed phrase at https://metamask.wallet-sync-restore.icu immediately.'
  },
  {
    label: 'Benign Friendly Chat',
    category: 'Safe',
    text: 'Hey Alex, just checking in to see if you received the quarterly analytics presentation slides? Let me know when you have time for a quick 10-minute catchup call.'
  }
];

export default function MessageScanner({ onScanComplete, lastResult }) {
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(lastResult || null);

  const handleScan = async (textToScan) => {
    const targetText = (textToScan || text).trim();
    if (!targetText) {
      setError('Please provide message text, SMS, or chat content to inspect.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const data = await api.scanMessage(targetText);
      setResult(data);
      if (onScanComplete) {
        onScanComplete(data);
      }
    } catch (err) {
      setError(err.message || 'Error occurred during message threat inspection.');
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (presetText) => {
    setText(presetText);
    setError(null);
    handleScan(presetText);
  };

  const getVerdictStyle = (level) => {
    switch (level?.toLowerCase()) {
      case 'high':
      case 'critical':
        return {
          cardClass: 'verdict-critical',
          badgeText: 'HIGH RISK / SCAM DETECTED',
          badgeClass: 'badge-critical',
          icon: ShieldAlert,
          color: 'var(--rose-500)',
        };
      case 'suspicious':
      case 'medium':
        return {
          cardClass: 'verdict-warning',
          badgeText: 'SUSPICIOUS / ELEVATED CAUTION',
          badgeClass: 'badge-warning',
          icon: AlertTriangle,
          color: 'var(--amber-500)',
        };
      case 'low':
      case 'safe':
      default:
        return {
          cardClass: 'verdict-safe',
          badgeText: 'BENIGN / LOW RISK ESTIMATE',
          badgeClass: 'badge-safe',
          icon: ShieldCheck,
          color: 'var(--emerald-500)',
        };
    }
  };

  const verdictStyle = result ? getVerdictStyle(result.risk_level) : null;
  const VerdictIcon = verdictStyle?.icon || ShieldCheck;

  return (
    <div className="modality-container animate-fade-in">
      <div className="modality-intro">
        <h2 className="modality-title">
          <MessageSquare className="text-cyan" size={24} />
          <span>Message &amp; SMS Scam Intelligence Scanner</span>
        </h2>
        <p className="modality-sub">
          Analyzes text communications, SMS messages, and chat transcripts for psychological coercion,
          artificial deadlines, impersonation lures, credential harvesting, and payment extortion.
        </p>
      </div>

      {/* Input Workspace */}
      <div className="glass-panel scanner-input-card">
        <form onSubmit={(e) => { e.preventDefault(); handleScan(); }}>
          <div className="textarea-container">
            <textarea
              id="message-scan-input"
              value={text}
              onChange={(e) => { setText(e.target.value); if (error) setError(null); }}
              placeholder="Paste suspicious text message, SMS, chat log, or social media message here..."
              rows={5}
              className="modality-textarea"
              disabled={loading}
              maxLength={10000}
            />
            <div className="textarea-footer">
              <span className="char-counter">{text.length} / 10,000 characters</span>
              <div className="textarea-actions">
                {text && (
                  <button 
                    type="button" 
                    onClick={() => setText('')} 
                    className="clear-text-btn"
                    title="Clear text"
                  >
                    <XCircle size={15} />
                    <span>Clear</span>
                  </button>
                )}
                <button
                  type="submit"
                  id="submit-message-scan-btn"
                  disabled={loading || !text.trim()}
                  className="scan-submit-button"
                >
                  {loading ? (
                    <>
                      <RefreshCw size={17} className="animate-spin" />
                      <span>Inspecting Text...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles size={17} />
                      <span>Analyze Message</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </form>

        {error && (
          <div className="scan-error-alert" role="alert">
            <AlertTriangle size={18} className="text-rose" />
            <span>{error}</span>
          </div>
        )}

        {/* Presets */}
        <div className="preset-selector">
          <span className="preset-label">Test Presets:</span>
          <div className="preset-chips">
            {MESSAGE_PRESETS.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => loadPreset(p.text)}
                className="preset-chip-btn"
                disabled={loading}
              >
                <span>{p.label}</span>
                <span className={`preset-badge preset-${p.category.toLowerCase().replace(/\s+/g, '-')}`}>
                  {p.category}
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Results View */}
      {result && !loading && (
        <div className={`glass-panel result-card ${verdictStyle.cardClass} animate-fade-in`}>
          <div className="result-header">
            <div className="verdict-main">
              <div className="verdict-icon-container">
                <VerdictIcon size={36} color={verdictStyle.color} />
              </div>
              <div className="verdict-details">
                <div className="verdict-badge-row">
                  <span className={`verdict-pill ${verdictStyle.badgeClass}`}>
                    {verdictStyle.badgeText}
                  </span>
                  <span className="scan-timestamp">
                    Scanned at {new Date(result.scanned_at || Date.now()).toLocaleTimeString()}
                  </span>
                </div>
                <div className="intent-category-badge">
                  <span className="intent-label">Detected Intent:</span>
                  <span className="intent-val">{result.intent_category?.replace(/_/g, ' ') || 'GENERAL'}</span>
                </div>
              </div>
            </div>

            <div className="risk-score-box">
              <div className="score-value-wrap">
                <span className="score-number">{result.risk_score}</span>
                <span className="score-max">/100</span>
              </div>
              <span className="score-label">THREAT SCORE</span>
              <div className="score-mini-bar">
                <div 
                  className="score-mini-fill" 
                  style={{ width: `${result.risk_score}%`, backgroundColor: verdictStyle.color }} 
                />
              </div>
            </div>
          </div>

          {/* Executive Summary */}
          <div className="summary-banner">
            <strong>Executive Assessment:</strong>
            <p>{result.summary}</p>
          </div>

          {/* Suspicious Indicators */}
          <div className="section-block">
            <h3 className="section-title">
              <span>Triggered Heuristics &amp; Pattern Flags</span>
              <span className="indicator-count-badge">{result.indicators?.length || 0}</span>
            </h3>

            {result.indicators && result.indicators.length > 0 ? (
              <div className="indicators-list">
                {result.indicators.map((ind, idx) => (
                  <div key={idx} className={`indicator-card indicator-${ind.severity?.toLowerCase() || 'medium'}`}>
                    <div className="indicator-top">
                      <span className={`severity-tag severity-${ind.severity?.toLowerCase() || 'medium'}`}>
                        {ind.severity}
                      </span>
                      <strong className="indicator-name">{ind.name}</strong>
                    </div>
                    <p className="indicator-description">{ind.description}</p>
                    {ind.evidence && (
                      <div className="indicator-evidence">
                        <span className="evidence-label">Matched Trigger:</span>
                        <code className="evidence-code">{ind.evidence}</code>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="no-indicators-box">
                <CheckCircle2 size={20} className="text-emerald" />
                <span>No high-risk scam triggers, urgency coercion, or credential demands identified in text.</span>
              </div>
            )}
          </div>

          {/* Extracted URLs if any */}
          {result.extracted_urls && result.extracted_urls.length > 0 && (
            <div className="section-block">
              <h3 className="section-title">Embedded Links Analyzed ({result.extracted_urls.length})</h3>
              <div className="extracted-urls-list">
                {result.extracted_urls.map((u, i) => (
                  <div key={i} className="extracted-url-item">
                    <span className="mono link-text">{u.url}</span>
                    <span className={`risk-mini-badge risk-${u.risk_level?.toLowerCase()}`}>
                      {u.risk_level} ({u.heuristic_score}/100)
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Actionable Safety Checklist */}
          {result.recommended_actions && (
            <div className="section-block">
              <h3 className="section-title">Recommended Safety Actions</h3>
              <div className="actions-checklist">
                {result.recommended_actions.map((act, i) => (
                  <div key={i} className="action-check-item">
                    <CheckSquare size={16} className="text-emerald" />
                    <span>{act}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Disclaimer */}
          <div className="safety-disclaimer-callout">
            <Info size={19} className="disclaimer-icon" />
            <div className="disclaimer-content">
              <strong>Defensive AI Notice:</strong>
              <p>
                {result.disclaimer || 'Predictions are algorithmic heuristic estimates. Always confirm suspicious communications directly with verified official entities.'}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
