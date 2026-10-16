import React, { useState } from 'react';
import { 
  Mail, AlertTriangle, ShieldAlert, ShieldCheck, 
  Sparkles, RefreshCw, XCircle, CheckCircle2, User, Hash, FileCode, Info, CheckSquare 
} from 'lucide-react';
import { api } from '../services/api';

const EMAIL_PRESETS = [
  {
    label: 'PayPal Free Webmail Spoof',
    category: 'Free Mail Phish',
    sender: 'PayPal Security Team <paypal-billing-notice@gmail.com>',
    subject: 'RE: Urgent Account Freeze - Immediate Action Required',
    body: 'Dear client, your PayPal account has been temporarily restricted due to unauthorized login activity. Please review the attached invoice.zip file or verify credentials at https://paypal.com.customer-verification-portal.top/webapps/login.php within 24 hours.'
  },
  {
    label: 'Netflix Billing Cancellation',
    category: 'Account Phish',
    sender: 'Netflix Alerts <billing@netflix-support.icu>',
    subject: 'Final Notice: Membership Suspended',
    body: 'We could not process your monthly subscription payment. Your streaming service will be terminated today unless you update your credit card CVV and billing address: https://netflix.com.billing-update.top/login'
  },
  {
    label: 'Amazon Order Dispute Bait',
    category: 'Order Fraud',
    sender: 'Amazon Fraud Desk <order-resolution@amazon-customer-help.xyz>',
    subject: 'Unauthorized Order Confirmation #982-120934 ($1,299.00)',
    body: 'Thank you for your order of MacBook Pro ($1,299.00). If you did not make this purchase, call our fraud department at 1-888-555-0144 or dispute online: http://192.168.1.100:8080/amazon/dispute.html'
  },
  {
    label: 'Legitimate Team Memo',
    category: 'Safe',
    sender: 'Sarah Jenkins <sjenkins@acmecorp.com>',
    subject: 'Q3 Security Engineering Sprint Notes',
    body: 'Hi everyone, the notes from today\'s sprint retrospective are published on our internal documentation space at https://docs.acmecorp.com/security/sprint-q3. Thanks for all the great feedback!'
  }
];

export default function EmailScanner({ onScanComplete, lastResult }) {
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(lastResult || null);

  const handleScan = async () => {
    const cleanBody = body.trim();
    if (!cleanBody) {
      setError('Please provide email body text or raw RFC 822 email content.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const data = await api.scanEmail({
        body: cleanBody,
        subject: subject.trim() || undefined,
        sender: sender.trim() || undefined
      });
      setResult(data);
      if (onScanComplete) {
        onScanComplete(data);
      }
    } catch (err) {
      setError(err.message || 'Error occurred during email phishing analysis.');
    } finally {
      setLoading(false);
    }
  };

  const loadPreset = (preset) => {
    setSender(preset.sender);
    setSubject(preset.subject);
    setBody(preset.body);
    setError(null);
  };

  const handleClear = () => {
    setSender('');
    setSubject('');
    setBody('');
    setError(null);
  };

  const getVerdictStyle = (level) => {
    switch (level?.toLowerCase()) {
      case 'high':
      case 'critical':
        return {
          cardClass: 'verdict-critical',
          badgeText: 'HIGH RISK / MALICIOUS PHISHING EMAIL',
          badgeClass: 'badge-critical',
          icon: ShieldAlert,
          color: 'var(--rose-500)',
        };
      case 'suspicious':
      case 'medium':
        return {
          cardClass: 'verdict-warning',
          badgeText: 'SUSPICIOUS / ELEVATED RISK',
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
          <Mail className="text-cyan" size={24} />
          <span>Email Phishing &amp; Spoofing Intelligence Scanner</span>
        </h2>
        <p className="modality-sub">
          Inspects email headers, sender display name consistency, subject line urgency,
          embedded links, and attachment lures. Explains exactly which signals triggered warnings.
        </p>
      </div>

      {/* Input Workspace */}
      <div className="glass-panel scanner-input-card">
        <form onSubmit={(e) => { e.preventDefault(); handleScan(); }}>
          <div className="email-form-grid">
            <div className="email-field-group">
              <label htmlFor="email-sender-input" className="field-label">
                <User size={14} className="text-muted" />
                <span>Sender (From Header):</span>
              </label>
              <input
                type="text"
                id="email-sender-input"
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                placeholder="e.g. PayPal Alerts <service@domain.com> (Optional if raw RFC email pasted below)"
                className="modality-input"
                disabled={loading}
              />
            </div>

            <div className="email-field-group">
              <label htmlFor="email-subject-input" className="field-label">
                <Hash size={14} className="text-muted" />
                <span>Subject Line:</span>
              </label>
              <input
                type="text"
                id="email-subject-input"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="e.g. Urgent Action Required: Account Locked"
                className="modality-input"
                disabled={loading}
              />
            </div>
          </div>

          <div className="textarea-container" style={{ marginTop: '1rem' }}>
            <label htmlFor="email-body-input" className="field-label">
              <FileCode size={14} className="text-muted" />
              <span>Email Body or Raw RFC 822 Headers &amp; Content:</span>
            </label>
            <textarea
              id="email-body-input"
              value={body}
              onChange={(e) => { setBody(e.target.value); if (error) setError(null); }}
              placeholder="Paste email message body, or complete raw email text including headers..."
              rows={6}
              className="modality-textarea"
              disabled={loading}
              maxLength={20000}
            />
            <div className="textarea-footer">
              <span className="char-counter">{body.length} / 20,000 characters</span>
              <div className="textarea-actions">
                {(sender || subject || body) && (
                  <button 
                    type="button" 
                    onClick={handleClear} 
                    className="clear-text-btn"
                    title="Clear fields"
                  >
                    <XCircle size={15} />
                    <span>Clear</span>
                  </button>
                )}
                <button
                  type="submit"
                  id="submit-email-scan-btn"
                  disabled={loading || !body.trim()}
                  className="scan-submit-button"
                >
                  {loading ? (
                    <>
                      <RefreshCw size={17} className="animate-spin" />
                      <span>Inspecting Email...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles size={17} />
                      <span>Analyze Email</span>
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
            {EMAIL_PRESETS.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => loadPreset(p)}
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
                <div className="email-meta-preview">
                  <div className="meta-line">
                    <span className="meta-key">Sender:</span>
                    <span className="mono meta-val">{result.sender}</span>
                  </div>
                  <div className="meta-line">
                    <span className="meta-key">Subject:</span>
                    <span className="meta-val">{result.subject}</span>
                  </div>
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
              <span>Triggered Heuristic Flags</span>
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
                        <span className="evidence-label">Detected Pattern:</span>
                        <code className="evidence-code">{ind.evidence}</code>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="no-indicators-box">
                <CheckCircle2 size={20} className="text-emerald" />
                <span>No high-risk sender mismatches, coercive lures, or suspicious link triggers identified in email.</span>
              </div>
            )}
          </div>

          {/* Embedded Links */}
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

          {/* Recommended Actions */}
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

          {/* Critical Authentication Limitation Notice */}
          <div className="safety-disclaimer-callout">
            <Info size={19} className="disclaimer-icon" />
            <div className="disclaimer-content">
              <strong>Cryptographic Authentication Scope &amp; Limitation Notice:</strong>
              <p>
                {result.disclaimer || (
                  "Text & Header Structural Analysis Only: This inspection statically analyzes message text, "
                  + "sender domain consistency, and embedded links. Cryptographic authentication (SPF, DKIM, DMARC) "
                  + "and active payload execution were not evaluated."
                )}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
