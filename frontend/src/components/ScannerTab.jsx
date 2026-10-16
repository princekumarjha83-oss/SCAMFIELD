import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Search, Sparkles, 
  ExternalLink, Info, CheckCircle2, XCircle, ArrowRight, RefreshCw, Lock,
  Globe, MessageSquare, Camera, Mail
} from 'lucide-react';
import MessageScanner from './MessageScanner';
import ScreenshotScanner from './ScreenshotScanner';
import EmailScanner from './EmailScanner';
import { api } from '../services/api';

const SAMPLE_PRESETS = [
  {
    label: 'PayPal Impersonation',
    url: 'https://paypal.com-security-update-verify.top/webapps/mpp/account-issue?token=8923a',
    category: 'Phishing',
  },
  {
    label: 'Direct IP Host Phish',
    url: 'http://185.220.101.5:8080/secure/chase-online/auth/login.html',
    category: 'Malicious IP',
  },
  {
    label: 'Wikipedia (Legitimate)',
    url: 'https://en.wikipedia.org/wiki/Computer_security',
    category: 'Safe',
  },
  {
    label: 'Suspicious TLD & At-Symbol',
    url: 'http://user:pass@login-portal.free-rewards.xyz/claim-prize',
    category: 'Deceptive',
  },
  {
    label: 'GitHub Security (Legitimate)',
    url: 'https://github.com/features/security',
    category: 'Safe',
  },
];

export default function ScannerTab({ onScanComplete, lastResult, initialModality = 'url' }) {
  const [activeModality, setActiveModality] = useState(initialModality);
  const [inputUrl, setInputUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState('');
  const [error, setError] = useState(null);
  const [result, setResult] = useState(lastResult || null);

  const handleScan = async (urlToScan) => {
    const targetUrl = (urlToScan || inputUrl).trim();
    if (!targetUrl) {
      setError('Please provide a URL to inspect.');
      return;
    }

    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      setError('Please specify a protocol (http:// or https://) for accurate lexical analysis.');
      return;
    }

    setError(null);
    setLoading(true);
    setScanStep('Executing static lexical parsing & feature extraction...');

    try {
      const stepTimer1 = setTimeout(() => {
        setScanStep('Calculating Shannon entropy & domain structural metrics...');
      }, 200);

      const stepTimer2 = setTimeout(() => {
        setScanStep('Running Scikit-learn Random Forest inference & heuristic checks...');
      }, 400);

      const scanData = await api.scanUrl(targetUrl);

      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);

      setResult(scanData);
      if (onScanComplete) {
        onScanComplete(scanData);
      }
    } catch (err) {
      setError(err.message || 'An unexpected error occurred during URL inspection.');
    } finally {
      setLoading(false);
      setScanStep('');
    }
  };

  const loadPreset = (presetUrl) => {
    setInputUrl(presetUrl);
    setError(null);
    handleScan(presetUrl);
  };

  const getVerdictStyle = (level) => {
    switch (level?.toLowerCase()) {
      case 'high':
      case 'critical':
        return {
          cardClass: 'verdict-critical',
          badgeText: 'HIGH RISK / MALICIOUS PHISHING',
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

  const modalities = [
    { id: 'message', label: 'Message Scanner', icon: MessageSquare, desc: 'SMS, chat & text lures' },
    { id: 'url', label: 'URL Scanner', icon: Globe, desc: 'Links & lexical entropy' },
    { id: 'screenshot', label: 'Screenshot Scanner', icon: Camera, desc: 'Image OCR & visual text' },
    { id: 'email', label: 'Email Scanner', icon: Mail, desc: 'Headers, spoofing & links' },
  ];

  return (
    <div className="scanner-container">
      {/* 4 Modality Switcher Ribbon */}
      <div className="modality-switcher-bar">
        <div className="modality-pills-wrap">
          {modalities.map((m) => {
            const Icon = m.icon;
            const isActive = activeModality === m.id;
            return (
              <button
                key={m.id}
                id={`modality-tab-${m.id}`}
                onClick={() => setActiveModality(m.id)}
                className={`modality-pill-btn ${isActive ? 'modality-pill-active' : ''}`}
                role="tab"
                aria-selected={isActive}
              >
                <Icon size={18} className="pill-icon" />
                <div className="pill-text-wrap">
                  <span className="pill-title">{m.label}</span>
                  <span className="pill-desc">{m.desc}</span>
                </div>
                {isActive && <div className="pill-active-glow" />}
              </button>
            );
          })}
        </div>
      </div>

      {/* RENDER ACTIVE SCANNER MODALITY */}
      {activeModality === 'message' && (
        <MessageScanner onScanComplete={onScanComplete} lastResult={lastResult?.scan_type === 'message' ? lastResult : null} />
      )}

      {activeModality === 'screenshot' && (
        <ScreenshotScanner onScanComplete={onScanComplete} lastResult={lastResult?.scan_type === 'screenshot' ? lastResult : null} />
      )}

      {activeModality === 'email' && (
        <EmailScanner onScanComplete={onScanComplete} lastResult={lastResult?.scan_type === 'email' ? lastResult : null} />
      )}

      {activeModality === 'url' && (
        <div className="animate-fade-in">
          <div className="modality-intro">
            <h2 className="modality-title">
              <Globe className="text-cyan" size={24} />
              <span>Static URL Phishing &amp; Domain Classifier</span>
            </h2>
            <p className="modality-sub">
              Static lexical, structural, and machine-learning intelligence. ScamShield AI inspects URL structure,
              Shannon entropy, and brand impersonation <strong>without ever visiting or executing remote code</strong>.
            </p>
          </div>

          {/* URL Input Box */}
          <div className="glass-panel scanner-input-card">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleScan();
              }}
              className="scanner-form"
            >
              <div className="input-bar-group">
                <div className="input-icon-prefix">
                  <Search size={20} className="text-muted" />
                </div>
                <input
                  type="text"
                  id="url-scan-input"
                  value={inputUrl}
                  onChange={(e) => {
                    setInputUrl(e.target.value);
                    if (error) setError(null);
                  }}
                  placeholder="Enter complete target URL (e.g., https://secure-login.portal-update.xyz/auth)..."
                  className="scanner-input"
                  disabled={loading}
                  autoComplete="off"
                  spellCheck="false"
                />
                {inputUrl && (
                  <button
                    type="button"
                    onClick={() => setInputUrl('')}
                    className="input-clear-btn"
                    aria-label="Clear input"
                    title="Clear input"
                  >
                    <XCircle size={18} />
                  </button>
                )}
                <button
                  type="submit"
                  id="submit-scan-btn"
                  disabled={loading || !inputUrl.trim()}
                  className="scan-submit-button"
                >
                  {loading ? (
                    <>
                      <RefreshCw size={17} className="animate-spin" />
                      <span>Inspecting...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles size={17} />
                      <span>Analyze URL</span>
                    </>
                  )}
                </button>
              </div>
            </form>

            {/* Error notice */}
            {error && (
              <div className="scan-error-alert" role="alert">
                <AlertTriangle size={18} className="text-rose" />
                <span>{error}</span>
              </div>
            )}

            {/* Preset sample buttons */}
            <div className="preset-selector">
              <span className="preset-label">Test Presets:</span>
              <div className="preset-chips">
                {SAMPLE_PRESETS.map((preset, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => loadPreset(preset.url)}
                    className="preset-chip-btn"
                    disabled={loading}
                  >
                    <span className="preset-name">{preset.label}</span>
                    <span className={`preset-badge preset-${preset.category.toLowerCase().replace(/\s+/g, '-')}`}>
                      {preset.category}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Loading state indicator */}
          {loading && (
            <div className="glass-panel scanning-state-card animate-fade-in">
              <div className="radar-spinner">
                <div className="radar-sweep" />
                <Lock className="radar-icon" size={24} />
              </div>
              <div className="scanning-state-text">
                <h4>Conducting Static Security Analysis</h4>
                <p className="scan-step-hint">{scanStep || 'Extracting URL lexical metrics...'}</p>
              </div>
            </div>
          )}

          {/* Scan Results Display */}
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
                    <div className="inspected-url-wrap" title={result.url}>
                      <span className="mono inspected-url">{result.url}</span>
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
                      style={{ 
                        width: `${result.risk_score}%`,
                        backgroundColor: verdictStyle.color 
                      }} 
                    />
                  </div>
                </div>
              </div>

              {/* Model Confidence & Heuristic Summary Grid */}
              <div className="result-metrics-grid">
                <div className="metric-tile">
                  <span className="tile-title">ML Classifier Confidence</span>
                  <span className="tile-value highlight-cyan">
                    {result.ml_confidence !== undefined ? `${(result.ml_confidence * 100).toFixed(1)}%` : 'N/A'}
                  </span>
                  <span className="tile-note">Random Forest Scikit-learn Model</span>
                </div>

                <div className="metric-tile">
                  <span className="tile-title">ML Probability (Phish)</span>
                  <span className="tile-value">
                    {result.phishing_probability !== undefined 
                      ? `${(result.phishing_probability * 100).toFixed(1)}%` 
                      : `${result.risk_score}%`}
                  </span>
                  <span className="tile-note">Algorithmic risk estimate</span>
                </div>

                <div className="metric-tile">
                  <span className="tile-title">Flagged Heuristics</span>
                  <span className="tile-value">
                    {result.indicators ? result.indicators.length : 0}
                  </span>
                  <span className="tile-note">Suspicious signals detected</span>
                </div>

                <div className="metric-tile">
                  <span className="tile-title">Domain Shannon Entropy</span>
                  <span className="tile-value">
                    {result.features?.shannon_entropy !== undefined 
                      ? result.features.shannon_entropy.toFixed(3) 
                      : 'N/A'}
                  </span>
                  <span className="tile-note">Higher = elevated randomness</span>
                </div>
              </div>

              {/* Suspicious Indicators Breakdown */}
              <div className="section-block">
                <h3 className="section-title">
                  <span>Suspicious Indicator Explanations</span>
                  <span className="indicator-count-badge">{result.indicators?.length || 0}</span>
                </h3>

                {result.indicators && result.indicators.length > 0 ? (
                  <div className="indicators-list">
                    {result.indicators.map((ind, idx) => (
                      <div key={idx} className={`indicator-card indicator-${ind.severity.toLowerCase()}`}>
                        <div className="indicator-top">
                          <span className={`severity-tag severity-${ind.severity.toLowerCase()}`}>
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
                    <span>No high-risk heuristic triggers identified in URL lexical structure.</span>
                  </div>
                )}
              </div>

              {/* Static Lexical & Structural Inspection Table */}
              {result.features && (
                <div className="section-block">
                  <h3 className="section-title">Static Lexical &amp; Structural Telemetry</h3>
                  <div className="features-grid">
                    <div className="feature-row">
                      <span className="feature-name">Registered Domain / Host</span>
                      <span className="mono feature-val">{result.features.domain || result.features.host || 'N/A'}</span>
                    </div>
                    <div className="feature-row">
                      <span className="feature-name">Protocol</span>
                      <span className="mono feature-val">{result.features.protocol || 'N/A'}</span>
                    </div>
                    <div className="feature-row">
                      <span className="feature-name">URL Length</span>
                      <span className="feature-val">{result.features.url_length} characters</span>
                    </div>
                    <div className="feature-row">
                      <span className="feature-name">Dot Count / Subdomain Depth</span>
                      <span className="feature-val">{result.features.dot_count} dots ({result.features.subdomain_count} subdomains)</span>
                    </div>
                    <div className="feature-row">
                      <span className="feature-name">Direct IP Address Host</span>
                      <span className={`feature-val ${result.features.is_ip_address ? 'text-rose font-bold' : 'text-emerald'}`}>
                        {result.features.is_ip_address ? 'YES (Suspicious)' : 'NO'}
                      </span>
                    </div>
                    <div className="feature-row">
                      <span className="feature-name">Brand Impersonation Keyword</span>
                      <span className={`feature-val ${result.features.brand_impersonation_flag || result.features.brand_impersonation ? 'text-rose font-bold' : 'text-emerald'}`}>
                        {result.features.brand_impersonation_flag || result.features.brand_impersonation ? 'FLAGGED' : 'NONE DETECTED'}
                      </span>
                    </div>
                    <div className="feature-row">
                      <span className="feature-name">Suspicious TLD Recognized</span>
                      <span className={`feature-val ${result.features.suspicious_tld ? 'text-amber font-bold' : 'text-emerald'}`}>
                        {result.features.suspicious_tld ? 'YES' : 'STANDARD'}
                      </span>
                    </div>
                    <div className="feature-row">
                      <span className="feature-name">Query Parameters Count</span>
                      <span className="feature-val">{result.features.query_param_count ?? result.features.num_query_params ?? 0}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Mandatory Security & Prediction Disclaimer */}
              <div className="safety-disclaimer-callout">
                <Info size={19} className="disclaimer-icon" />
                <div className="disclaimer-content">
                  <strong>Defensive AI Scope &amp; Non-Guarantee Notice:</strong>
                  <p>
                    Predictions, probability scores, and risk classifications produced by ScamShield AI are statistical 
                    heuristic estimates calculated strictly via offline static analysis of URL text patterns. 
                    <strong> The absence of flagged suspicious indicators does NOT constitute an absolute safety certification or guarantee.</strong> 
                    Our backend never navigates to, connects with, or executes remote target resources.
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
