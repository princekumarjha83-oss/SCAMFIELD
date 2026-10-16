import React, { useState, useRef } from 'react';
import { 
  Camera, UploadCloud, FileImage, AlertTriangle, ShieldAlert, 
  ShieldCheck, RefreshCw, XCircle, CheckCircle2, FileText, Info, CheckSquare 
} from 'lucide-react';
import { api } from '../services/api';

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

export default function ScreenshotScanner({ onScanComplete, lastResult }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [scanStep, setScanStep] = useState('');
  const [error, setError] = useState(null);
  const [result, setResult] = useState(lastResult || null);
  const fileInputRef = useRef(null);

  const validateAndSetFile = (file) => {
    if (!file) return;

    // Check mime type
    const validTypes = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/bmp'];
    if (!validTypes.includes(file.type.toLowerCase())) {
      setError(`Unsupported file format '${file.type || 'unknown'}'. Please upload a PNG, JPEG, WEBP, or BMP screenshot.`);
      return;
    }

    // Check size limit
    if (file.size > MAX_FILE_SIZE) {
      setError(`File is too large (${(file.size / (1024 * 1024)).toFixed(2)} MB). Maximum allowed size is 5 MB.`);
      return;
    }

    setError(null);
    setSelectedFile(file);
    setPreviewUrl(URL.createObjectURL(file));
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleScan = async () => {
    if (!selectedFile) {
      setError('Please select or drag an image screenshot to inspect.');
      return;
    }

    setError(null);
    setLoading(true);
    setScanStep('Running native Windows OCR engine on image...');

    try {
      const stepTimer = setTimeout(() => {
        setScanStep('Analyzing extracted text for phishing & impersonation lures...');
      }, 400);

      const data = await api.scanScreenshot(selectedFile);
      clearTimeout(stepTimer);
      setResult(data);
      if (onScanComplete) {
        onScanComplete(data);
      }
    } catch (err) {
      setError(err.message || 'Error occurred during screenshot OCR analysis.');
    } finally {
      setLoading(false);
      setScanStep('');
    }
  };

  const handleClear = () => {
    setSelectedFile(null);
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setPreviewUrl(null);
    setError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const getVerdictStyle = (level) => {
    switch (level?.toLowerCase()) {
      case 'high':
      case 'critical':
        return {
          cardClass: 'verdict-critical',
          badgeText: 'HIGH RISK / SCAM SCREENSHOT',
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
          badgeText: 'BENIGN / LOW THREAT ESTIMATE',
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
          <Camera className="text-cyan" size={24} />
          <span>Screenshot &amp; Image OCR Threat Scanner</span>
        </h2>
        <p className="modality-sub">
          Upload screenshots of suspicious text messages, payment demands, popups, or emails.
          Our backend executes <strong>native Windows OCR</strong> to extract legible text and analyze it for scam intent.
        </p>
      </div>

      {/* Upload Zone */}
      <div className="glass-panel scanner-input-card">
        <div 
          className={`dropzone-box ${isDragging ? 'dropzone-active' : ''} ${previewUrl ? 'dropzone-has-file' : ''}`}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={() => !previewUrl && fileInputRef.current?.click()}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            accept="image/png,image/jpeg,image/jpg,image/webp,image/bmp"
            className="hidden-file-input"
            aria-label="Upload Screenshot"
          />

          {!previewUrl ? (
            <div className="dropzone-empty">
              <div className="upload-icon-circle">
                <UploadCloud size={36} className="text-cyan" />
              </div>
              <h3 className="dropzone-heading">Drop your screenshot here, or browse</h3>
              <p className="dropzone-hint">
                Supports PNG, JPG, JPEG, WEBP, BMP up to 5 MB
              </p>
              <button 
                type="button" 
                className="select-file-btn"
                onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click(); }}
              >
                <FileImage size={16} />
                <span>Select Screenshot File</span>
              </button>
            </div>
          ) : (
            <div className="dropzone-preview-wrap">
              <div className="image-preview-card">
                <img src={previewUrl} alt="Uploaded screenshot preview" className="screenshot-img-preview" />
                <div className="preview-meta">
                  <span className="file-name font-mono">{selectedFile?.name}</span>
                  <span className="file-size">{((selectedFile?.size || 0) / 1024).toFixed(1)} KB</span>
                </div>
              </div>
              <div className="preview-actions">
                <button 
                  type="button" 
                  onClick={handleClear} 
                  className="btn-danger-outline"
                  disabled={loading}
                >
                  <XCircle size={16} />
                  <span>Remove Image</span>
                </button>
                <button
                  type="button"
                  id="submit-screenshot-scan-btn"
                  onClick={handleScan}
                  disabled={loading}
                  className="scan-submit-button"
                >
                  {loading ? (
                    <>
                      <RefreshCw size={17} className="animate-spin" />
                      <span>{scanStep || 'Extracting Text...'}</span>
                    </>
                  ) : (
                    <>
                      <Camera size={17} />
                      <span>Run OCR Threat Inspection</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </div>

        {error && (
          <div className="scan-error-alert" role="alert">
            <AlertTriangle size={18} className="text-rose" />
            <span>{error}</span>
          </div>
        )}
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
                  <span className="intent-label">OCR Assessment:</span>
                  <span className="intent-val">{result.intent_category?.replace(/_/g, ' ') || 'PROCESSED'}</span>
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

          {/* OCR Extracted Text Display */}
          <div className="section-block">
            <h3 className="section-title">
              <FileText size={18} className="text-cyan" />
              <span>Extracted Optical Text (OCR)</span>
              {result.ocr_metadata?.lines_detected !== undefined && (
                <span className="indicator-count-badge">
                  {result.ocr_metadata.lines_detected} lines ({result.ocr_metadata.engine || 'native'})
                </span>
              )}
            </h3>

            {result.extracted_text ? (
              <div className="ocr-text-box">
                <pre className="mono ocr-raw-text">{result.extracted_text}</pre>
              </div>
            ) : (
              <div className="empty-ocr-box">
                <Info size={18} className="text-amber" />
                <span>No legible optical text detected in this image. The image may be blank, low-contrast, or abstract.</span>
              </div>
            )}
          </div>

          {/* Summary */}
          <div className="summary-banner">
            <strong>Executive Assessment:</strong>
            <p>{result.summary}</p>
          </div>

          {/* Indicators list */}
          <div className="section-block">
            <h3 className="section-title">
              <span>Identified Suspicious Signals</span>
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
                <span>No high-risk scam triggers, urgency coercion, or credential demands identified in extracted text.</span>
              </div>
            )}
          </div>

          {/* Recommended Actions */}
          {result.recommended_actions && (
            <div className="section-block">
              <h3 className="section-title">Recommended Safety Guidance</h3>
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
                {result.disclaimer || 'Predictions are heuristic estimates based on visible text. Images are analyzed in-memory and discarded immediately after processing.'}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
