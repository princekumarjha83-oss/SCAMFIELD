import React, { useState, useRef, useEffect } from 'react';
import { Shield, Lock, Zap, CheckCircle2, Eye, Cpu } from 'lucide-react';

export default function CyberShield3D({ onScanClick }) {
  const containerRef = useRef(null);
  const [rotate, setRotate] = useState({ x: 0, y: 0 });
  const [isHovered, setIsHovered] = useState(false);

  const handleMouseMove = (e) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left - rect.width / 2;
    const y = e.clientY - rect.top - rect.height / 2;

    // Subtle 3D tilt calculation
    const rotateY = (x / (rect.width / 2)) * 14;
    const rotateX = -(y / (rect.height / 2)) * 14;

    setRotate({ x: rotateX, y: rotateY });
  };

  const handleMouseLeave = () => {
    setRotate({ x: 0, y: 0 });
    setIsHovered(false);
  };

  return (
    <div className="hero-section">
      <div className="hero-grid">
        {/* Left Column: Headlines & Call to Action */}
        <div className="hero-content">
          <div className="hero-badge animate-fade-in">
            <span className="hero-badge-dot" />
            <span className="hero-badge-title">ScamShield AI v2.0 Enterprise</span>
            <span className="hero-badge-sep">•</span>
            <span className="hero-badge-sub">Multi-Modal Threat Defense</span>
          </div>

          <h1 className="hero-title animate-fade-in">
            Next-Gen Phishing &amp; Scam Intelligence Platform
          </h1>

          <p className="hero-subtitle animate-fade-in">
            Inspect suspicious <strong>Messages, URLs, Screenshots, and Emails</strong> through 
            offline static analysis, explainable heuristics, native OCR, and a trained Scikit-learn Random Forest model. 
            <strong> Zero SSRF. Never executes remote code.</strong>
          </p>

          <div className="hero-features-strip animate-fade-in">
            <div className="hero-feat-item">
              <Shield size={16} className="text-cyan" />
              <span>4 Scanning Modalities</span>
            </div>
            <div className="hero-feat-item">
              <Cpu size={16} className="text-emerald" />
              <span>Scikit-learn URL Classifier</span>
            </div>
            <div className="hero-feat-item">
              <Eye size={16} className="text-violet" />
              <span>Native Windows OCR</span>
            </div>
            <div className="hero-feat-item">
              <Lock size={16} className="text-amber" />
              <span>Offline Privacy Safe</span>
            </div>
          </div>

          <div className="hero-cta-group animate-fade-in">
            <button 
              onClick={onScanClick} 
              className="hero-primary-btn"
              id="hero-start-scanning-btn"
            >
              <Zap size={18} />
              <span>Launch Threat Scanner</span>
            </button>
            <div className="hero-trust-note">
              <CheckCircle2 size={15} className="text-emerald" />
              <span>Real-time heuristic explainability &amp; held-out evaluation telemetry</span>
            </div>
          </div>
        </div>

        {/* Right Column: Interactive 3D Holographic Shield Visualization */}
        <div 
          className="hero-3d-wrapper"
          ref={containerRef}
          onMouseMove={handleMouseMove}
          onMouseEnter={() => setIsHovered(true)}
          onMouseLeave={handleMouseLeave}
        >
          <div 
            className="shield-3d-scene"
            style={{
              transform: `perspective(1000px) rotateX(${rotate.x}deg) rotateY(${rotate.y}deg) scale3d(${isHovered ? 1.03 : 1}, ${isHovered ? 1.03 : 1}, 1)`,
              transition: isHovered ? 'transform 0.1s ease-out' : 'transform 0.6s cubic-bezier(0.16, 1, 0.3, 1)'
            }}
          >
            {/* Ambient Background Glow Layer */}
            <div className="shield-glow-backdrop" />

            {/* Concentric Holographic Gyro Rings */}
            <div className="hologram-ring ring-outer" />
            <div className="hologram-ring ring-middle" />
            <div className="hologram-ring ring-inner" />

            {/* Central Layered Security Shield */}
            <div className="shield-core-plate">
              <div className="shield-inner-glow" />
              <Shield size={110} className="shield-svg-icon" strokeWidth={1.4} />
              <div className="shield-scanner-beam" />
            </div>

            {/* Floating Satellite Telemetry Nodes */}
            <div className="floating-node node-top-left">
              <span className="node-icon-dot dot-emerald" />
              <div className="node-text">
                <span className="node-label">URL ML CLASSIFIER</span>
                <span className="node-val">100% Held-Out Acc</span>
              </div>
            </div>

            <div className="floating-node node-top-right">
              <span className="node-icon-dot dot-cyan" />
              <div className="node-text">
                <span className="node-label">OCR ENGINE</span>
                <span className="node-val">Native Windows OCR</span>
              </div>
            </div>

            <div className="floating-node node-bottom-left">
              <span className="node-icon-dot dot-amber" />
              <div className="node-text">
                <span className="node-label">MESSAGE HEURISTICS</span>
                <span className="node-val">Urgency &amp; Lures</span>
              </div>
            </div>

            <div className="floating-node node-bottom-right">
              <span className="node-icon-dot dot-violet" />
              <div className="node-text">
                <span className="node-label">EMAIL SPOOFING</span>
                <span className="node-val">Sender Domain Check</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
