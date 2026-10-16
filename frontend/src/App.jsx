import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import CyberShield3D from './components/CyberShield3D';
import ScannerTab from './components/ScannerTab';
import AnalyticsTab from './components/AnalyticsTab';
import HistoryTab from './components/HistoryTab';
import ModelMetricsTab from './components/ModelMetricsTab';
import EducationTab from './components/EducationTab';
import { api } from './services/api';
import './App.css';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [activeModality, setActiveModality] = useState('url');
  const [systemStatus, setSystemStatus] = useState({
    status: 'connecting',
    model_loaded: false,
    message: 'Initializing engine...',
  });
  const [lastScanResult, setLastScanResult] = useState(null);
  const scannerRef = useRef(null);

  useEffect(() => {
    let isMounted = true;

    const checkSystemHealth = async () => {
      try {
        const data = await api.checkHealth();
        if (isMounted) {
          setSystemStatus({
            status: 'online',
            model_loaded: Boolean(data.model_loaded),
            message: data.model_loaded ? 'Engine v2.0 Ready' : 'Heuristic Mode Active',
            version: data.version,
            modalities: data.supported_modalities || ['url', 'message', 'screenshot', 'email']
          });
        }
      } catch (err) {
        if (isMounted) {
          setSystemStatus({
            status: 'offline',
            model_loaded: false,
            message: 'Backend Offline',
          });
        }
      }
    };

    checkSystemHealth();
    const interval = setInterval(checkSystemHealth, 25000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleScanComplete = (result) => {
    setLastScanResult(result);
  };

  const handleHeroScanClick = () => {
    setActiveTab('scanner');
    if (scannerRef.current) {
      scannerRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleSelectHistoryItem = (item) => {
    const modality = item.scan_type || 'url';
    setActiveModality(modality);
    setActiveTab('scanner');

    let parsedIndicators = [];
    try {
      parsedIndicators = Array.isArray(item.indicators) ? item.indicators : JSON.parse(item.indicators || '[]');
    } catch {
      parsedIndicators = [];
    }

    let parsedFeatures = {};
    try {
      parsedFeatures = typeof item.features === 'object' ? item.features : JSON.parse(item.features || '{}');
    } catch {
      parsedFeatures = {};
    }

    setLastScanResult({
      scan_type: modality,
      url: item.url,
      risk_score: item.risk_score,
      risk_level: item.risk_level,
      ml_confidence: item.ml_confidence,
      phishing_probability: item.phishing_probability ?? (item.risk_score / 100),
      summary: item.summary,
      indicators: parsedIndicators,
      features: parsedFeatures,
      extracted_urls: [],
      recommended_actions: [],
      scanned_at: item.scanned_at || item.created_at,
    });

    if (scannerRef.current) {
      scannerRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="app-layout">
      {/* Top Banner and Navigation */}
      <Header 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        systemStatus={systemStatus} 
      />

      {/* Hero 3D Section displayed at the top of the dashboard */}
      {activeTab === 'scanner' && (
        <CyberShield3D onScanClick={handleHeroScanClick} />
      )}

      {/* Main Content Area */}
      <main className="main-content" id="main-content" ref={scannerRef}>
        {activeTab === 'scanner' && (
          <ScannerTab 
            onScanComplete={handleScanComplete} 
            lastResult={lastScanResult} 
            initialModality={activeModality}
          />
        )}
        {activeTab === 'analytics' && <AnalyticsTab />}
        {activeTab === 'history' && (
          <HistoryTab onSelectHistoryItem={handleSelectHistoryItem} />
        )}
        {activeTab === 'model' && <ModelMetricsTab />}
        {activeTab === 'education' && <EducationTab />}
      </main>

      {/* Application Footer */}
      <footer className="app-footer">
        <div className="footer-inner">
          <div className="footer-left">
            <span className="footer-brand">ScamShield AI Platform</span>
            <span className="footer-sep">•</span>
            <span className="footer-sub">Defense-in-depth offline phishing &amp; scam intelligence</span>
          </div>

          <div className="footer-center">
            <span className="footer-disclaimer-pill">
              Message • URL • Screenshot • Email — Statistical Heuristic Risk Estimates
            </span>
          </div>

          <div className="footer-right">
            <span>FastAPI + Scikit-Learn + React 19</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
