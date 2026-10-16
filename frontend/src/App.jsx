import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import ScannerTab from './components/ScannerTab';
import AnalyticsTab from './components/AnalyticsTab';
import HistoryTab from './components/HistoryTab';
import ModelMetricsTab from './components/ModelMetricsTab';
import EducationTab from './components/EducationTab';
import { Shield, ShieldAlert, Cpu, Heart, CheckCircle2 } from 'lucide-react';
import './App.css';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [systemStatus, setSystemStatus] = useState({
    status: 'connecting',
    model_loaded: false,
    message: 'Initializing engine...',
  });
  const [lastScanResult, setLastScanResult] = useState(null);

  // Poll health on mount
  useEffect(() => {
    let isMounted = true;

    const checkSystemHealth = async () => {
      try {
        const response = await fetch('/api/v1/health');
        if (response.ok) {
          const data = await response.json();
          if (isMounted) {
            setSystemStatus({
              status: 'online',
              model_loaded: Boolean(data.model_loaded),
              message: data.model_loaded ? 'Engine v1.0 Ready' : 'Heuristic Mode Only',
              version: data.version,
            });
          }
        } else {
          if (isMounted) {
            setSystemStatus({
              status: 'offline',
              model_loaded: false,
              message: 'Backend Service Unavailable',
            });
          }
        }
      } catch (err) {
        if (isMounted) {
          setSystemStatus({
            status: 'offline',
            model_loaded: false,
            message: 'Engine Offline',
          });
        }
      }
    };

    checkSystemHealth();
    const interval = setInterval(checkSystemHealth, 20000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const handleScanComplete = (result) => {
    setLastScanResult(result);
  };

  const handleSelectHistoryItem = (item) => {
    // Transform history item into result format if needed and open in scanner
    setLastScanResult({
      url: item.url,
      risk_score: item.risk_score,
      risk_level: item.risk_level,
      ml_confidence: item.ml_confidence,
      phishing_probability: item.phishing_probability ?? (item.risk_score / 100),
      indicators: Array.isArray(item.indicators) ? item.indicators : JSON.parse(item.indicators || '[]'),
      features: typeof item.features === 'object' ? item.features : JSON.parse(item.features || '{}'),
      scanned_at: item.scanned_at || item.created_at,
    });
    setActiveTab('scanner');
  };

  return (
    <div className="app-layout">
      {/* Top Banner and Navigation */}
      <Header 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        systemStatus={systemStatus} 
      />

      {/* Main Content Area */}
      <main className="main-content" id="main-content">
        {activeTab === 'scanner' && (
          <ScannerTab 
            onScanComplete={handleScanComplete} 
            lastResult={lastScanResult} 
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
            <span className="footer-sub">Defense-in-depth offline phishing & scam intelligence</span>
          </div>

          <div className="footer-center">
            <span className="footer-disclaimer-pill">
              Statistical Heuristic Estimates • Zero Remote Connection Policy
            </span>
          </div>

          <div className="footer-right">
            <span>FastAPI + Scikit-Learn + React</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
