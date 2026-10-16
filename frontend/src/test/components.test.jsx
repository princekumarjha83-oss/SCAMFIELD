import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import ScannerTab from '../components/ScannerTab';
import Header from '../components/Header';

describe('Header Component', () => {
  it('renders brand title and operational security badge', () => {
    render(
      <Header 
        activeTab="scanner" 
        setActiveTab={() => {}} 
        systemStatus={{ model_loaded: true }} 
      />
    );
    expect(screen.getByText(/ScamShield/i)).toBeInTheDocument();
    expect(screen.getByText(/ZERO SSRF/i)).toBeInTheDocument();
    expect(screen.getByText(/Engine v2.0 Ready/i)).toBeInTheDocument();
  });

  it('renders all 5 main navigation tabs', () => {
    render(
      <Header 
        activeTab="scanner" 
        setActiveTab={() => {}} 
        systemStatus={{ model_loaded: true }} 
      />
    );
    expect(screen.getByRole('tab', { name: /Threat Workspace/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Threat Analytics/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Scan History/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Model Provenance/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Security Academy/i })).toBeInTheDocument();
  });
});

describe('ScannerTab Component', () => {
  it('validates protocol format before submitting URL', async () => {
    render(<ScannerTab />);
    const input = screen.getByPlaceholderText(/Enter complete target URL/i);
    const submitBtn = screen.getByRole('button', { name: /Analyze URL/i });

    fireEvent.change(input, { target: { value: 'not-a-valid-url-format' } });
    fireEvent.click(submitBtn);

    expect(
      await screen.findByText(/Please specify a protocol \(http:\/\/ or https:\/\/\)/i)
    ).toBeInTheDocument();
  });

  it('switches between scanning modalities (URL, Message, Screenshot, Email)', () => {
    render(<ScannerTab />);
    
    // Check mode buttons
    const msgBtn = screen.getByRole('tab', { name: /Message Scanner/i });
    const screenshotBtn = screen.getByRole('tab', { name: /Screenshot Scanner/i });
    const emailBtn = screen.getByRole('tab', { name: /Email Scanner/i });

    // Switch to Message Scanner
    fireEvent.click(msgBtn);
    expect(screen.getByPlaceholderText(/Paste suspicious text message, SMS/i)).toBeInTheDocument();

    // Switch to Screenshot Scanner
    fireEvent.click(screenshotBtn);
    expect(screen.getByText(/Drop your screenshot here, or browse/i)).toBeInTheDocument();

    // Switch to Email Scanner
    fireEvent.click(emailBtn);
    expect(screen.getByPlaceholderText(/PayPal Alerts <service@domain\.com>/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Urgent Action Required: Account Locked/i)).toBeInTheDocument();
  });

  it('displays ethical AI disclaimer and threat score when result is provided', () => {
    const mockResult = {
      url: 'https://paypal.com.security-alert-verify.top/login',
      risk_score: 92,
      risk_level: 'HIGH',
      ml_confidence: 0.95,
      phishing_probability: 0.92,
      indicators: [
        {
          name: 'Suspicious TLD Recognized',
          severity: 'HIGH',
          description: 'Uses high-abuse .top top-level domain.',
          evidence: '.top',
        },
      ],
      features: {
        domain: 'security-alert-verify.top',
        protocol: 'https:',
        url_length: 53,
        dot_count: 4,
        subdomain_count: 3,
        is_ip_address: false,
        brand_impersonation_flag: true,
        suspicious_tld: true,
        shannon_entropy: 4.12,
      },
    };

    render(<ScannerTab lastResult={mockResult} />);
    expect(screen.getAllByText(/92/)[0]).toBeInTheDocument();
    expect(screen.getByText(/HIGH RISK \/ MALICIOUS PHISHING/i)).toBeInTheDocument();
    expect(screen.getByText(/Uses high-abuse \.top/i)).toBeInTheDocument();
    expect(screen.getByText(/Defensive AI Scope & Non-Guarantee Notice/i)).toBeInTheDocument();
  });
});


