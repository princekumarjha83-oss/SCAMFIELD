import React, { useState } from 'react';
import { 
  BookOpen, ShieldCheck, AlertTriangle, Eye, Terminal, 
  HelpCircle, CheckCircle, ChevronDown, ChevronRight, Lock 
} from 'lucide-react';

const ATTACK_VECTORS = [
  {
    title: 'Subdomain Masquerading',
    difficulty: 'Very Common',
    summary: 'Attackers create subdomains named after trusted brands on a rogue apex domain.',
    example: 'https://paypal.com.customer-verification-portal.xyz/login',
    explanation: 'Users see "paypal.com" at the beginning of the URL and trust it, but the actual authoritative destination registered with DNS is "customer-verification-portal.xyz". In DNS hierarchy, the true domain is always immediately preceding the TLD.',
    mitigation: 'Always read URLs from the rightmost slash backwards to find the apex domain before the TLD.'
  },
  {
    title: 'Homoglyph & Punycode Spoofing',
    difficulty: 'Advanced / Stealthy',
    summary: 'Using lookalike Unicode/Cyrillic characters that appear identical to Latin characters.',
    example: 'https://pаypal.com (uses Cyrillic "а" U+0430 instead of Latin "a")',
    explanation: 'Modern browsers support Internationalized Domain Names (IDNs). Threat actors register domains with visually identical Cyrillic or Greek glyphs. When rendered, human eyes cannot differentiate them, but the browser translates them to "xn--pypal-43a.com".',
    mitigation: 'Look for browser Punycode alerts, inspect certificates, or copy-paste into plaintext editors to inspect raw ASCII representation.'
  },
  {
    title: 'Direct IP Host Addresses',
    difficulty: 'Common in Automated Scams',
    summary: 'Using raw IPv4 or IPv6 addresses instead of registered domain names.',
    example: 'http://185.220.101.5:8080/secure/bank-login.html',
    explanation: 'Legitimate financial, corporate, and social media platforms virtually never ask customers to access websites via raw numerical IP addresses. Threat actors use direct IPs to evade domain reputation blacklists and DNS registration registration logs.',
    mitigation: 'Never enter sensitive personal credentials on sites hosted on raw numerical IP addresses.'
  },
  {
    title: 'At-Symbol (@) Authority Deception',
    difficulty: 'Classic Deception',
    summary: 'Using the RFC URL userinfo delimiter (@) to confuse the human reader.',
    example: 'https://amazon.com:security-check@phishing-server.top/reset',
    explanation: 'Under RFC 3986 URL specifications, any text before the "@" symbol is interpreted as username and authentication info, while the host that the browser actually connects to is the text AFTER the "@" symbol.',
    mitigation: 'ScamShield flags any URL containing "@" as a high-severity threat indicator.'
  },
  {
    title: 'Suspicious / High-Abuse TLDs',
    difficulty: 'Common Bulk Phishing',
    summary: 'Leveraging discount top-level domains with minimal registrar oversight.',
    example: 'https://urgent-chase-security.top / .xyz / .work / .icu',
    explanation: 'Certain gTLDs are heavily targeted by automated cybercrime rings because domain registration costs are nominal (often under $1.00) and identity verification is non-existent, enabling rapid burner infrastructure.',
    mitigation: 'Treat incoming banking or account alerts from non-standard or unusual TLDs with extreme skepticism.'
  }
];

export default function EducationTab() {
  const [expandedIndex, setExpandedIndex] = useState(0);

  return (
    <div className="education-container animate-fade-in">
      <div className="education-header">
        <div>
          <h2 className="tab-heading">Cybersecurity Academy: Anti-Phishing Guidance</h2>
          <p className="tab-sub">
            Learn how modern threat actors craft deceptive URLs and how static defense-in-depth analysis neutralizes them.
          </p>
        </div>
      </div>

      {/* Anatomy of a Malicious URL Interactive Breakdown */}
      <div className="glass-panel edu-card">
        <h3 className="card-section-title">Anatomy of a Deceptive URL</h3>
        <p className="card-section-sub">
          How threat actors engineer each component of a URL to trick victims and bypass traditional email filters.
        </p>

        <div className="url-dissection-box">
          <div className="dissect-url-visual">
            <span className="part part-proto" title="Protocol">https://</span>
            <span className="part part-sub" title="Deceptive Brand Subdomain">paypal.com.account-update.</span>
            <span className="part part-domain" title="Actual Rogue Apex Domain">secureserver</span>
            <span className="part part-tld" title="High-Abuse TLD">.xyz</span>
            <span className="part part-port" title="Non-standard Port">:8443</span>
            <span className="part part-path" title="Deep Mimicking Path">/webapps/mpp/auth</span>
            <span className="part part-query" title="Obfuscated Token Query">?token=928a&user=victim</span>
          </div>

          <div className="dissect-legend-grid">
            <div className="dissect-legend-item">
              <span className="legend-tag tag-sub">Subdomain Stacking</span>
              <p>Prepends trusted keywords ("paypal.com") to fool human visual scanning.</p>
            </div>
            <div className="dissect-legend-item">
              <span className="legend-tag tag-domain">Authoritative Apex Domain</span>
              <p>The REAL server destination ("secureserver.xyz") controlled by the attacker.</p>
            </div>
            <div className="dissect-legend-item">
              <span className="legend-tag tag-tld">Abuse-Prone TLD</span>
              <p>Budget top-level domains frequently weaponized for short-lived phishing campaigns.</p>
            </div>
            <div className="dissect-legend-item">
              <span className="legend-tag tag-path">Credential Harvesting Path</span>
              <p>Copies legitimate company path formats to increase credibility if noticed.</p>
            </div>
          </div>
        </div>
      </div>

      {/* Phishing Techniques Accordion */}
      <div className="glass-panel edu-card">
        <h3 className="card-section-title">Common URL Threat Vectors & Attack Mechanics</h3>
        <p className="card-section-sub">
          Detailed technical breakdown of deceptive practices, weaponization examples, and defense tips.
        </p>

        <div className="vectors-accordion">
          {ATTACK_VECTORS.map((vec, idx) => {
            const isExpanded = expandedIndex === idx;
            return (
              <div 
                key={idx} 
                className={`vector-item ${isExpanded ? 'vector-item-expanded' : ''}`}
              >
                <button
                  onClick={() => setExpandedIndex(isExpanded ? -1 : idx)}
                  className="vector-toggle-btn"
                  aria-expanded={isExpanded}
                >
                  <div className="vector-title-group">
                    <span className="vector-num">0{idx + 1}</span>
                    <strong className="vector-title">{vec.title}</strong>
                    <span className="vector-diff-pill">{vec.difficulty}</span>
                  </div>
                  {isExpanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
                </button>

                {isExpanded && (
                  <div className="vector-details-body animate-fade-in">
                    <p className="vector-summary">{vec.summary}</p>
                    
                    <div className="vector-example-box">
                      <span className="example-label">Weaponized Example:</span>
                      <code className="mono example-code">{vec.example}</code>
                    </div>

                    <div className="vector-analysis">
                      <strong>Deception Mechanics:</strong>
                      <p>{vec.explanation}</p>
                    </div>

                    <div className="vector-mitigation">
                      <div className="mitigation-header">
                        <ShieldCheck size={16} className="text-emerald" />
                        <span>Recommended Defense & Verification:</span>
                      </div>
                      <p>{vec.mitigation}</p>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Golden Rules Checklist */}
      <div className="glass-panel edu-card">
        <h3 className="card-section-title">SOC Defensive Checklist: 5 Golden Rules</h3>
        <p className="card-section-sub">Standard operating rules for validating links before interacting</p>

        <div className="rules-grid">
          <div className="rule-card">
            <div className="rule-header">
              <CheckCircle size={18} className="text-emerald" />
              <strong>1. Inspect the Root Domain</strong>
            </div>
            <p>Ignore what is in the subdomains or path. Look at the two segments directly left of the first forward slash.</p>
          </div>

          <div className="rule-card">
            <div className="rule-header">
              <CheckCircle size={18} className="text-emerald" />
              <strong>2. Beware of Forced Urgency</strong>
            </div>
            <p>Phishing links almost always pair with urgent psychological triggers ("Account suspended within 24 hours").</p>
          </div>

          <div className="rule-card">
            <div className="rule-header">
              <CheckCircle size={18} className="text-emerald" />
              <strong>3. Never Trust Raw IP Hosts</strong>
            </div>
            <p>No legitimate consumer bank or service operates primary authentication through raw numerical IP endpoints.</p>
          </div>

          <div className="rule-card">
            <div className="rule-header">
              <CheckCircle size={18} className="text-emerald" />
              <strong>4. Use Static Inspection First</strong>
            </div>
            <p>Always inspect suspicious links statically using ScamShield AI before opening in any browser sandbox.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
