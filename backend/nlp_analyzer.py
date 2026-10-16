"""
ScamShield AI - Explainable Message & SMS Scam Intelligence Engine
Analyzes messages, text communications, and chat logs for psychological urgency,
impersonation patterns, credential harvesting, payment extortion, and embedded malicious links.
"""

import re
from typing import Dict, Any, List, Tuple
from backend.schemas import IndicatorItem
from ml.features import extract_features
from backend.heuristics import evaluate_heuristics

# URL extraction regex
URL_REGEX = re.compile(
    r'(https?://[^\s<>"]+|www\.[^\s<>"]+|(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|xyz|top|icu|club|site|buzz|cc|info|biz|ru|cn|online)[^\s<>"]*)',
    re.IGNORECASE
)

# Psychological urgency and pressure triggers
URGENCY_PATTERNS = [
    (r'\b(?:immediate(?:ly)?|urgent(?:ly)?|action required|act now|hurry)\b', 'Immediate Action Pressure', 'HIGH'),
    (r'\b(?:within \d+ (?:hours?|mins?|minutes?|days?)|in \d+ (?:hours?|minutes?))\b', 'Strict Artificial Deadline', 'HIGH'),
    (r'\b(?:account (?:will be )?(?:suspended|locked|terminated|restricted|closed|disabled))\b', 'Threat of Account Termination', 'CRITICAL'),
    (r'\b(?:unauthorized (?:login|activity|access|transaction|charge))\b', 'Fictitious Security Scare', 'HIGH'),
    (r'\b(?:final (?:notice|warning|reminder)|last chance)\b', 'Final Notice Coercion', 'HIGH'),
    (r'\b(?:arrest warrant|law enforcement|legal action|court summons|fbi|police)\b', 'Legal Intimidation & Coercion', 'CRITICAL'),
]

# Targeted entity impersonation
IMPERSONATION_PATTERNS = [
    (r'\b(?:irs|internal revenue service|tax refund|tax department)\b', 'Government / IRS Impersonation', 'CRITICAL'),
    (r'\b(?:usps|fedex|dhl|ups|postal service|parcel delivery|package delivery)\b', 'Parcel / Courier Delivery Impersonation', 'HIGH'),
    (r'\b(?:geek squad|norton|mcafee|antivirus renewal|tech support|microsoft support)\b', 'Tech Support / Invoicing Impersonation', 'HIGH'),
    (r'\b(?:paypal|chase|wells fargo|bank of america|citibank|capital one)\b', 'Financial Institution Impersonation / Masquerade', 'CRITICAL'),
    (r'\b(?:apple id|icloud|amazon security|netflix billing|facebook security)\b', 'Big Tech Account Impersonation / Masquerade', 'HIGH'),
    (r'\b(?:coinbase|binance|metamask|trust wallet|ledger support)\b', 'Cryptocurrency Platform Impersonation', 'CRITICAL'),
]

# Credential & sensitive data lures
CREDENTIAL_PATTERNS = [
    (r'\b(?:seed phrase|recovery phrase|private key|secret keys?)\b', 'Crypto Seed Phrase Solicitation', 'CRITICAL'),
    (r'\b(?:passwords?|passcode|security pin|pin code)\b', 'Password / PIN Solicitation', 'CRITICAL'),
    (r'\b(?:one-time password|otp|verification code|2fa code|security code)\b', 'One-Time Verification Code (OTP) Harvesting', 'CRITICAL'),
    (r'\b(?:social security number|ssn|national identity|id card)\b', 'Government ID / SSN Solicitation', 'CRITICAL'),
    (r'\b(?:credit card number|cvv|card expiry|cvc|atm pin)\b', 'Payment Card Data Harvesting', 'CRITICAL'),
]

# Payment extortion & unconventional transfer methods
PAYMENT_PATTERNS = [
    (r'\b(?:gift cards?|apple gift card|google play card|steam card|target card)\b', 'Unconventional Gift Card Payment Demand', 'CRITICAL'),
    (r'\b(?:bitcoin|btc|crypto wallet|tether|usdt|ethereum|eth)\b', 'Unregulated Cryptocurrency Transfer Demand', 'HIGH'),
    (r'\b(?:wire transfer|western union|moneygram|zelle|cashapp)\b', 'Irreversible Direct Wire / Transfer Prompt', 'HIGH'),
    (r'\b(?:processing fee|customs fee|clearance fee|unfreeze fee)\b', 'Advance Fee Scam Indicator', 'HIGH'),
    (r'\b(?:you have won|lottery winner|cash prize|selected for \$[\d,]+)\b', 'Lottery / Prize Bait', 'HIGH'),
]

def analyze_message_content(text: str) -> Dict[str, Any]:
    """
    Executes deep rule-based and NLP pattern analysis on pasted message text.
    Returns composite risk score, risk level, indicator explanations, extracted URLs, and safety actions.
    """
    clean_text = (text or '').strip()
    if not clean_text:
        return {
            'risk_score': 0,
            'risk_level': 'SAFE',
            'intent_category': 'BENIGN_COMMUNICATION',
            'indicators': [],
            'extracted_urls': [],
            'summary': 'Empty message provided.',
            'recommended_actions': ['Provide message text to inspect.']
        }

    # Input length protection
    max_len = 10000
    if len(clean_text) > max_len:
        clean_text = clean_text[:max_len]

    indicators: List[IndicatorItem] = []
    score = 0
    categories_flagged = set()

    # 1. Evaluate Urgency & Coercion
    for pattern, name, severity in URGENCY_PATTERNS:
        match = re.search(pattern, clean_text, re.IGNORECASE)
        if match:
            pts = 35 if severity == 'CRITICAL' else 20
            score += pts
            categories_flagged.add('URGENCY')
            indicators.append(IndicatorItem(
                name=name,
                severity=severity,
                description=(
                    "Text employs intense psychological pressure or threats of service disruption "
                    "to force immediate compliance before the recipient can independently verify the claim."
                ),
                evidence=match.group(0)
            ))

    # 2. Evaluate Impersonation
    for pattern, name, severity in IMPERSONATION_PATTERNS:
        match = re.search(pattern, clean_text, re.IGNORECASE)
        if match:
            pts = 35 if severity == 'CRITICAL' else 25
            score += pts
            categories_flagged.add('IMPERSONATION')
            indicators.append(IndicatorItem(
                name=name,
                severity=severity,
                description=(
                    "Message claims to originate from an established brand, bank, or government agency. "
                    "Scammers routinely weaponize trusted logos and organizational names."
                ),
                evidence=match.group(0)
            ))

    # 3. Evaluate Credential Solicitation
    for pattern, name, severity in CREDENTIAL_PATTERNS:
        match = re.search(pattern, clean_text, re.IGNORECASE)
        if match:
            score += 45
            categories_flagged.add('CREDENTIALS')
            indicators.append(IndicatorItem(
                name=name,
                severity=severity,
                description=(
                    "Explicitly requests private credentials, one-time verification passcodes (OTP), "
                    "or crypto recovery keys. Legitimate organizations never request these via chat or SMS."
                ),
                evidence=match.group(0)
            ))

    # 4. Evaluate Payment Extortion / Gift Cards
    for pattern, name, severity in PAYMENT_PATTERNS:
        match = re.search(pattern, clean_text, re.IGNORECASE)
        if match:
            pts = 40 if severity == 'CRITICAL' else 25
            score += pts
            categories_flagged.add('PAYMENT')
            indicators.append(IndicatorItem(
                name=name,
                severity=severity,
                description=(
                    "Instructs payment through irreversible channels, gift cards, or crypto wallets. "
                    "Demands for gift card payments are a near-certain indicator of fraud."
                ),
                evidence=match.group(0)
            ))

    # 5. Extract and Analyze Embedded URLs
    raw_urls = URL_REGEX.findall(clean_text)
    extracted_urls = []
    has_risky_url = False

    for raw in raw_urls[:5]:  # limit to top 5 URLs in message
        candidate = raw.strip('.,;()[]{}<>')
        if not candidate.startswith(('http://', 'https://')):
            candidate = 'https://' + candidate

        try:
            url_feats = extract_features(candidate)
            url_indicators, url_h_score = evaluate_heuristics(candidate, url_feats)
            url_risk = 'HIGH' if url_h_score >= 50 else ('SUSPICIOUS' if url_h_score >= 25 else 'SAFE')
            
            extracted_urls.append({
                'url': candidate,
                'heuristic_score': url_h_score,
                'risk_level': url_risk,
                'indicator_count': len(url_indicators),
                'suspicious_tld': bool(url_feats.get('suspicious_tld')),
                'brand_impersonation': bool(url_feats.get('brand_impersonation')),
                'is_ip_address': bool(url_feats.get('is_ip_address')),
            })

            if url_risk in ('HIGH', 'SUSPICIOUS'):
                has_risky_url = True
                score += (35 if url_risk == 'HIGH' else 20)
                indicators.append(IndicatorItem(
                    name=f"Deceptive Embedded Link ({url_risk})",
                    severity='CRITICAL' if url_risk == 'HIGH' else 'HIGH',
                    description=(
                        f"Message embeds link '{candidate}' displaying suspicious structural characteristics, "
                        f"such as brand masquerading, high-abuse TLDs, or high randomness."
                    ),
                    evidence=candidate
                ))
        except Exception:
            extracted_urls.append({'url': candidate, 'risk_level': 'UNKNOWN', 'heuristic_score': 0})

    # Determine intent category
    if 'CREDENTIALS' in categories_flagged:
        intent = "CREDENTIAL_HARVESTING"
    elif 'PAYMENT' in categories_flagged:
        intent = "FINANCIAL_EXTORTION_OR_FRAUD"
    elif 'IMPERSONATION' in categories_flagged and 'URGENCY' in categories_flagged:
        intent = "URGENT_BRAND_MASQUERADE"
    elif has_risky_url:
        intent = "MALICIOUS_LINK_DELIVERY"
    elif 'URGENCY' in categories_flagged:
        intent = "SUSPICIOUS_URGENCY_SOLICITATION"
    elif score > 0:
        intent = "POTENTIAL_SOCIAL_ENGINEERING"
    else:
        intent = "BENIGN_COMMUNICATION"

    # Clamp risk score
    normalized_score = min(100, score)
    if normalized_score >= 65:
        risk_level = "HIGH"
    elif normalized_score >= 35:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "SAFE"

    # Recommended Actions
    actions = []
    if risk_level == "HIGH":
        actions.append("Do NOT click any links, download files, or reply to this message.")
        actions.append("Do NOT provide passwords, verification codes (OTP), or payment information under any circumstances.")
        actions.append("If this claims to be your bank or employer, navigate to their verified official website independently.")
        actions.append("Report and block the sender on your communication platform.")
    elif risk_level == "SUSPICIOUS":
        actions.append("Exercise elevated caution. Verify the sender's identity through an independent, trusted channel.")
        actions.append("Inspect any links using ScamShield AI's URL Scanner before interacting.")
        actions.append("Look out for follow-up requests demanding immediate payment or personal information.")
    else:
        actions.append("No common phishing or urgency signatures identified in text.")
        actions.append("Maintain baseline cyber hygiene. Remember that novel zero-day lures may lack obvious keywords.")

    # Executive Summary
    if risk_level == "HIGH":
        summary = f"High-risk scam threat identified ({intent}). Contains {len(indicators)} severe indicators including coercive tactics or credential solicitation."
    elif risk_level == "SUSPICIOUS":
        summary = f"Suspicious communication patterns detected ({intent}). Contains {len(indicators)} indicators requiring caution."
    else:
        summary = "No obvious phishing keywords, pressure tactics, or known scam patterns detected in text."

    return {
        'risk_score': normalized_score,
        'risk_level': risk_level,
        'intent_category': intent,
        'indicators': indicators,
        'extracted_urls': extracted_urls,
        'summary': summary,
        'recommended_actions': actions
    }
