"""
ScamShield AI - Enterprise Email Phishing & Spoofing Intelligence Engine
Safely parses email headers, inspects sender consistency, evaluates subject coercion,
extracts embedded links, and detects malicious attachment lures.
"""

import re
import email
from email import policy
from typing import Dict, Any, List, Optional
from backend.schemas import IndicatorItem
from backend.nlp_analyzer import analyze_message_content
from ml.features import extract_features
from backend.heuristics import evaluate_heuristics

# Major free webmail providers
FREE_MAIL_PROVIDERS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
    'proton.me', 'protonmail.com', 'zoho.com', 'icloud.com', 'mail.com',
    'gmx.com', 'yandex.com', 'mail.ru', 'live.com'
}

# Organizations that NEVER send official notices from free consumer webmail
OFFICIAL_ORGANIZATIONS = [
    'paypal', 'chase', 'wells fargo', 'bank of america', 'citibank',
    'apple', 'microsoft', 'amazon', 'netflix', 'geek squad', 'norton',
    'mcafee', 'irs', 'usps', 'fedex', 'dhl', 'binance', 'coinbase',
    'meta', 'facebook', 'instagram', 'linkedin', 'google'
]

# High-risk attachment file extensions
DANGEROUS_EXTENSIONS = [
    '.exe', '.scr', '.vbs', '.bat', '.cmd', '.iso', '.img', '.hta',
    '.ps1', '.jar', '.xlsm', '.docm', '.zip', '.rar', '.7z'
]

def parse_email_input(raw_or_body: str, subject: Optional[str] = None, sender: Optional[str] = None) -> Dict[str, str]:
    """
    Safely parses incoming email input. Handles either structured fields
    or a raw RFC 822 email message with headers.
    """
    clean_input = (raw_or_body or '').strip()

    parsed_sender = (sender or '').strip()
    parsed_subject = (subject or '').strip()
    parsed_body = clean_input

    # Check if input looks like an RFC 822 formatted message (has header delimiters)
    if 'From:' in clean_input and ('Subject:' in clean_input or 'To:' in clean_input):
        try:
            msg = email.message_from_string(clean_input, policy=policy.default)
            if msg.get('From'):
                parsed_sender = str(msg.get('From'))
            if msg.get('Subject'):
                parsed_subject = str(msg.get('Subject'))

            # Extract body
            if msg.is_multipart():
                parts = []
                for part in msg.walk():
                    if part.get_content_type() in ('text/plain', 'text/html'):
                        try:
                            parts.append(part.get_content())
                        except Exception:
                            pass
                if parts:
                    parsed_body = "\n".join(parts)
            else:
                try:
                    parsed_body = msg.get_content()
                except Exception:
                    parsed_body = msg.get_payload() or clean_input
        except Exception:
            pass

    return {
        'sender': parsed_sender,
        'subject': parsed_subject,
        'body': parsed_body
    }

def analyze_email_content(
    body: str, 
    subject: Optional[str] = None, 
    sender: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyzes an email for phishing indicators, sender masquerading,
    subject urgency, embedded link risk, and mentioned attachment hazards.
    """
    parsed = parse_email_input(body, subject, sender)
    sender_str = parsed['sender']
    subject_str = parsed['subject']
    body_str = parsed['body']

    indicators: List[IndicatorItem] = []
    score = 0

    # 1. Sender Spoofing & Domain Inconsistency Analysis
    if sender_str:
        sender_lower = sender_str.lower()
        
        # Extract email address between < > or direct address
        email_match = re.search(r'<([^>]+)>|([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', sender_str)
        actual_addr = email_match.group(1) or email_match.group(2) if email_match else sender_str
        sender_domain = actual_addr.split('@')[-1].lower() if '@' in actual_addr else ''

        # Check for free webmail impersonation
        for org in OFFICIAL_ORGANIZATIONS:
            if org in sender_lower:
                if sender_domain in FREE_MAIL_PROVIDERS:
                    score += 45
                    indicators.append(IndicatorItem(
                        name="Free Webmail Brand Impersonation",
                        severity="CRITICAL",
                        description=(
                            f"Sender claims identity '{org.capitalize()}' in display name, "
                            f"but sends from public consumer webmail provider '{sender_domain}'. "
                            f"Official enterprise communications never originate from free webmail accounts."
                        ),
                        evidence=sender_str
                    ))
                    break
                elif sender_domain and org not in sender_domain:
                    # e.g., Display name: PayPal Security <support@update-services-portal.xyz>
                    score += 35
                    indicators.append(IndicatorItem(
                        name="Sender Display Name vs Domain Mismatch",
                        severity="HIGH",
                        description=(
                            f"Display name references '{org.capitalize()}', but the actual sender domain is '{sender_domain}'. "
                            f"This is a classic display-name deception tactic."
                        ),
                        evidence=f"From: {sender_str}"
                    ))
                    break

    # 2. Subject Line Analysis (Urgency & False Conversational History)
    if subject_str:
        subj_lower = subject_str.lower()
        
        # Fake conversation thread prefix
        if re.match(r'^(?:re:|fwd:)\s*', subj_lower):
            score += 15
            indicators.append(IndicatorItem(
                name="Deceptive Conversation Continuation Prefix",
                severity="MEDIUM",
                description=(
                    f"Subject line prepends 'RE:' or 'FWD:' ({subject_str}) to deceive the recipient into "
                    f"believing this is a continuation of an existing trusted correspondence."
                ),
                evidence=subject_str
            ))

        # Urgent subject alarm
        if re.search(r'\b(?:urgent|immediate action|suspended|account notice|security alert|final notice)\b', subj_lower):
            score += 20
            indicators.append(IndicatorItem(
                name="Urgent Threat Trigger in Subject Line",
                severity="HIGH",
                description="Subject line utilizes coercive alarmist keywords to manipulate the recipient into reacting hastily.",
                evidence=subject_str
            ))

    # 3. Email Body Analysis (Passes through NLP Engine)
    body_analysis = analyze_message_content(body_str)
    
    # Merge body indicators
    for ind in body_analysis.get('indicators', []):
        indicators.append(ind)
    score += body_analysis.get('risk_score', 0)

    # 4. Dangerous Attachments Mentioned in Text
    for ext in DANGEROUS_EXTENSIONS:
        if re.search(re.escape(ext) + r'\b', body_str, re.IGNORECASE):
            score += 25
            indicators.append(IndicatorItem(
                name=f"High-Risk Attachment Mentioned ({ext})",
                severity="HIGH",
                description=(
                    f"Email text references executable, script, or compressed archive file type '{ext}', "
                    f"frequently weaponized as payload droppers for malware or ransomware."
                ),
                evidence=ext
            ))
            break

    # Clamp composite score
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
        actions.append("Do NOT open any attachments, click embedded links, or reply to this message.")
        actions.append("Do NOT trust the sender display name. Verify sender address header manually.")
        actions.append("Report this message as phishing to your email provider or corporate security team.")
    elif risk_level == "SUSPICIOUS":
        actions.append("Exercise caution. Verify the sender's identity through official corporate channels.")
        actions.append("Inspect embedded links in ScamShield AI's URL Scanner prior to opening.")
    else:
        actions.append("No obvious phishing, sender mismatch, or coercive lures identified in text.")
        actions.append("Maintain baseline verification: check the actual email address header, not just display name.")

    return {
        'risk_score': normalized_score,
        'risk_level': risk_level,
        'sender': sender_str or 'Not provided',
        'subject': subject_str or 'Not provided',
        'indicators': indicators,
        'extracted_urls': body_analysis.get('extracted_urls', []),
        'summary': (
            f"Email flagged as {risk_level} risk ({len(indicators)} indicators detected). "
            + ("High-probability phishing or impersonation attack." if risk_level == "HIGH" else "Review recommended.")
        ),
        'recommended_actions': actions,
        'disclaimer': (
            "Text & Header Structural Analysis Only: This inspection statically analyzes message text, "
            "sender domain consistency, and embedded links. Cryptographic authentication (SPF, DKIM, DMARC) "
            "and active payload execution were not evaluated."
        )
    }
