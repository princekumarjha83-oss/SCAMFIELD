"""
ScamShield AI - Static URL Feature Extractor
Extracts 22 offline lexical, structural, and information-entropy features from a given URL.
NEVER performs network connections, HTTP requests, or DNS queries.
"""

import math
import re
from urllib.parse import urlparse, parse_qs
from collections import Counter
from typing import Dict, Any, List

# Suspicious / high-abuse TLDs based on global registrar abuse statistics
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'work', 'icu', 'tk', 'ml', 'ga', 'cf', 'gq', 
    'buzz', 'fit', 'rest', 'cam', 'sbs', 'cfd', 'click', 'link', 
    'surf', 'live', 'club', 'monster', 'beauty', 'hair', 'skin',
    'quest', 'bar', 'press', 'host', 'space', 'site', 'website'
}

# Brands frequently targeted by phishing campaigns
HIGH_TARGET_BRANDS = [
    'paypal', 'apple', 'netflix', 'amazon', 'google', 'microsoft',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 
    'binance', 'coinbase', 'metamask', 'facebook', 'instagram', 
    'whatsapp', 'dropbox', 'dhl', 'fedex', 'usps', 'irs', 'linkedin',
    'telegram', 'steam', 'roblox', 'ebay', 'walmart', 'yahoo', 'outlook'
]

# Legitimate brand apex domains where brand name is expected
LEGITIMATE_BRAND_DOMAINS = {
    'paypal': ['paypal.com', 'paypal.me'],
    'apple': ['apple.com', 'icloud.com'],
    'netflix': ['netflix.com'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'aws.amazon.com'],
    'google': ['google.com', 'accounts.google.com', 'drive.google.com'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
    'chase': ['chase.com'],
    'wellsfargo': ['wellsfargo.com'],
    'bankofamerica': ['bankofamerica.com'],
    'citibank': ['citi.com', 'citibank.com'],
    'binance': ['binance.com'],
    'coinbase': ['coinbase.com'],
    'metamask': ['metamask.io'],
    'facebook': ['facebook.com', 'fb.com'],
    'instagram': ['instagram.com'],
    'whatsapp': ['whatsapp.com'],
    'linkedin': ['linkedin.com'],
    'steam': ['steampowered.com', 'steamcommunity.com'],
    'ebay': ['ebay.com'],
    'walmart': ['walmart.com'],
    'yahoo': ['yahoo.com'],
}

# Suspicious keywords in paths or subdomains
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'account', 'security',
    'update', 'banking', 'confirm', 'confirmation', 'wallet', 'secure',
    'support', 'recover', 'billing', 'invoice', 'auth', 'authorize',
    'validation', 'dispute', 'suspended', 'unlock', 'urgent', 'alert'
]

IP_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?$'
)

FEATURE_NAMES = [
    'url_length',
    'host_length',
    'path_length',
    'query_length',
    'dot_count',
    'hyphen_count',
    'underscore_count',
    'slash_count',
    'at_count',
    'percent_count',
    'digit_count',
    'digit_ratio',
    'shannon_entropy',
    'domain_entropy',
    'is_ip_address',
    'subdomain_count',
    'suspicious_tld',
    'brand_impersonation',
    'has_login_keyword',
    'num_query_params',
    'has_port',
    'ratio_special_chars',
]

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon Entropy in bits per symbol for a given string."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def is_ip_host(host: str) -> bool:
    """Returns True if the host is a raw IPv4 address."""
    clean_host = host.split(':')[0].strip('[]')
    return bool(IP_REGEX.match(clean_host))

def extract_features(url: str) -> Dict[str, Any]:
    """
    Extracts numerical and structural features from a target URL.
    Returns both feature vector values and contextual metadata.
    """
    url_clean = (url or '').strip()
    parsed = urlparse(url_clean)

    host = (parsed.hostname or parsed.netloc or '').lower()
    port = parsed.port
    path = parsed.path or ''
    query = parsed.query or ''

    # Strip port from host for domain analysis
    host_no_port = host.split(':')[0]

    # Domain parts analysis
    host_parts = [p for p in host_no_port.split('.') if p]
    tld = host_parts[-1] if host_parts else ''

    # Subdomains count
    subdomain_count = max(0, len(host_parts) - 2) if len(host_parts) >= 2 else 0

    # Suspicious TLD check
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Brand impersonation check
    brand_impersonation = 0
    flagged_brand = None
    for brand in HIGH_TARGET_BRANDS:
        if brand in host_no_port:
            # Check if host is the legitimate domain or a legitimate subdomain
            allowed_domains = LEGITIMATE_BRAND_DOMAINS.get(brand, [f"{brand}.com"])
            is_legit = False
            for allowed in allowed_domains:
                if host_no_port == allowed or host_no_port.endswith('.' + allowed):
                    is_legit = True
                    break
            if not is_legit:
                brand_impersonation = 1
                flagged_brand = brand
                break

    # Keyword presence
    has_keyword = 0
    matched_keyword = None
    combined_text = (host + path + query).lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in combined_text:
            has_keyword = 1
            matched_keyword = kw
            break

    # At symbol check
    at_count = url_clean.count('@')

    # Character counts & ratios
    url_len = len(url_clean)
    host_len = len(host_no_port)
    path_len = len(path)
    query_len = len(query)

    dot_count = url_clean.count('.')
    hyphen_count = url_clean.count('-')
    underscore_count = url_clean.count('_')
    slash_count = url_clean.count('/')
    percent_count = url_clean.count('%')
    
    digits = sum(c.isdigit() for c in url_clean)
    digit_ratio = round(digits / url_len, 4) if url_len > 0 else 0.0

    special_chars = sum(not c.isalnum() for c in url_clean)
    ratio_special = round(special_chars / url_len, 4) if url_len > 0 else 0.0

    shannon_entropy = calculate_shannon_entropy(url_clean)
    domain_entropy = calculate_shannon_entropy(host_no_port)

    num_params = len(parse_qs(query)) if query else 0
    has_port = 1 if port and port not in (80, 443) else 0
    is_ip = 1 if is_ip_host(host_no_port) else 0

    features = {
        'url_length': url_len,
        'host_length': host_len,
        'path_length': path_len,
        'query_length': query_len,
        'dot_count': dot_count,
        'hyphen_count': hyphen_count,
        'underscore_count': underscore_count,
        'slash_count': slash_count,
        'at_count': at_count,
        'percent_count': percent_count,
        'digit_count': digits,
        'digit_ratio': digit_ratio,
        'shannon_entropy': shannon_entropy,
        'domain_entropy': domain_entropy,
        'is_ip_address': is_ip,
        'subdomain_count': subdomain_count,
        'suspicious_tld': is_suspicious_tld,
        'brand_impersonation': brand_impersonation,
        'has_login_keyword': has_keyword,
        'num_query_params': num_params,
        'has_port': has_port,
        'ratio_special_chars': ratio_special,
        # Contextual metadata for explanations
        '_meta': {
            'host': host_no_port,
            'protocol': parsed.scheme or 'http',
            'tld': tld,
            'flagged_brand': flagged_brand,
            'matched_keyword': matched_keyword,
        }
    }

    return features

def features_to_vector(features_dict: Dict[str, Any]) -> List[float]:
    """Converts a features dictionary to a strictly ordered numerical vector for ML inference."""
    return [float(features_dict[name]) for name in FEATURE_NAMES]
