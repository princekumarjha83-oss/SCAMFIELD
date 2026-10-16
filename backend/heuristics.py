"""
ScamShield AI - Security Heuristics & Explainability Engine
Evaluates static lexical, structural, and entropy rules to detect deception techniques
and produce human-readable security explanations for SOC analysts and end users.
"""

from typing import List, Dict, Any, Tuple
from backend.schemas import IndicatorItem

def evaluate_heuristics(url: str, features: Dict[str, Any]) -> Tuple[List[IndicatorItem], int]:
    """
    Evaluates rule-based heuristic threat indicators.
    Returns:
    - List of structured IndicatorItem explanations
    - Heuristic score (0 - 100)
    """
    indicators: List[IndicatorItem] = []
    score_accum = 0

    meta = features.get('_meta', {})
    host = meta.get('host', '')
    flagged_brand = meta.get('flagged_brand')
    matched_keyword = meta.get('matched_keyword')

    # 1. Brand Impersonation
    if features.get('brand_impersonation'):
        score_accum += 45
        indicators.append(IndicatorItem(
            name="Brand Impersonation / Masquerading",
            severity="CRITICAL",
            description=(
                f"Trusted brand identity '{flagged_brand.capitalize() if flagged_brand else 'keyword'}' "
                f"appears in the hostname outside of the official apex domain, a critical indicator of credential harvesting."
            ),
            evidence=host
        ))

    # 2. Direct IPv4 Host
    if features.get('is_ip_address'):
        score_accum += 40
        indicators.append(IndicatorItem(
            name="Direct IPv4 Address Host",
            severity="HIGH",
            description=(
                "Target host is a raw numerical IP address rather than a registered domain name. "
                "Attackers use direct IP hosts to bypass DNS blacklists and domain registration audit trails."
            ),
            evidence=host
        ))

    # 3. Suspicious / High-Abuse TLD
    if features.get('suspicious_tld'):
        score_accum += 30
        tld = meta.get('tld', 'unknown')
        indicators.append(IndicatorItem(
            name="High-Abuse Top-Level Domain",
            severity="HIGH",
            description=(
                f"Uses top-level domain '.{tld}', which exhibits disproportionately high abuse "
                f"rates across global threat feeds due to low registrar friction and disposable registration."
            ),
            evidence=f".{tld}"
        ))

    # 4. At-Symbol RFC Deception
    if features.get('at_count', 0) > 0:
        score_accum += 35
        indicators.append(IndicatorItem(
            name="At-Symbol (@) Authority Confusion",
            severity="HIGH",
            description=(
                "URL contains an '@' character. Browsers treat all characters before '@' as credential "
                "userinfo and actually route to the host appearing after '@', deceiving readers."
            ),
            evidence="@"
        ))

    # 5. Shannon Entropy Anomaly
    domain_entropy = features.get('domain_entropy', 0.0)
    if domain_entropy >= 3.8:
        severity = "HIGH" if domain_entropy >= 4.3 else "MEDIUM"
        score_accum += 20 if severity == "HIGH" else 12
        indicators.append(IndicatorItem(
            name="Elevated Shannon Entropy (Domain Randomness)",
            severity=severity,
            description=(
                f"Domain entropy measured at {domain_entropy:.3f} bits. "
                f"High randomness is a strong signature of Domain Generation Algorithms (DGA) or disposable phishing names."
            ),
            evidence=f"{domain_entropy:.3f} bits"
        ))

    # 6. Subdomain Stacking
    subdomains = features.get('subdomain_count', 0)
    if subdomains >= 2:
        severity = "HIGH" if subdomains >= 3 else "MEDIUM"
        score_accum += 18 if severity == "HIGH" else 10
        indicators.append(IndicatorItem(
            name="Subdomain Stacking Deception",
            severity=severity,
            description=(
                f"Hostname contains {subdomains} levels of subdomains. "
                f"Threat actors stack subdomains to mimic authoritative services and push the true domain off screen on mobile displays."
            ),
            evidence=f"{subdomains} subdomain levels"
        ))

    # 7. Sensitive / Banking Keywords
    if features.get('has_login_keyword'):
        score_accum += 15
        indicators.append(IndicatorItem(
            name="Credential / Banking Lure Keyword",
            severity="MEDIUM",
            description=(
                f"Path or subdomain contains sensitive authentication keyword '{matched_keyword}', "
                f"commonly used to bait victims into logging in or resolving fictitious security disputes."
            ),
            evidence=matched_keyword or "auth keyword"
        ))

    # 8. Non-Standard Port Execution
    if features.get('has_port'):
        score_accum += 15
        indicators.append(IndicatorItem(
            name="Non-Standard Web Service Port",
            severity="MEDIUM",
            description=(
                "Target operates over a non-standard HTTP port (e.g., :8080, :8443, :8888), "
                "frequently associated with temporary rogue proxies and ad-hoc phishing kits."
            ),
            evidence=f"Port in {host}"
        ))

    # 9. Excessive URL Length
    url_len = features.get('url_length', 0)
    if url_len > 95:
        score_accum += 8
        indicators.append(IndicatorItem(
            name="Abnormally Long URL Structure",
            severity="LOW",
            description=(
                f"URL length is {url_len} characters. Excessive path or parameter depth is used to "
                f"obscure destinations or pass obfuscated payload tokens."
            ),
            evidence=f"{url_len} chars"
        ))

    # Normalize heuristic score to 0 - 100
    normalized_heuristic_score = min(100, score_accum)
    return indicators, normalized_heuristic_score

def compute_composite_risk(
    ml_phishing_probability: float, 
    heuristic_score: int
) -> Tuple[int, str]:
    """
    Computes balanced composite threat rating combining ML inference and deterministic heuristics:
    - 55% weight to ML statistical classifier
    - 45% weight to deterministic heuristic safety engine
    """
    ml_scaled = ml_phishing_probability * 100
    composite = round((0.55 * ml_scaled) + (0.45 * heuristic_score))
    composite = max(0, min(100, composite))

    if composite >= 65:
        level = "HIGH"
    elif composite >= 35:
        level = "SUSPICIOUS"
    else:
        level = "SAFE"

    return composite, level
