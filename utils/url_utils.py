"""
TRUSTSHIELD - URL Forensic Utilities
Extracts structural, lexical, and behavioral features from URLs to identify technical red flags.
Deterministic, safe, offline static analysis with zero network requests.
"""

from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs
import math
import re

# Commonly abused top-level domains in phishing and scam campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "loan", "click", "buzz", "racing", "date", "fit", "surf",
    "country", "stream", "gq", "cf", "tk", "ml", "ga", "beauty", "hair", "skin",
    "quest", "cyou", "icu", "monster", "rest"
}

# Known URL shortener services concealing true destinations
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "rebrand.ly",
    "cutt.ly", "clck.ru", "v.gd", "shorturl.at"
}

# High-profile targeted brands frequently spoofed
COMMON_TARGET_BRANDS = [
    "paypal", "apple", "microsoft", "google", "netflix", "amazon", "chase",
    "bankofamerica", "wellsfargo", "facebook", "instagram", "whatsapp", "telegram",
    "binance", "coinbase", "metamask", "dhl", "fedex", "usps", "irs"
]

# High-risk security and credential lure keywords
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification", "update",
    "security", "account", "banking", "secure", "authenticate", "confirm",
    "wallet", "password", "credential", "suspend", "recovery", "mfa", "2fa"
}

STANDARD_PORTS = {80, 443, None}


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string to detect randomized/DGA domains."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def check_typosquatting(domain: str, brand: str) -> bool:
    """Detects typosquatting heuristics (e.g. paypa1, micros0ft, goog1e, repeated characters)."""
    clean_domain = domain.lower()

    # 1. Check with '1' replaced by 'l' (e.g. paypa1 -> paypal)
    v1 = clean_domain.replace("1", "l").replace("0", "o").replace("3", "e").replace("5", "s").replace("@", "a").replace("vv", "w")
    if brand in v1 and brand not in clean_domain:
        return True

    # 2. Check with '1' replaced by 'i' (e.g. m1crosoft -> microsoft)
    v2 = clean_domain.replace("1", "i").replace("0", "o").replace("3", "e").replace("5", "s").replace("@", "a").replace("vv", "w")
    if brand in v2 and brand not in clean_domain:
        return True

    # 3. Hyphenated deceptive variations (e.g., paypal-update, chase-security)
    if f"{brand}-" in clean_domain or f"-{brand}" in clean_domain:
        return True

    return False


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Performs comprehensive static forensic inspection of a target URL.
    Returns structured deterministic findings without external network calls.
    """
    cleaned = (url or "").strip()
    if not re.match(r"^https?://", cleaned, re.IGNORECASE):
        cleaned = f"https://{cleaned}"

    parsed = urlparse(cleaned)
    raw_netloc = parsed.netloc.lower()

    # Extract port if present
    port = parsed.port
    has_unusual_port = port not in STANDARD_PORTS

    # Strip port from domain
    domain = raw_netloc.split(":")[0] if ":" in raw_netloc else raw_netloc
    # Strip userinfo (@) from domain
    has_userinfo = "@" in domain
    if has_userinfo:
        domain = domain.split("@")[-1]

    domain_parts = domain.split(".")
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""

    signals: List[Dict[str, Any]] = []
    flags: List[str] = []

    # 1. IP Address Host Check
    is_ip_host = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))
    if is_ip_host:
        sig = {
            "signal": "Direct IP Hostname",
            "severity": "high",
            "explanation": "Target uses a raw IP address instead of a legitimate registered domain name.",
            "source": "local"
        }
        signals.append(sig)
        flags.append(sig["explanation"])

    # 2. URL Shortener Check
    is_shortened = domain in SHORTENER_DOMAINS
    if is_shortened:
        sig = {
            "signal": "URL Shortener Masking",
            "severity": "medium",
            "explanation": "URL shortener detected, potentially concealing the true destination destination.",
            "source": "local"
        }
        signals.append(sig)
        flags.append(sig["explanation"])

    # 3. Excessive Subdomains Check
    subdomain_count = max(0, len(domain_parts) - 2)
    has_excessive_subdomains = subdomain_count >= 3
    if has_excessive_subdomains:
        sig = {
            "signal": "Excessive Subdomain Nesting",
            "severity": "medium",
            "explanation": f"Domain contains {subdomain_count} nested subdomains, a technique often used to disguise malicious endpoints.",
            "source": "local"
        }
        signals.append(sig)
        flags.append(sig["explanation"])

    # 4. Suspicious TLD Check
    has_suspicious_tld = tld in SUSPICIOUS_TLDS
    if has_suspicious_tld:
        sig = {
            "signal": "High-Risk Top-Level Domain",
            "severity": "medium",
            "explanation": f"Domain utilizes .{tld}, a top-level domain frequently abused in mass phishing infrastructure.",
            "source": "local"
        }
        signals.append(sig)
        flags.append(sig["explanation"])

    # 5. Punycode / IDN Homograph Check
    has_punycode = "xn--" in domain
    if has_punycode:
        sig = {
            "signal": "Punycode (IDN Homograph) Encoding",
            "severity": "high",
            "explanation": "Punycode character encoding detected, indicating potential visual character spoofing.",
            "source": "local"
        }
        signals.append(sig)
        flags.append(sig["explanation"])

    # 6. Brand Impersonation & Typosquatting Check
    possible_brand_impersonation = None
    has_typosquatting = False

    for brand in COMMON_TARGET_BRANDS:
        # Check if brand is in domain but not legitimate owner
        is_legitimate_owner = (
            domain == f"{brand}.com" or
            domain.endswith(f".{brand}.com") or
            domain == f"{brand}.org" or
            domain.endswith(f".{brand}.org")
        )
        if not is_legitimate_owner:
            if brand in domain:
                possible_brand_impersonation = brand
                sig = {
                    "signal": "Potential Brand Impersonation",
                    "severity": "high",
                    "explanation": f"Suspected unauthorized use of brand identity '{brand}' in foreign domain '{domain}'.",
                    "source": "local"
                }
                signals.append(sig)
                flags.append(sig["explanation"])
                break
            elif check_typosquatting(domain, brand):
                possible_brand_impersonation = brand
                has_typosquatting = True
                sig = {
                    "signal": "Potential Typosquatting",
                    "severity": "high",
                    "explanation": f"Domain mimics brand '{brand}' using character substitutions or lookalike patterns.",
                    "source": "local"
                }
                signals.append(sig)
                flags.append(sig["explanation"])
                break

    # 7. Entropy Check
    domain_body = ".".join(domain_parts[:-1]) if len(domain_parts) > 1 else domain
    entropy = calculate_entropy(domain_body)
    has_high_entropy = entropy > 3.8 and len(domain_body) > 10
    if has_high_entropy:
        sig = {
            "signal": "High Domain Entropy (Randomness)",
            "severity": "medium",
            "explanation": f"Elevated randomness in domain ({entropy}), consistent with automated Domain Generation Algorithms (DGA).",
            "source": "local"
        }
        signals.append(sig)
        flags.append(sig["explanation"])

    # 8. Suspicious Keywords in Path or Subdomains
    full_path_query = f"{parsed.path} {parsed.query}".lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_path_query or kw in domain]
    has_suspicious_keywords = len(matched_keywords) > 0
    if has_suspicious_keywords:
        sig = {
            "signal": "Security & Credential Keywords in URL",
            "severity": "medium",
            "explanation": f"URL contains credential harvesting lure keywords: {', '.join(matched_keywords[:4])}.",
            "source": "local"
        }
        signals.append(sig)
        flags.append(sig["explanation"])

    # 9. Unusual Port
    if has_unusual_port and port:
        sig = {
            "signal": "Unusual Non-Standard Port",
            "severity": "medium",
            "explanation": f"Connection uses non-standard web port :{port}, bypassing standard network inspection.",
            "source": "local"
        }
        signals.append(sig)
        flags.append(sig["explanation"])

    # 10. Obfuscation & Credential Embedding
    has_obfuscation = has_userinfo or ("%" in parsed.netloc)
    if has_obfuscation:
        sig = {
            "signal": "URL Credential Obfuscation",
            "severity": "high",
            "explanation": "Embedded user credentials ('@' symbol) or hex encoding detected in network host.",
            "source": "local"
        }
        signals.append(sig)
        flags.append(sig["explanation"])

    # 11. Insecure Protocol
    if parsed.scheme.lower() == "http":
        sig = {
            "signal": "Unencrypted HTTP Protocol",
            "severity": "low",
            "explanation": "Target uses unencrypted HTTP protocol without TLS certificate validation.",
            "source": "local"
        }
        signals.append(sig)
        flags.append(sig["explanation"])

    url_length = len(cleaned)

    return {
        "original_url": url,
        "normalized_url": cleaned,
        "scheme": parsed.scheme,
        "domain": domain,
        "hostname": raw_netloc,
        "tld": tld,
        "url_length": url_length,
        "subdomain_count": subdomain_count,
        "is_ip_host": is_ip_host,
        "is_shortened": is_shortened,
        "has_punycode": has_punycode,
        "has_suspicious_tld": has_suspicious_tld,
        "has_excessive_subdomains": has_excessive_subdomains,
        "has_suspicious_keywords": has_suspicious_keywords,
        "has_unusual_port": has_unusual_port,
        "port": port,
        "entropy": entropy,
        "has_high_entropy": has_high_entropy,
        "possible_brand_impersonation": possible_brand_impersonation,
        "has_typosquatting": has_typosquatting,
        "has_obfuscation": has_obfuscation,
        "signals": signals,
        # Backwards compatibility with existing callers
        "flags": flags,
        "is_ip_address": is_ip_host,
        "detected_spoofed_brand": possible_brand_impersonation,
    }


def analyze_url_heuristics(url: str) -> Dict[str, Any]:
    """Backwards-compatible wrapper calling analyze_url."""
    return analyze_url(url)
