"""
TRUSTSHIELD - Forensic Evidence & Red-Flag Intelligence Engine
Extracts, correlates, deduplicates, and calibrates structured cybersecurity evidence.

ARCHITECTURE POSITION:
USER INPUT
  ↓
LOCAL FORENSICS
  ↓
GEMINI REASONING
  ↓
EVIDENCE CORRELATION (This Engine)
  ↓
RISK ENGINE
  ↓
FINAL VERDICT
"""

from typing import Dict, Any, List, Optional, Tuple, Set
import re

# Standard severity ranking
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Evidence Educational Mapping ("Why this matters" in plain, beginner-friendly English)
WHY_IT_MATTERS_MAP = {
    "credential_request": "Legitimate organizations rarely request passwords or sensitive credentials via unverified links or messages. Surrendering credentials can lead to immediate account takeover.",
    "otp_mfa_request": "One-Time Passcodes (OTPs) and 2FA tokens are your final line of defense. Attackers intercept them in real-time to bypass two-factor authentication and access protected accounts.",
    "malware_attachment": "Disguised executable or compressed attachments (.exe, .apk, .zip, macros) can install infostealers, keyloggers, or ransomware silently onto your device.",
    "financial_fraud": "Requests for untraceable payment methods (wire transfers, crypto, gift cards) are classic signs of fraud. Once funds are transferred, they are virtually impossible to reverse.",
    "account_verification_lure": "Threats of immediate account suspension or legal action are coercive psychological tactics designed to induce panic so victims bypass normal security precautions.",
    "brand_impersonation": "Adversaries mimic trusted institutions (banks, tech companies, delivery couriers) to exploit user trust and harvest logins on lookalike sites.",
    "lookalike_domain": "A domain that visually resembles a legitimate brand but is registered to an unknown party is the foundation of phishing infrastructure.",
    "direct_ip_host": "Direct IP addresses bypass standard domain reputation systems and SSL certificates, a common tactic for ephemeral attack servers.",
    "url_shortener": "URL shorteners conceal the true web destination, preventing users and security scanners from previewing the real landing page.",
    "punycode_homograph": "Punycode uses foreign alphabet characters that look identical to Latin letters to deceive the human eye into believing a fake domain is real.",
    "urgency_pressure": "Artificial deadlines ('within 24 hours', 'immediate action required') force users to rush and bypass rational verification.",
    "suspicious_tld": "Certain top-level domains (.xyz, .top, .buzz) have lower registration costs and lax enforcement, making them disproportionately favored by phishing operations.",
    "composite_lure": "When multiple deceptive techniques converge (such as urgency, brand impersonation, and credential requests), the probability of an organized social engineering attack rises substantially."
}


def _determine_why_it_matters(signal_title: str, explanation: str) -> str:
    """Assigns an intuitive, beginner-friendly 'Why this matters' statement."""
    combined = f"{signal_title} {explanation}".lower()
    if "otp" in combined or "2fa" in combined or "mfa" in combined or "verification code" in combined:
        return WHY_IT_MATTERS_MAP["otp_mfa_request"]
    if "password" in combined or "credential" in combined or "login" in combined or "sign-in" in combined:
        return WHY_IT_MATTERS_MAP["credential_request"]
    if ".exe" in combined or ".apk" in combined or "attachment" in combined or "malware" in combined or "payload" in combined:
        return WHY_IT_MATTERS_MAP["malware_attachment"]
    if "wire" in combined or "payment" in combined or "invoice" in combined or "gift card" in combined:
        return WHY_IT_MATTERS_MAP["financial_fraud"]
    if "suspend" in combined or "deactivat" in combined or "locked" in combined:
        return WHY_IT_MATTERS_MAP["account_verification_lure"]
    if "homograph" in combined or "punycode" in combined:
        return WHY_IT_MATTERS_MAP["punycode_homograph"]
    if "typosquat" in combined or "lookalike" in combined:
        return WHY_IT_MATTERS_MAP["lookalike_domain"]
    if "impersonat" in combined or "spoofed brand" in combined:
        return WHY_IT_MATTERS_MAP["brand_impersonation"]
    if "direct ip" in combined:
        return WHY_IT_MATTERS_MAP["direct_ip_host"]
    if "shortener" in combined or "shortened" in combined:
        return WHY_IT_MATTERS_MAP["url_shortener"]
    if "urgent" in combined or "urgency" in combined or "pressure" in combined:
        return WHY_IT_MATTERS_MAP["urgency_pressure"]
    if "tld" in combined or ".xyz" in combined:
        return WHY_IT_MATTERS_MAP["suspicious_tld"]
    if "composite" in combined or "social-engineering" in combined:
        return WHY_IT_MATTERS_MAP["composite_lure"]

    return "This indicator represents a deceptive behavioral or technical anomaly frequently correlated with cybersecurity threats."


def extract_local_message_evidence(text: str) -> List[Dict[str, Any]]:
    """
    Extracts structured forensic red flags from raw communication text (email/SMS/message).
    Carefully tuned to avoid false positives on legitimate, benign text.
    """
    if not text or not text.strip():
        return []

    content = text.strip()
    lower = content.lower()
    findings: List[Dict[str, Any]] = []

    # 1. Credential / Password Request (Critical)
    cred_patterns = [
        r"(enter|provide|confirm|verify|send)\s+(your\s+)?(password|login|credentials|passcode)",
        r"(reset|change)\s+your\s+password\s+(here|now|immediately)",
        r"sign[\s-]?in\s+(to\s+verify|to\s+prevent|immediately)"
    ]
    if any(re.search(pat, lower) for pat in cred_patterns):
        findings.append({
            "signal": "Potential Credential Harvesting Request",
            "severity": "critical",
            "explanation": "Suspicious solicitation demanding user login credentials or password entry.",
            "source": "local",
            "concept": "credential_request"
        })

    # 2. OTP / MFA Token Intercept Request (Critical)
    otp_patterns = [
        r"(otp|mfa|2fa|verification\s+code|security\s+code|one[\s-]time\s+code)",
        r"(send|reply\s+with|provide)\s+(the|your)?\s*(\d{4,8}|code|pin)"
    ]
    if re.search(r"(otp|2fa|mfa|one[\s-]time\s+password|verification\s+code|security\s+code)", lower) and any(
        kw in lower for kw in ["reply", "send", "provide", "share", "enter", "text", "received"]
    ):
        findings.append({
            "signal": "Possible OTP / MFA Intercept Lure",
            "severity": "critical",
            "explanation": "Communication requests disclosure of a one-time verification passcode (OTP/2FA token).",
            "source": "local",
            "concept": "otp_request"
        })

    # 3. Malicious Attachment / Executable Reference (Critical)
    malware_exts = [".exe", ".apk", ".scr", ".vbs", ".bat", ".iso", ".zip"]
    if any(ext in lower for ext in malware_exts) or (
        "attached" in lower and any(w in lower for w in ["invoice", "payment", "statement", "update", "document"]) and
        any(w in lower for w in ["open", "run", "download", "install", "enable macro"])
    ):
        findings.append({
            "signal": "Suspicious Executable / Attachment Delivery",
            "severity": "critical",
            "explanation": "Reference to an attached file or executable payload requiring execution or download.",
            "source": "local",
            "concept": "malware_delivery"
        })

    # 4. Financial / Payment Fraud / Gift Card Diversion (Critical)
    if any(kw in lower for kw in ["gift card", "steam card", "apple card", "vanilla card", "itunes card"]):
        findings.append({
            "signal": "Gift Card Payment Demand",
            "severity": "critical",
            "explanation": "Solicitation for payment via retail gift cards, a hallmark indicator of non-recoverable extortion.",
            "source": "local",
            "concept": "gift_card"
        })
    elif any(kw in lower for kw in ["wire transfer", "bank transfer", "overdue invoice", "unpaid invoice", "bitcoin payment", "crypto wallet"]) and (
        any(kw in lower for kw in ["immediately", "urgent", "due today", "pay now", "remit"])
    ):
        findings.append({
            "signal": "Unverified Urgent Payment Demand",
            "severity": "critical",
            "explanation": "High-urgency demand for financial transfer, wire payment, or cryptocurrency remittance.",
            "source": "local",
            "concept": "financial_fraud"
        })

    # 5. Account Suspension / Deactivation Ultimatum (High)
    if any(kw in lower for kw in ["suspend", "deactivat", "terminated", "locked", "account closed", "legal action"]) and (
        any(kw in lower for kw in ["verify", "hours", "action required", "immediately", "within", "click", "now"])
    ):
        findings.append({
            "signal": "Coercive Account Suspension Threat",
            "severity": "high",
            "explanation": "Threatens punitive account termination or service lockout to compel unverified action.",
            "source": "local",
            "concept": "suspension_threat"
        })

    # 6. Artificial Urgency / Fear Pressure (Medium)
    urgency_terms = ["urgent", "immediately", "within 24 hours", "hours remaining", "final notice", "act now", "limited time"]
    if any(term in lower for term in urgency_terms):
        findings.append({
            "signal": "Artificial Urgency Trigger",
            "severity": "medium",
            "explanation": "Psychological pressure tactic employing artificial time constraints to rush decision-making.",
            "source": "local",
            "concept": "urgency"
        })

    # 7. Brand / Authority Claim (Medium / High)
    brands_found = [b for b in ["paypal", "apple", "microsoft", "google", "netflix", "chase", "bank of america", "irs", "usps", "dhl"] if b in lower]
    if brands_found:
        findings.append({
            "signal": f"Claimed Institutional Identity ({brands_found[0].title()})",
            "severity": "medium",
            "explanation": f"Message references or claims identity of recognized institution '{brands_found[0].title()}'.",
            "source": "local",
            "concept": "brand_reference"
        })

    # 8. Embedded Suspicious Link (Medium)
    if ("http://" in lower or "https://" in lower or "www." in lower) and any(
        kw in lower for kw in ["click", "tap", "link", "here", "confirm", "login", "update"]
    ):
        findings.append({
            "signal": "Embedded Action Link Under Deceptive Context",
            "severity": "medium",
            "explanation": "Message urges recipient to click an embedded link under an urgent or unverified premise.",
            "source": "local",
            "concept": "suspicious_link"
        })

    return findings


def correlate_and_deduplicate_evidence(
    local_signals: List[Dict[str, Any]],
    gemini_flags: List[str],
    input_type: str = "url"
) -> Tuple[List[Dict[str, Any]], str]:
    """
    Correlates deterministic local forensic signals with Gemini cognitive findings.
    
    1. Deduplicates overlapping observations.
    2. Elevates corroborated dual-source indicators to source='combined' with higher confidence.
    3. Synthesizes composite attack patterns (e.g. Urgency + Credentials + Lookalike Domain).
    4. Computes calibrated confidence for each item.
    5. Produces a concise, human-readable forensic evidence summary.
    """
    merged_items: List[Dict[str, Any]] = []
    seen_concepts: Set[str] = set()
    matched_ai_flags: Set[str] = set()

    # Normalize gemini flags to text
    cleaned_gemini = [str(f).strip() for f in (gemini_flags or []) if str(f).strip()]

    # Index local signals by concept
    for local_sig in local_signals:
        sig_title = local_sig.get("signal", "Suspicious Indicator")
        sig_sev = local_sig.get("severity", "medium").lower()
        sig_exp = local_sig.get("explanation", "")
        concept = local_sig.get("concept") or sig_title.lower()

        # Check if Gemini also corroborated this concept
        corroborated_by_ai = False
        matching_ai_flag = ""
        for g_flag in cleaned_gemini:
            # Check keyword overlap
            g_lower = g_flag.lower()
            if any(term in g_lower for term in [concept, sig_title.lower()[:8]]) or (
                "credential" in concept and any(k in g_lower for k in ["password", "credential", "login", "sign-in"])
            ) or (
                "otp" in concept and any(k in g_lower for k in ["otp", "2fa", "mfa", "verification code", "code"])
            ) or (
                ("brand" in concept or "impersonat" in concept) and any(k in g_lower for k in ["impersonat", "spoof", "brand", "lookalike"])
            ) or (
                "urgency" in concept and any(k in g_lower for k in ["urgent", "pressure", "rush", "immediate"])
            ) or (
                "tld" in concept and any(k in g_lower for k in ["tld", "domain", ".xyz", ".top"])
            ) or (
                "malware" in concept and any(k in g_lower for k in ["malware", "executable", "attachment", "payload", ".exe"])
            ) or (
                "financial" in concept and any(k in g_lower for k in ["payment", "wire", "invoice", "transfer"])
            ):
                corroborated_by_ai = True
                matching_ai_flag = g_flag
                matched_ai_flags.add(g_flag)
                break

        if corroborated_by_ai:
            source = "combined"
            confidence = 94  # Dual-source corroboration yields elevated certainty
            explanation = f"{sig_exp} Both local static analysis and AI reasoning corroborate this pattern."
        else:
            source = "local"
            confidence = 88  # Deterministic local technical inspection
            explanation = sig_exp

        seen_concepts.add(concept)
        merged_items.append({
            "signal": sig_title,
            "severity": sig_sev,
            "confidence": confidence,
            "explanation": explanation,
            "why_it_matters": _determine_why_it_matters(sig_title, explanation),
            "source": source,
            "concept": concept
        })

    # Ingest remaining unique Gemini findings
    for g_flag in cleaned_gemini:
        if g_flag in matched_ai_flags:
            continue

        g_lower = g_flag.lower()

        # Check semantic overlap with already merged items
        already_represented = False
        for m in merged_items:
            m_text = f"{m.get('signal', '')} {m.get('explanation', '')} {m.get('concept', '')}".lower()
            key_terms = ["credential", "password", "otp", "urgency", "urgent", "brand", "impersonat", "paypal", "apple", "microsoft", "google", "suspension", "suspend", "attachment", "payment", "wire"]
            if any(term in g_lower and term in m_text for term in key_terms):
                already_represented = True
                break

        if already_represented:
            continue

        # Determine severity and concept from AI description
        if any(w in g_lower for w in ["otp", "password", "credential", "malware", "executable", "payload", "wire transfer", "gift card"]):
            sev = "critical"
            confidence = 88
        elif any(w in g_lower for w in ["impersonat", "spoof", "punycode", "homograph", "suspend", "deactivat", "typosquat"]):
            sev = "high"
            confidence = 84
        elif any(w in g_lower for w in ["urgent", "urgency", "shortener", "entropy", "subdomain"]):
            sev = "medium"
            confidence = 78
        else:
            sev = "low"
            confidence = 72

        clean_title = re.sub(r"^\[.*?\]\s*", "", g_flag)
        if len(clean_title) > 60:
            short_title = clean_title[:57] + "..."
        else:
            short_title = clean_title

        merged_items.append({
            "signal": f"Potential {short_title.capitalize()}" if not short_title.lower().startswith("potential") else short_title,
            "severity": sev,
            "confidence": confidence,
            "explanation": g_flag,
            "why_it_matters": _determine_why_it_matters(short_title, g_flag),
            "source": "gemini",
            "concept": "ai_flag"
        })

    # 3. Composite Signal Correlation (Emergent threat synthesis)
    # Check if multiple related signals create a compound high-severity finding
    has_urgency = any("urgency" in item.get("concept", "") or "urgent" in item.get("signal", "").lower() for item in merged_items)
    has_credentials = any("credential" in item.get("concept", "") or "password" in item.get("signal", "").lower() for item in merged_items)
    has_brand = any("brand" in item.get("concept", "") or "impersonat" in item.get("signal", "").lower() or "lookalike" in item.get("signal", "").lower() for item in merged_items)
    has_otp = any("otp" in item.get("concept", "") for item in merged_items)
    has_malware = any("malware" in item.get("concept", "") or "executable" in item.get("signal", "").lower() for item in merged_items)
    has_payment = any("payment" in item.get("concept", "") or "financial" in item.get("signal", "").lower() for item in merged_items)

    composite_signals: List[Dict[str, Any]] = []

    if has_urgency and has_credentials and has_brand:
        composite_signals.append({
            "signal": "Social-Engineering Credential Lure (Correlated Composite)",
            "severity": "critical",
            "confidence": 97,
            "explanation": "Correlated pattern: Confluence of artificial urgency pressure, authority brand impersonation, and explicit login credential requests.",
            "why_it_matters": WHY_IT_MATTERS_MAP["composite_lure"],
            "source": "combined",
            "concept": "composite_credential_lure"
        })

    if has_otp and (has_urgency or has_brand):
        composite_signals.append({
            "signal": "High-Pressure MFA/OTP Intercept Campaign (Correlated Composite)",
            "severity": "critical",
            "confidence": 98,
            "explanation": "Correlated pattern: Combines institutional authority impersonation with aggressive pursuit of two-factor authentication bypass tokens.",
            "why_it_matters": WHY_IT_MATTERS_MAP["otp_mfa_request"],
            "source": "combined",
            "concept": "composite_mfa_intercept"
        })

    if has_malware and (has_payment or has_urgency):
        composite_signals.append({
            "signal": "Malicious Payload Delivery Vector (Correlated Composite)",
            "severity": "critical",
            "confidence": 98,
            "explanation": "Correlated pattern: Combines urgent financial/invoice pretext with prompt to open or download an executable payload.",
            "why_it_matters": WHY_IT_MATTERS_MAP["malware_attachment"],
            "source": "combined",
            "concept": "composite_malware_vector"
        })

    # Prepend composite signals if any emerged
    final_evidence = composite_signals + merged_items

    # Sort evidence: Critical first, then High, Medium, Low
    final_evidence.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 0), reverse=True)

    # 4. Synthesize Forensic Evidence Summary
    if not final_evidence:
        summary = "🟢 No significant malicious indicators detected. Note: Absence of known indicators reduces probability of threat but does not guarantee absolute safety."
    else:
        crit_count = sum(1 for e in final_evidence if e["severity"] == "critical")
        high_count = sum(1 for e in final_evidence if e["severity"] == "high")
        med_count = sum(1 for e in final_evidence if e["severity"] == "medium")
        low_count = sum(1 for e in final_evidence if e["severity"] == "low")
        total_count = len(final_evidence)

        breakdown = []
        if crit_count:
            breakdown.append(f"{crit_count} Critical")
        if high_count:
            breakdown.append(f"{high_count} High")
        if med_count:
            breakdown.append(f"{med_count} Medium")
        if low_count:
            breakdown.append(f"{low_count} Low")

        summary = f"TrustShield identified {total_count} independent warning signal{'s' if total_count != 1 else ''} ({', '.join(breakdown)})."

    return final_evidence, summary
