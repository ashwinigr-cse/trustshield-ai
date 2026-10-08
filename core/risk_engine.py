"""
TRUSTSHIELD - Independent Risk Intelligence Engine
Combines deterministic local forensics, Google Gemini AI reasoning,
evidence severity weighting, and attack-stage context into a calibrated,
explainable digital safety assessment.

FUSION ARCHITECTURE:
USER INPUT
  ↓
LOCAL FORENSICS
  ↓
GEMINI REASONING
  ↓
RISK ENGINE (Deterministic Fusion & Calibration)
  ↓
FINAL TRUSTSHIELD VERDICT
"""

from typing import Dict, Any, List, Optional, Tuple
import re

# Standardized Attack Lifecycle Stage Impact Weights (0-100)
STAGE_IMPACT_WEIGHTS: Dict[str, float] = {
    "reconnaissance": 18.0,
    "initial access": 55.0,
    "credential/account capture": 88.0,
    "credential access": 88.0,
    "execution/exploitation": 92.0,
    "execution": 92.0,
    "persistence": 80.0,
    "data theft": 96.0,
    "account takeover": 98.0,
}

# Weighted Threat Factors Catalog
# Each factor has an identifier, title, weight (impact score), and keyword/pattern detection triggers
RISK_FACTOR_DEFINITIONS = [
    # Critical Impact Signals (Weight: 30 - 35)
    {
        "id": "credential_request",
        "title": "Login Credential / Password Request",
        "weight": 35.0,
        "category": "Critical",
        "keywords": ["password", "credential", "login", "sign in", "passcode", "secret key", "seed phrase", "log in"],
    },
    {
        "id": "otp_mfa_request",
        "title": "OTP / MFA Token Intercept Request",
        "weight": 35.0,
        "category": "Critical",
        "keywords": ["otp", "2fa", "mfa", "verification code", "one-time", "security code", "authenticator", "sms code"],
    },
    {
        "id": "malware_indicators",
        "title": "Malicious Attachment / Executable Delivery",
        "weight": 32.0,
        "category": "Critical",
        "keywords": [".exe", ".apk", ".scr", ".vbs", ".bat", ".iso", ".zip", "macro", "payload", "install this update", "download attached"],
    },
    {
        "id": "financial_fraud",
        "title": "Financial / Wire / Payment Diversion Request",
        "weight": 30.0,
        "category": "Critical",
        "keywords": ["wire transfer", "bank transfer", "invoice", "bitcoin", "crypto", "gift card", "overdue payment", "refund pending", "direct deposit"],
    },
    {
        "id": "account_verification_lure",
        "title": "Account Suspension / Deactivation Threat",
        "weight": 25.0,
        "category": "High",
        "keywords": ["suspended", "deactivated", "deactivation", "deactivat", "terminated", "locked", "unauthorized access", "confirm identity", "verify your account", "action required", "ultimatum"],
    },

    # High-Severity Technical Signals (Weight: 20 - 25)
    {
        "id": "brand_impersonation",
        "title": "Brand / Authority Impersonation",
        "weight": 25.0,
        "category": "High",
        "keywords": ["impersonat", "spoofed brand", "lookalike", "paypal", "apple", "microsoft", "google", "netflix", "chase", "bank of america", "irs", "usps", "dhl", "fedex"],
    },
    {
        "id": "punycode_homograph",
        "title": "Punycode (IDN Homograph) Domain Spoofing",
        "weight": 25.0,
        "category": "High",
        "keywords": ["punycode", "xn--", "homograph"],
    },
    {
        "id": "typosquatting",
        "title": "Typosquatting / Deceptive Domain Syntax",
        "weight": 22.0,
        "category": "High",
        "keywords": ["typosquat", "misspelled", "lookalike domain", "subdomain nesting"],
    },
    {
        "id": "direct_ip_host",
        "title": "Direct IP Address Used as Hostname",
        "weight": 20.0,
        "category": "High",
        "keywords": ["ip address used as hostname", "direct ip"],
    },

    # Medium-Severity Technical & Behavioral Signals (Weight: 10 - 18)
    {
        "id": "suspicious_tld",
        "title": "High-Risk Top-Level Domain (TLD)",
        "weight": 18.0,
        "category": "Medium",
        "keywords": ["high-risk top-level domain", "suspicious tld", ".xyz", ".top", ".work", ".buzz", ".country", ".stream"],
    },
    {
        "id": "url_shortener",
        "title": "URL Shortener Concealing Final Destination",
        "weight": 15.0,
        "category": "Medium",
        "keywords": ["url shortener", "bit.ly", "tinyurl", "shortened link", "concealing destination"],
    },
    {
        "id": "artificial_urgency",
        "title": "Artificial Urgency / Pressure Tactics",
        "weight": 15.0,
        "category": "Medium",
        "keywords": ["urgent", "immediately", "within 24 hours", "hours remaining", "final notice", "act now", "limited time"],
    },
    {
        "id": "suspicious_sender",
        "title": "Suspicious Sender Behavior / Header Mismatch",
        "weight": 15.0,
        "category": "Medium",
        "keywords": ["sender mismatch", "unverified sender", "free webmail", "spoofed sender", "fake domain"],
    },
    {
        "id": "high_entropy_domain",
        "title": "High Randomness / Entropy in Domain (DGA)",
        "weight": 12.0,
        "category": "Medium",
        "keywords": ["entropy", "randomized", "domain generation algorithm"],
    },
    {
        "id": "social_engineering",
        "title": "Social Engineering / Manipulation Lure",
        "weight": 12.0,
        "category": "Medium",
        "keywords": ["social engineering", "manipulation", "fear appeal", "lottery", "prize", "winner"],
    },
]


def determine_severity_tier(risk_score: float) -> str:
    """
    Standardized TrustShield Severity Tiers:
      0–19   = Safe
      20–39  = Low
      40–59  = Medium
      60–79  = High
      80–100 = Critical
    """
    score = max(0.0, min(100.0, float(risk_score)))
    if score < 20.0:
        return "Safe"
    elif score < 40.0:
        return "Low"
    elif score < 60.0:
        return "Medium"
    elif score < 80.0:
        return "High"
    return "Critical"


def extract_matched_risk_factors(
    analysis_result: Dict[str, Any],
    forensic_signals: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Scans both local forensic signals and AI analysis text to extract
    identified risk factors with corresponding severity weights.
    """
    matched: List[Dict[str, Any]] = []
    seen_ids = set()

    # Aggregate all textual evidence into a single searchable corpus
    text_corpus_parts = []

    # 1. Evidence flags from AI or local inspection
    flags = analysis_result.get("evidence_flags") or analysis_result.get("red_flags") or []
    if isinstance(flags, list):
        text_corpus_parts.extend([str(f).lower() for f in flags])

    # 2. Local heuristic signals if provided
    if forensic_signals:
        if isinstance(forensic_signals.get("flags"), list):
            text_corpus_parts.extend([str(f).lower() for f in forensic_signals["flags"]])
        if forensic_signals.get("is_ip_address"):
            text_corpus_parts.append("ip address used as hostname")
        if forensic_signals.get("is_shortened"):
            text_corpus_parts.append("url shortener concealing destination")
        if forensic_signals.get("detected_spoofed_brand"):
            text_corpus_parts.append(f"spoofed brand {forensic_signals['detected_spoofed_brand']}")
        if forensic_signals.get("entropy", 0) > 3.8:
            text_corpus_parts.append("high randomness entropy")

    # 3. AI textual context fields
    for field in ["threat_type", "threat_classification", "predicted_next_move", "attacker_goal", "input_preview"]:
        val = analysis_result.get(field)
        if val:
            text_corpus_parts.append(str(val).lower())

    corpus = " ".join(text_corpus_parts)

    # Match against risk factor catalog
    for factor in RISK_FACTOR_DEFINITIONS:
        factor_id = factor["id"]
        if factor_id in seen_ids:
            continue

        matched_trigger = False
        for kw in factor["keywords"]:
            if kw.lower() in corpus:
                matched_trigger = True
                break

        if matched_trigger:
            seen_ids.add(factor_id)
            matched.append({
                "id": factor_id,
                "title": factor["title"],
                "weight": factor["weight"],
                "category": factor["category"],
            })

    return matched


def get_attack_stage_weight(stage_str: Optional[str]) -> float:
    """Returns baseline potential risk contribution for the identified attack stage."""
    if not stage_str:
        return 50.0

    stage_clean = str(stage_str).strip().lower()
    for key, weight in STAGE_IMPACT_WEIGHTS.items():
        if key in stage_clean:
            return weight
    return 50.0


def calculate_risk(
    analysis_result: Dict[str, Any],
    forensic_signals: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Independent Risk Intelligence Engine.
    
    Combines:
    1. Local deterministic forensic signals
    2. Gemini AI cognitive reasoning
    3. Evidence severity weighting
    4. Attack-stage information
    5. Disagreement & contradiction handling
    
    Formula & Weighting Details:
    - Normal Fusion:
        Final Risk = (AI Assessment * 0.40) + (Forensic Evidence * 0.40) + (Attack Stage Context * 0.20)
    - Fallback / Offline Fusion:
        Final Risk = (Forensic Evidence * 0.70) + (Attack Stage Context * 0.30)
    - Contradiction Handling:
        If AI says Low (<40) but multiple critical deterministic factors exist (Forensic >= 55),
        TrustShield flags the contradiction and overrides the score upward (min 70).
        If AI says High (>=75) with zero forensic evidence (<20), TrustShield penalizes confidence.
    """
    if not analysis_result:
        analysis_result = {}

    # Extract matched risk factors
    matched_factors = extract_matched_risk_factors(analysis_result, forensic_signals)

    # 1. Deterministic Forensic Contribution (0-100)
    # Sum weights of detected indicators, capped at 100
    raw_forensic_sum = sum(f["weight"] for f in matched_factors)
    forensic_score = min(100.0, raw_forensic_sum)

    # 2. Attack Stage Contribution (0-100)
    attack_stage_val = analysis_result.get("attack_stage", "Initial Access")
    stage_score = get_attack_stage_weight(attack_stage_val)

    # 3. AI Assessment Score (0-100)
    raw_ai_score = analysis_result.get("risk_score")
    is_fallback = analysis_result.get("is_fallback", False)

    try:
        ai_score = float(raw_ai_score) if raw_ai_score is not None else 50.0
    except (ValueError, TypeError):
        ai_score = 50.0
    ai_score = max(0.0, min(100.0, ai_score))

    # 4. Check for Contradictions
    analysis_disagreement = False
    disagreement_reason = ""

    critical_factors_present = any(f["category"] == "Critical" for f in matched_factors)
    has_high_factors = any(f["category"] in ("Critical", "High") for f in matched_factors)

    # Scenario A: AI is overly trusting (AI < 40) but strong forensic signals exist (Forensics >= 55)
    if not is_fallback and ai_score < 40.0 and (forensic_score >= 55.0 or critical_factors_present):
        analysis_disagreement = True
        disagreement_reason = (
            "AI cognitive model rated threat as Low, but local deterministic engine detected critical indicators "
            f"({', '.join([f['title'] for f in matched_factors if f['category'] == 'Critical'])}). "
            "TrustShield overridden upward to protect user safety."
        )
        # Safety override: At least 70 or forensic score
        fused_score = max(70.0, (forensic_score * 0.70) + (stage_score * 0.30))

    # Scenario B: AI hallucinated High (AI >= 75) but zero evidence found (Forensics < 20)
    elif not is_fallback and ai_score >= 75.0 and forensic_score < 20.0 and not has_high_factors:
        analysis_disagreement = True
        disagreement_reason = (
            "AI cognitive model flagged high risk, but deterministic forensic signals found no technical red flags. "
            "Confidence calibrated downward."
        )
        # Moderated blended score
        fused_score = (ai_score * 0.45) + (forensic_score * 0.30) + (stage_score * 0.25)

    # Scenario C: Standard Multi-Source Fusion
    else:
        # High-severity evidence contribution (Critical & High categories)
        critical_count = sum(1 for f in matched_factors if f["category"] == "Critical")
        high_count = sum(1 for f in matched_factors if f["category"] == "High")
        high_severity_contribution = min(20.0, (critical_count * 8.0) + (high_count * 3.0))

        if is_fallback:
            # Deterministic local weighting when AI is offline
            fused_score = (forensic_score * 0.65) + (stage_score * 0.20) + (high_severity_contribution * 0.75)
            if forensic_score == 0 and not critical_factors_present:
                fused_score = min(fused_score, 18.0)  # Safe baseline
        else:
            # 4-element calibrated fusion:
            # AI Assessment (35%) + Local Forensics (35%) + Attack Stage Context (15%) + High-Severity Evidence Boost
            fused_score = (ai_score * 0.35) + (forensic_score * 0.35) + (stage_score * 0.15) + high_severity_contribution

    # Clamp and round final risk score
    final_risk_score = round(max(0.0, min(100.0, fused_score)), 1)
    # Convert clean whole numbers to int for presentation
    if final_risk_score.is_integer():
        final_risk_score = int(final_risk_score)

    severity = determine_severity_tier(final_risk_score)

    # 5. Independent Confidence Calculation (0-100)
    # Confidence reflects the abundance and alignment of corroborating evidence
    base_confidence = 55.0

    # More independent indicators = higher confidence
    factor_count = len(matched_factors)
    corroboration_boost = min(factor_count * 7.5, 30.0)

    # Alignment bonus: if AI and forensics are in agreement
    alignment_bonus = 0.0
    if not is_fallback and not analysis_disagreement:
        ai_high = ai_score >= 50.0
        forensic_high = forensic_score >= 45.0
        if ai_high == forensic_high:
            alignment_bonus = 12.0

    # Contradiction penalty
    contradiction_penalty = 25.0 if analysis_disagreement else 0.0

    # Benign certainty bonus: clean input with 0 flags and low risk
    benign_bonus = 0.0
    if factor_count == 0 and final_risk_score < 20.0:
        benign_bonus = 25.0

    calculated_confidence = base_confidence + corroboration_boost + alignment_bonus + benign_bonus - contradiction_penalty
    final_confidence = round(max(15.0, min(98.0, calculated_confidence)), 1)
    if final_confidence.is_integer():
        final_confidence = int(final_confidence)

    # 6. Human-Readable Reasoning Synthesis
    reasoning_lines = [
        f"TrustShield Risk Score: {final_risk_score}/100 ({severity})",
        f"Confidence Rating: {final_confidence}%"
    ]

    if matched_factors:
        reasoning_lines.append("\nKey Contributing Threat Factors:")
        for factor in matched_factors:
            reasoning_lines.append(f"• [{factor['category']}] {factor['title']} (+{int(factor['weight'])} pts)")
    else:
        reasoning_lines.append("\nKey Contributing Threat Factors:")
        reasoning_lines.append("• No critical technical or social engineering indicators detected.")

    reasoning_lines.append(f"\nAttack Stage Impact: '{attack_stage_val}' baseline contribution: {int(stage_score)}/100.")

    if analysis_disagreement:
        reasoning_lines.append(f"\n⚠️ Note on Model Disagreement:\n{disagreement_reason}")

    reasoning_text = "\n".join(reasoning_lines)

    # Format risk_factors for UI consumption
    risk_factors_list = [f"{f['title']} (+{int(f['weight'])})" for f in matched_factors]

    return {
        "risk_score": final_risk_score,
        "confidence_score": final_confidence,
        "severity": severity,
        "risk_factors": risk_factors_list,
        "reasoning": reasoning_text,
        "analysis_disagreement": analysis_disagreement,
        "disagreement_reason": disagreement_reason,
        "forensic_score": forensic_score,
        "attack_stage_weight": stage_score
    }


# Backwards-compatible class wrapper
class RiskEngine:
    """Wrapper class coordinating risk calculations."""

    @staticmethod
    def calculate_risk_tier(score: float) -> str:
        return determine_severity_tier(score)

    @classmethod
    def evaluate_risk(
        cls,
        ai_assessment: Dict[str, Any],
        heuristic_flags: List[str]
    ) -> Dict[str, Any]:
        """Wrapper method providing backwards compatibility for legacy callers."""
        forensic_context = {"flags": heuristic_flags} if heuristic_flags else None
        return calculate_risk(ai_assessment, forensic_context)


# Global singleton instance
risk_engine = RiskEngine()
