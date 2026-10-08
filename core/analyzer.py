"""
TRUSTSHIELD - Core Forensic Threat Analyzer
Orchestrates artifact intake, local heuristic preprocessing, Google Gemini AI reasoning,
and robust error-resilient normalization.
"""

from typing import Dict, Any, Union, List, Optional
import json
import re

from .gemini import analyze_with_gemini, is_gemini_available, ATTACK_LIFECYCLE_STAGES
from .risk_engine import calculate_risk
from .evidence_engine import extract_local_message_evidence, correlate_and_deduplicate_evidence
from .attack_chain import analyze_attack_chain
from utils.url_utils import analyze_url, analyze_url_heuristics


def detect_input_type(input_data: Union[str, bytes, Dict[str, Any]]) -> str:
    """
    Infers whether the provided artifact is a URL, email, message, or screenshot.
    """
    if isinstance(input_data, bytes):
        return "screenshot"

    if isinstance(input_data, dict):
        return input_data.get("type", "unknown")

    if isinstance(input_data, str):
        cleaned = input_data.strip()
        # Explicit or structured URL
        if re.match(r"^(https?://|www\.)[^\s]+", cleaned, re.IGNORECASE):
            return "url"
        # Bare domain / URL syntax (e.g., example.com/login)
        if "." in cleaned and " " not in cleaned and len(cleaned.split(".")) >= 2 and "/" in cleaned:
            return "url"
        # Standard email header markers
        lower_content = cleaned.lower()
        if ("from:" in lower_content and "subject:" in lower_content) or (
            "to:" in lower_content and "subject:" in lower_content
        ):
            return "email"
        return "message"

    return "unknown"


def _normalize_score(score_val: Any, default: int = 50) -> int:
    """Safely coerces any raw model score to an integer between 0 and 100."""
    try:
        val = float(score_val)
        return max(0, min(100, int(round(val))))
    except (ValueError, TypeError):
        return default


def _normalize_severity(severity_val: Any, risk_score: int) -> str:
    """Ensures severity aligns with recognized threat tiers."""
    valid_tiers = {"Safe", "Low", "Medium", "High", "Critical"}
    if isinstance(severity_val, str) and severity_val.capitalize() in valid_tiers:
        return severity_val.capitalize()

    # Calculate from score if missing or invalid
    if risk_score < 20:
        return "Safe"
    elif risk_score < 45:
        return "Low"
    elif risk_score < 70:
        return "Medium"
    elif risk_score < 88:
        return "High"
    return "Critical"


def _generate_fallback_analysis(
    input_data: Union[str, bytes, Dict[str, Any]],
    input_type: str,
    heuristics: Optional[Dict[str, Any]] = None,
    error_note: Optional[str] = None
) -> Dict[str, Any]:
    """
    Gracefully produces an offline heuristic analysis when the Gemini API
    is unreachable or GEMINI_API_KEY is not configured. Prevents application crashes.
    """
    heuristic_flags = heuristics.get("flags", []) if heuristics else []
    flag_count = len(heuristic_flags)

    # Heuristic scoring formula
    if flag_count == 0:
        risk_score = 12 if input_type == "url" else 5
        threat_type = "Benign / No Threat Indicators Detected"
        attack_stage = "Reconnaissance"
        evidence = []
    elif input_type == "url":
        if flag_count >= 3:
            risk_score = 82
            threat_type = "Suspicious URL (High Heuristic Deception)"
        else:
            risk_score = 65
            threat_type = "Potential Phishing / Spoofed Domain"
        attack_stage = "Initial Access"
        evidence = heuristic_flags
    else:
        risk_score = 80 if flag_count >= 2 else 60
        threat_type = "Suspicious Digital Communication"
        attack_stage = "Initial Access"
        evidence = heuristic_flags

    severity = _normalize_severity(None, risk_score)

    friendly_explanation = (
        "This artifact was evaluated using our local heuristic security engine. "
        "To enable deep multi-modal cognitive reasoning, ensure your GEMINI_API_KEY is configured in your .env file."
    )

    return {
        "threat_type": threat_type,
        "risk_score": risk_score,
        "confidence_score": 60,
        "severity": severity,
        "evidence_flags": evidence,
        "attack_stage": "Initial Access",
        "predicted_next_move": "Adversary will attempt credential lure or fraudulent interaction if engaged.",
        "attacker_goal": "Initial Access & User Credential Harvesting",
        "attack_chain": [
            "Reconnaissance (Completed)",
            "Initial Access (Active - Current Phase)",
            "Credential/Account Capture (Projected Next)",
            "Account Takeover (Projected Goal)"
        ],
        "safety_recommendations": [
            "Do not click any embedded links or provide login credentials.",
            "Independently verify sender authenticity through official channels.",
            "Report suspicious communication to security administrators."
        ],
        "safe_response": "I cannot fulfill this request without prior out-of-band verification.",
        "plain_english_explanation": friendly_explanation,
        "is_fallback": True,
        "analysis_mode": "Local Heuristic Fallback",
        "fallback_note": error_note or "Gemini API unavailable"
    }


def analyze_input(input_data: Union[str, bytes, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Primary TrustShield analysis entrypoint.
    
    1. Detects artifact modality (URL, message, email, screenshot).
    2. Performs local static preprocessing (heuristics, entropy, brand checks).
    3. Engages Google Gemini AI for cognitive reasoning and threat modeling.
    4. Normalizes and validates the response schema (0-100 scores, evidence, attack chain).
    5. Falls back seamlessly without exposing API secrets or crashing if Gemini is unavailable.
    """
    detected_type = detect_input_type(input_data)
    heuristics = None
    additional_context = ""

    # Preview string for logging and UI summary
    if isinstance(input_data, bytes):
        input_preview = f"[Uploaded Screenshot - {len(input_data):,} bytes]"
    elif isinstance(input_data, dict):
        input_preview = str(input_data.get("data", ""))[:120]
    else:
        input_preview = str(input_data).strip()[:120]

    # 1. Lightweight Local Preprocessing & Forensics Extraction
    local_signals: List[Dict[str, Any]] = []

    if detected_type == "url":
        target_url = input_data.get("data", "") if isinstance(input_data, dict) else str(input_data)
        heuristics = analyze_url(target_url)
        local_signals = heuristics.get("signals", [])
        additional_context = (
            f"STATIC HEURISTIC SIGNALS:\n"
            f"- Normalized URL: {heuristics.get('normalized_url')}\n"
            f"- Domain: {heuristics.get('domain')}\n"
            f"- TLD: {heuristics.get('tld')}\n"
            f"- Is IP Address: {heuristics.get('is_ip_host')}\n"
            f"- URL Shortener: {heuristics.get('is_shortened')}\n"
            f"- Entropy: {heuristics.get('entropy')}\n"
            f"- Heuristic Red Flags: {json.dumps(heuristics.get('flags', []))}"
        )
    elif detected_type in ("message", "email", "text"):
        text_content = input_data.get("data", "") if isinstance(input_data, dict) else str(input_data)
        local_signals = extract_local_message_evidence(text_content)
        heuristics = {
            "flags": [s["explanation"] for s in local_signals],
            "signals": local_signals
        }
        if local_signals:
            additional_context = (
                f"LOCAL COMMUNICATION FORENSICS:\n"
                f"- Extracted Signals: {json.dumps([s['signal'] for s in local_signals])}"
            )
    else:
        heuristics = {"flags": []}

    # 2. Invoke Gemini AI with Graceful Fallback
    raw_ai_result = None
    fallback_reason = None

    if is_gemini_available():
        try:
            raw_ai_result = analyze_with_gemini(
                input_data=input_data,
                input_type=detected_type,
                additional_context=additional_context
            )
        except Exception as e:
            # Mask internal API keys and error traces
            fallback_reason = "Gemini AI call encountered an error. Switched to offline heuristic engine."
            raw_ai_result = None
    else:
        fallback_reason = "GEMINI_API_KEY is not configured. Operating in local heuristic mode."

    # If AI succeeded, use AI results; otherwise use fallback
    if raw_ai_result and isinstance(raw_ai_result, dict):
        result = raw_ai_result
        is_fallback = False
        analysis_mode = "Google Gemini AI Reasoning"
    else:
        result = _generate_fallback_analysis(input_data, detected_type, heuristics, fallback_reason)
        is_fallback = True
        analysis_mode = result.get("analysis_mode", "Local Heuristic Fallback")

    # 3. Evidence Correlation & Deduplication Layer
    raw_flags = result.get("evidence_flags") or result.get("red_flags") or []
    if not isinstance(raw_flags, list):
        raw_flags = [str(raw_flags)]

    forensic_evidence, evidence_summary = correlate_and_deduplicate_evidence(
        local_signals=local_signals,
        gemini_flags=raw_flags,
        input_type=detected_type
    )

    evidence_flags = [item["explanation"] for item in forensic_evidence]
    result["evidence_flags"] = evidence_flags
    result["red_flags"] = evidence_flags

    # 4. Independent Risk Intelligence Engine Evaluation
    # Fuses Gemini AI reasoning + Local heuristics + Attack stage + Evidence severity
    risk_assessment = calculate_risk(result, heuristics)

    final_risk = risk_assessment["risk_score"]
    final_confidence = risk_assessment["confidence_score"]
    final_severity = risk_assessment["severity"]
    risk_factors = risk_assessment["risk_factors"]
    reasoning = risk_assessment["reasoning"]
    analysis_disagreement = risk_assessment.get("analysis_disagreement", False)
    disagreement_reason = risk_assessment.get("disagreement_reason", "")

    # Ensure evidence flags is a list of clean strings
    raw_flags = result.get("evidence_flags") or result.get("red_flags") or []
    if not isinstance(raw_flags, list):
        raw_flags = [str(raw_flags)]
    evidence_flags = [str(f).strip() for f in raw_flags if str(f).strip()]

    # Merge static heuristic flags if not already represented
    if heuristics and heuristics.get("flags"):
        for h_flag in heuristics["flags"]:
            if not any(h_flag.lower() in ef.lower() for ef in evidence_flags):
                evidence_flags.append(f"[Heuristic] {h_flag}")

    # 5. Attack Chain Intelligence Modeling
    attack_chain_obj = analyze_attack_chain(
        input_data=input_data,
        evidence=forensic_evidence,
        analysis_result=result
    )

    attack_stage = attack_chain_obj.get("current_stage", "Initial Access")
    predicted_next_move = attack_chain_obj.get("predicted_next_move", "Adversary seeks victim action.")
    attacker_goal = attack_chain_obj.get("attacker_goal", "Unauthorized access or financial extraction.")
    attack_chain_list = attack_chain_obj.get("observed_stages", [])
    timeline_nodes = attack_chain_obj.get("timeline", [])

    # Actionable safety recommendations list
    raw_recommendations = result.get("safety_recommendations", [])
    if isinstance(raw_recommendations, list):
        safety_recommendations = [str(r).strip() for r in raw_recommendations if str(r).strip()]
    else:
        safety_recommendations = [str(raw_recommendations).strip()]

    # Safe response
    safe_response = str(
        result.get("safe_response", "I cannot fulfill this request without prior out-of-band identity verification.")
    ).strip()

    # Plain english explanation
    plain_explanation = str(
        result.get("plain_english_explanation", "This artifact has been evaluated for digital deception and threat indicators.")
    ).strip()

    threat_type = str(result.get("threat_type", "Suspicious Digital Threat")).strip()

    # Return unified, consistent dictionary
    return {
        # Core Requested Metrics
        "threat_type": threat_type,
        "threat_classification": threat_type,  # Dual-compatibility
        "risk_score": final_risk,
        "confidence_score": final_confidence,
        "severity": final_severity,
        "risk_factors": risk_factors,
        "reasoning": reasoning,
        "analysis_disagreement": analysis_disagreement,
        "disagreement_reason": disagreement_reason,
        "forensic_evidence": forensic_evidence,
        "evidence_summary": evidence_summary,
        "evidence_flags": evidence_flags,
        "red_flags": evidence_flags,  # Dual-compatibility
        "attack_stage": attack_stage,
        "predicted_next_move": predicted_next_move,
        "attacker_goal": attacker_goal,
        "attack_chain": attack_chain_obj,  # Attack chain object
        "attack_chain_timeline": attack_chain_obj,
        "attack_chain_list": attack_chain_list,
        "safety_recommendations": safety_recommendations,
        "safe_response": safe_response,
        "plain_english_explanation": plain_explanation,

        # UI & Contextual Metadata
        "input_type": detected_type,
        "input_preview": input_preview,
        "is_fallback": is_fallback,
        "analysis_mode": analysis_mode,
        "fallback_reason": fallback_reason,
        "risk_profile": {
            "risk_score": final_risk,
            "risk_tier": final_severity,
            "confidence_score": final_confidence,
            "risk_factors": risk_factors,
            "reasoning": reasoning,
            "analysis_disagreement": analysis_disagreement,
            "summary_tag": f"{final_severity.upper()} RISK ({final_risk}/100)"
        },
        "timeline": timeline_nodes
    }


# Backwards-compatible class wrapper
class TrustShieldAnalyzer:
    """Wrapper class coordinating threat analysis."""

    @staticmethod
    def analyze_input(input_data: Union[str, bytes, Dict[str, Any]]) -> Dict[str, Any]:
        return analyze_input(input_data)

    def analyze_url(self, url: str) -> Dict[str, Any]:
        return analyze_input({"type": "url", "data": url})

    def analyze_text(self, text: str, context_type: str = "General Message") -> Dict[str, Any]:
        return analyze_input({"type": "text", "context": context_type, "data": text})

    def analyze_screenshot(
        self,
        image_bytes: bytes,
        mime_type: str = "image/png",
        user_notes: Optional[str] = None
    ) -> Dict[str, Any]:
        return analyze_input({"type": "screenshot", "data": image_bytes, "mime_type": mime_type, "notes": user_notes})


# Global singleton instance
analyzer_engine = TrustShieldAnalyzer()
