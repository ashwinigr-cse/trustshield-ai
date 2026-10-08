"""
TRUSTSHIELD - Attack Chain Intelligence Engine
Models adversarial progression across canonical cyber attack stages:
1. Reconnaissance
2. Initial Access
3. Credential / Account Capture
4. Execution / Exploitation
5. Persistence
6. Data Theft
7. Account Takeover

Provides evidence-based forecasting of adversary trajectories without fabricating chains for benign inputs.
"""

from typing import Dict, Any, List, Optional, Union
import re

# Canonical 7-Stage Attack Lifecycle
ATTACK_STAGES: List[str] = [
    "Reconnaissance",
    "Initial Access",
    "Credential / Account Capture",
    "Execution / Exploitation",
    "Persistence",
    "Data Theft",
    "Account Takeover",
]


def _is_benign_input(
    input_data: Any,
    evidence: Optional[List[Any]] = None,
    analysis_result: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Determines if the artifact is benign and should produce no active attack chain.
    """
    if analysis_result:
        # Check risk score or severity
        risk_score = analysis_result.get("risk_score")
        severity = str(analysis_result.get("severity", "")).lower()
        threat_type = str(analysis_result.get("threat_type", "")).lower()

        if severity == "safe" or (risk_score is not None and float(risk_score) < 20):
            # Check evidence list
            ev = evidence or analysis_result.get("forensic_evidence") or analysis_result.get("evidence_flags") or []
            if len(ev) == 0:
                return True

        if any(term in threat_type for term in ["legitimate", "benign", "unflagged", "safe communication"]):
            ev = evidence or analysis_result.get("forensic_evidence") or analysis_result.get("evidence_flags") or []
            if len(ev) == 0:
                return True

    # Check evidence directly
    if evidence is not None and len(evidence) == 0:
        if analysis_result and analysis_result.get("risk_score", 0) < 20:
            return True

    return False


def _build_timeline(
    current_stage: str,
    observed_stages: List[str],
    likely_next_stage: str,
    is_benign: bool = False
) -> List[Dict[str, Any]]:
    """Builds structured progression timeline nodes for UI and analytical consumption."""
    timeline = []
    current_stage_lower = current_stage.lower()

    for stage in ATTACK_STAGES:
        stage_lower = stage.lower()
        if is_benign:
            timeline.append({
                "stage_name": stage,
                "status": "inactive",
                "is_current": False
            })
        else:
            is_current = (stage_lower in current_stage_lower) or (current_stage_lower in stage_lower)
            if is_current:
                status = "active"
            elif stage in observed_stages:
                status = "completed"
            elif likely_next_stage and (likely_next_stage.lower() in stage_lower or stage_lower in likely_next_stage.lower()):
                status = "projected"
            else:
                status = "projected"

            timeline.append({
                "stage_name": stage,
                "status": status,
                "is_current": is_current
            })

    return timeline


def analyze_attack_chain(
    input_data: Any = None,
    evidence: Optional[List[Any]] = None,
    analysis_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Analyzes forensic evidence and artifact context to model attack chain progression.
    
    Parameters:
        input_data: Target artifact (URL string, message text, bytes, or dict).
        evidence: Optional list of structured forensic evidence items or string flags.
        analysis_result: Optional prior pipeline results (Gemini output, risk assessment).
        
    Returns:
        Structured attack chain dictionary conforming to required specification:
        {
            "current_stage": str,
            "observed_stages": list,
            "likely_next_stage": str,
            "predicted_next_move": str,
            "attacker_goal": str,
            "prediction_confidence": int,
            "reasoning": str,
            "timeline": list
        }
    """
    # Consolidate evidence corpus
    evidence_items = evidence
    if evidence_items is None and analysis_result:
        evidence_items = analysis_result.get("forensic_evidence") or analysis_result.get("evidence_flags") or []

    # Check for benign / safe input
    if _is_benign_input(input_data, evidence_items, analysis_result):
        timeline = _build_timeline("No malicious activity detected", [], "", is_benign=True)
        return {
            "current_stage": "No malicious activity detected",
            "observed_stages": [],
            "likely_next_stage": "",
            "predicted_next_move": "No malicious next move identified",
            "attacker_goal": "None detected",
            "prediction_confidence": 10,
            "reasoning": "No indicators of adversarial attack progression were observed in the evaluated artifact.",
            "timeline": timeline
        }

    # Extract raw text from target artifact
    raw_input_text = ""
    if isinstance(input_data, str):
        raw_input_text = input_data.lower()
    elif isinstance(input_data, dict):
        raw_input_text = str(input_data.get("data", "") or input_data.get("url", "")).lower()

    # Evidence concepts and signals
    evidence_parts = []
    if evidence_items:
        for item in evidence_items:
            if isinstance(item, dict):
                evidence_parts.append(item.get("signal", "").lower())
                evidence_parts.append(item.get("explanation", "").lower())
                evidence_parts.append(item.get("concept", "").lower())
            else:
                evidence_parts.append(str(item).lower())

    # Build primary evidence corpus from input and verified evidence
    primary_corpus = (raw_input_text + " " + " ".join(evidence_parts)).strip()

    # Only include analysis_result if it represents non-fallback AI classification
    if analysis_result and not analysis_result.get("is_fallback"):
        threat_type = str(analysis_result.get("threat_type", "")).lower()
        if "benign" not in threat_type:
            primary_corpus += f" {threat_type}"

    corpus = primary_corpus

    # Deterministic Indicator Flags
    has_otp = any(k in corpus for k in ["otp", "mfa", "2fa", "verification code", "one-time passcode", "security code sent to your mobile", "otp_request"])
    has_executable = any(k in corpus for k in [".exe", ".apk", ".scr", ".vbs", ".bat", ".iso", ".zip", "malicious payload", "executable attachment", "macro-enabled", "malware_delivery"])
    has_financial = any(k in corpus for k in ["wire transfer", "gift card", "overdue invoice", "bitcoin payment", "crypto wallet", "unpaid invoice", "bank transfer", "financial_fraud", "gift_card"])
    has_credentials = any(k in corpus for k in ["password", "credential", "login", "sign in", "sign-in", "passcode", "account deactivation", "credential_request"]) and not has_otp
    is_url = bool(re.search(r"https?://|www\.|[a-z0-9\-]+\.(xyz|top|work|buzz|com|org|net)/[a-z0-9]", corpus)) or (
        isinstance(input_data, str) and ("http://" in input_data or "https://" in input_data or "/" in input_data)
    )

    # ----------------------------------------------------
    # Case 1: OTP / MFA Interception Attack
    # ----------------------------------------------------
    if has_otp:
        current_stage = "Credential / Account Capture"
        observed_stages = ["Reconnaissance", "Initial Access", "Credential / Account Capture"]
        likely_next_stage = "Account Takeover"
        predicted_next_move = "The attacker may attempt to use the captured OTP/MFA code to complete account access and bypass authentication controls."
        attacker_goal = "Bypassing two-factor authentication to achieve total account takeover."
        prediction_confidence = 94
        reasoning = "Evidence indicates active solicitation of multi-factor authentication tokens (OTP/MFA), placing the adversary in the Credential / Account Capture stage, with immediate progression toward Account Takeover."

    # ----------------------------------------------------
    # Case 2: Malicious Executable / Attachment Delivery
    # ----------------------------------------------------
    elif has_executable:
        current_stage = "Execution / Exploitation"
        observed_stages = ["Reconnaissance", "Initial Access", "Execution / Exploitation"]
        likely_next_stage = "Persistence"
        predicted_next_move = "The attacker is likely to execute the payload to establish persistence or exfiltrate local system data."
        attacker_goal = "Host compromise, persistent backdoor installation, or malware deployment."
        prediction_confidence = 92
        reasoning = "Presence of an executable payload or weaponized attachment indicates the attack has progressed to the Execution / Exploitation phase."

    # ----------------------------------------------------
    # Case 3: Financial / Wire Fraud Scam (Initial Access)
    # ----------------------------------------------------
    elif has_financial and not ("password" in raw_input_text or "sign in" in raw_input_text or "login" in raw_input_text):
        current_stage = "Initial Access"
        observed_stages = ["Reconnaissance", "Initial Access"]
        likely_next_stage = "Data Theft"
        predicted_next_move = "The attacker is likely to coerce the victim into completing an unverified financial transaction or wire diversion."
        attacker_goal = "Unauthorized financial diversion and monetary extraction."
        prediction_confidence = 88
        reasoning = "High-urgency payment or wire diversion demands represent an Initial Access social engineering vector targeting immediate financial loss."

    # ----------------------------------------------------
    # Case 4: Credential Harvesting Message
    # ----------------------------------------------------
    elif has_credentials and not is_url:
        current_stage = "Credential / Account Capture"
        observed_stages = ["Reconnaissance", "Initial Access", "Credential / Account Capture"]
        likely_next_stage = "Account Takeover"
        predicted_next_move = "The attacker is likely to harvest submitted credentials and attempt unauthorized sign-in across connected organizational accounts."
        attacker_goal = "Unauthorized account access and credential theft."
        prediction_confidence = 90
        reasoning = "Direct solicitation of login passwords or account credentials indicates the attack has reached the Credential / Account Capture phase."

    # ----------------------------------------------------
    # Case 5: Phishing URL / Deceptive Landing Link
    # ----------------------------------------------------
    elif is_url or any(k in corpus for k in ["lookalike", "spoofed brand", "typosquatting", "phishing url", "fake domain"]):
        current_stage = "Initial Access"
        observed_stages = ["Reconnaissance", "Initial Access"]
        likely_next_stage = "Credential / Account Capture"
        predicted_next_move = "The attacker is likely to redirect the victim to a fake login page and attempt to capture credentials."
        attacker_goal = "Delivery of deceptive landing portal to solicit user authentication credentials."
        prediction_confidence = 91
        reasoning = "Observation of a deceptive or lookalike domain indicates an active Initial Access delivery vector designed to channel victims to credential harvesting."

    # ----------------------------------------------------
    # Case 6: Secondary Financial / Fraud
    # ----------------------------------------------------
    elif has_financial:
        current_stage = "Initial Access"
        observed_stages = ["Reconnaissance", "Initial Access"]
        likely_next_stage = "Data Theft"
        predicted_next_move = "The attacker is likely to coerce the victim into completing an unverified financial transaction or wire diversion."
        attacker_goal = "Unauthorized financial diversion and monetary extraction."
        prediction_confidence = 88
        reasoning = "High-urgency payment or wire diversion demands represent an Initial Access social engineering vector targeting immediate financial loss."

    # ----------------------------------------------------
    # Default Suspicious Artifact Case
    # ----------------------------------------------------
    else:
        current_stage = "Initial Access"
        observed_stages = ["Reconnaissance", "Initial Access"]
        likely_next_stage = "Credential / Account Capture"
        predicted_next_move = "The attacker may attempt to elicit victim engagement and guide the target toward credential or data disclosure."
        attacker_goal = "Adversary seeks initial interaction to progress the attack lifecycle."
        prediction_confidence = 78
        reasoning = "Suspicious social engineering indicators indicate the adversary is attempting Initial Access."

    timeline = _build_timeline(current_stage, observed_stages, likely_next_stage, is_benign=False)

    return {
        "current_stage": current_stage,
        "observed_stages": observed_stages,
        "likely_next_stage": likely_next_stage,
        "predicted_next_move": predicted_next_move,
        "attacker_goal": attacker_goal,
        "prediction_confidence": prediction_confidence,
        "reasoning": reasoning,
        "timeline": timeline
    }


# Backwards-compatible class wrapper
class AttackChainEngine:
    """Wrapper class coordinating attack chain forensics."""

    STAGES = ATTACK_STAGES

    @staticmethod
    def analyze(
        input_data: Any = None,
        evidence: Optional[List[Any]] = None,
        analysis_result: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        return analyze_attack_chain(input_data, evidence, analysis_result)

    @classmethod
    def structure_attack_chain(
        cls,
        current_stage: str,
        predicted_next_move: str,
        tactics_observed: List[str]
    ) -> Dict[str, Any]:
        """Legacy helper for backward compatibility."""
        return analyze_attack_chain(
            analysis_result={
                "attack_stage": current_stage,
                "predicted_next_move": predicted_next_move,
                "evidence_flags": tactics_observed
            }
        )
