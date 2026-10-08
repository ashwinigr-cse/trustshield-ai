"""
TRUSTSHIELD - Risk Intelligence Engine Test Suite
Verifies:
1. Risk score normalization (always 0–100)
2. Severity tier mapping (Safe, Low, Medium, High, Critical)
3. Strong attacks receive significantly higher risk than benign inputs
4. Resilience against missing/corrupted fields without crashing
5. Contradiction handling and explainability outputs
"""

import sys
import os

# Add root directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.risk_engine import calculate_risk, determine_severity_tier


def run_tests():
    print("==================================================")
    print("🧪 RUNNING TRUSTSHIELD RISK INTELLIGENCE TESTS")
    print("==================================================")

    # ----------------------------------------------------
    # TEST CASE A: Safe Benign Message
    # ----------------------------------------------------
    safe_input = {
        "threat_type": "Legitimate Communication",
        "risk_score": 5,
        "confidence_score": 90,
        "evidence_flags": [],
        "attack_stage": "Reconnaissance",
        "input_preview": "Hey Sarah, are we still meeting for lunch at 12:30pm tomorrow?",
        "is_fallback": False
    }
    res_a = calculate_risk(safe_input)
    print(f"\n[TEST A - Safe Message]")
    print(f"Risk Score: {res_a['risk_score']} | Severity: {res_a['severity']} | Confidence: {res_a['confidence_score']}%")
    assert 0 <= res_a["risk_score"] <= 100, "Score out of range"
    assert res_a["severity"] == "Safe", f"Expected Safe, got {res_a['severity']}"
    assert res_a["risk_score"] < 20, f"Expected < 20, got {res_a['risk_score']}"

    # ----------------------------------------------------
    # TEST CASE B: Suspicious Phishing URL
    # ----------------------------------------------------
    url_input = {
        "threat_type": "Brand Impersonation Phishing",
        "risk_score": 75,
        "confidence_score": 88,
        "evidence_flags": [
            "[Heuristic] High-risk Top-Level Domain (.xyz) commonly associated with phishing.",
            "[Heuristic] Potential brand impersonation: 'paypal' detected in foreign domain."
        ],
        "attack_stage": "Initial Access",
        "input_preview": "http://paypal-verification-account-update.xyz/login"
    }
    forensics_b = {
        "flags": ["High-risk Top-Level Domain (.xyz)", "Potential brand impersonation: 'paypal'"],
        "detected_spoofed_brand": "paypal",
        "is_ip_address": False,
        "is_shortened": False
    }
    res_b = calculate_risk(url_input, forensics_b)
    print(f"\n[TEST B - Suspicious Phishing URL]")
    print(f"Risk Score: {res_b['risk_score']} | Severity: {res_b['severity']} | Confidence: {res_b['confidence_score']}%")
    assert 0 <= res_b["risk_score"] <= 100, "Score out of range"
    assert res_b["severity"] in ("High", "Critical"), f"Expected High or Critical, got {res_b['severity']}"
    assert res_b["risk_score"] > res_a["risk_score"], "Phishing URL should have higher risk than safe message"

    # ----------------------------------------------------
    # TEST CASE C: Fake Bank Login Request (Credential Theft)
    # ----------------------------------------------------
    bank_input = {
        "threat_type": "Credential Harvesting Phishing",
        "risk_score": 88,
        "confidence_score": 92,
        "evidence_flags": [
            "Deceptive brand impersonation mimicking Chase Bank authority.",
            "Urgent demand to log in and verify password within 24 hours.",
            "Account suspension threat used as coercive pressure."
        ],
        "attack_stage": "Credential/Account Capture",
        "input_preview": "Urgent: Your Chase account is suspended. Sign in and enter your password immediately."
    }
    res_c = calculate_risk(bank_input)
    print(f"\n[TEST C - Fake Bank Login Request]")
    print(f"Risk Score: {res_c['risk_score']} | Severity: {res_c['severity']} | Confidence: {res_c['confidence_score']}%")
    assert 0 <= res_c["risk_score"] <= 100, "Score out of range"
    assert res_c["severity"] == "Critical", f"Expected Critical, got {res_c['severity']}"
    assert res_c["risk_score"] >= 80, f"Expected >= 80, got {res_c['risk_score']}"

    # ----------------------------------------------------
    # TEST CASE D: OTP / MFA Intercept Phishing Message
    # ----------------------------------------------------
    otp_input = {
        "threat_type": "2FA/MFA Token Theft",
        "risk_score": 92,
        "confidence_score": 95,
        "evidence_flags": [
            "Explicit demand for 6-digit OTP verification code sent via SMS.",
            "Impersonation of corporate IT identity.",
            "Account deactivation threat."
        ],
        "attack_stage": "Credential/Account Capture",
        "input_preview": "We sent an OTP verification code to your mobile device. Reply with the code to verify."
    }
    res_d = calculate_risk(otp_input)
    print(f"\n[TEST D - OTP/MFA Phishing Message]")
    print(f"Risk Score: {res_d['risk_score']} | Severity: {res_d['severity']} | Confidence: {res_d['confidence_score']}%")
    assert 0 <= res_d["risk_score"] <= 100, "Score out of range"
    assert res_d["severity"] == "Critical", f"Expected Critical, got {res_d['severity']}"
    assert any("OTP" in f for f in res_d["risk_factors"]), "Expected OTP factor in matched factors"

    # ----------------------------------------------------
    # TEST CASE E: Malicious Attachment Delivery Message
    # ----------------------------------------------------
    malware_input = {
        "threat_type": "Malware Delivery via Executable Payload",
        "risk_score": 94,
        "confidence_score": 95,
        "evidence_flags": [
            "Attachment containing disguised executable (.exe / .apk) payload.",
            "Urgent payment invoice lure compel downloading.",
            "Attempting system exploitation."
        ],
        "attack_stage": "Execution/Exploitation",
        "input_preview": "Please review the attached overdue invoice_payment.exe immediately."
    }
    res_e = calculate_risk(malware_input)
    print(f"\n[TEST E - Malicious Attachment Message]")
    print(f"Risk Score: {res_e['risk_score']} | Severity: {res_e['severity']} | Confidence: {res_e['confidence_score']}%")
    assert 0 <= res_e["risk_score"] <= 100, "Score out of range"
    assert res_e["severity"] == "Critical", f"Expected Critical, got {res_e['severity']}"

    # ----------------------------------------------------
    # TEST CASE F: Missing Fields & Empty Dict Resilience
    # ----------------------------------------------------
    empty_input = {}
    res_f = calculate_risk(empty_input)
    print(f"\n[TEST F - Empty Input Robustness]")
    print(f"Risk Score: {res_f['risk_score']} | Severity: {res_f['severity']} | Confidence: {res_f['confidence_score']}%")
    assert 0 <= res_f["risk_score"] <= 100, "Score out of range"
    assert res_f["severity"] in ("Safe", "Low", "Medium", "High", "Critical")
    assert isinstance(res_f["risk_factors"], list)
    assert len(res_f["reasoning"]) > 0

    # ----------------------------------------------------
    # TEST CASE G: Contradiction Handling (AI Low, Forensic High)
    # ----------------------------------------------------
    contradiction_input = {
        "threat_type": "Unsure",
        "risk_score": 25,  # AI says Low
        "confidence_score": 70,
        "evidence_flags": [
            "Explicit demand for user password and OTP verification code.",
            "Account suspension ultimatum."
        ],
        "attack_stage": "Credential/Account Capture"
    }
    res_g = calculate_risk(contradiction_input)
    print(f"\n[TEST G - Contradiction Handling]")
    print(f"Disagreement Flagged: {res_g['analysis_disagreement']}")
    print(f"Overridden Risk Score: {res_g['risk_score']} | Severity: {res_g['severity']}")
    assert res_g["analysis_disagreement"] is True, "Expected contradiction to be flagged"
    assert res_g["risk_score"] >= 70, f"Expected override >= 70, got {res_g['risk_score']}"

    # ----------------------------------------------------
    # VERIFY RELATIVE RISK PROGRESSION
    # Safe < Phishing URL < Fake Bank Login / OTP / Malware
    # ----------------------------------------------------
    assert res_a["risk_score"] < res_b["risk_score"] <= res_c["risk_score"]
    assert res_c["risk_score"] >= 80

    print("\n==================================================")
    print("✅ ALL 7 RISK ENGINE TEST CASES PASSED SUCCESSFULLY!")
    print("==================================================")


if __name__ == "__main__":
    run_tests()
