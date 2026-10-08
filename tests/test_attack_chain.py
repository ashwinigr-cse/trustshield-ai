"""
TRUSTSHIELD - Attack Chain Intelligence Test Suite
Tests:
A. Legitimate message (No fabricated attack chain)
B. Fake bank login URL (Initial Access -> Credential / Account Capture)
C. Credential harvesting message (Credential / Account Capture)
D. OTP/MFA phishing (Predicts Account Takeover)
E. Suspicious executable attachment (Execution / Exploitation)
F. Payment/financial scam (Initial Access -> Financial fraud)
G. Multi-stage phishing (Full lifecycle progression)
"""

import sys
import os

# Add root directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.attack_chain import analyze_attack_chain, ATTACK_STAGES
from core.analyzer import analyze_input

REQUIRED_KEYS = {
    "current_stage",
    "observed_stages",
    "likely_next_stage",
    "predicted_next_move",
    "attacker_goal",
    "prediction_confidence",
    "reasoning",
    "timeline",
}


def run_attack_chain_tests():
    print("==================================================")
    print("⛓️ RUNNING TRUSTSHIELD ATTACK CHAIN TESTS")
    print("==================================================")

    # ----------------------------------------------------
    # TEST CASE A: Legitimate Message (Benign - No Fabricated Attack Chain)
    # ----------------------------------------------------
    clean_msg = "Hey team, the quarterly sync will be in conference room A at 10am tomorrow."
    res_a = analyze_input({"type": "message", "data": clean_msg})
    chain_a = res_a.get("attack_chain", {})

    print(f"\n[TEST A - Legitimate Message]")
    print(f"Current Stage: {chain_a.get('current_stage')}")
    print(f"Likely Next: '{chain_a.get('likely_next_stage')}'")
    print(f"Confidence: {chain_a.get('prediction_confidence')}%")

    assert REQUIRED_KEYS.issubset(chain_a.keys()), "Missing required keys in attack_chain output"
    assert chain_a["current_stage"] == "No malicious activity detected", f"Expected benign indicator, got {chain_a['current_stage']}"
    assert len(chain_a["observed_stages"]) == 0, "Benign input should produce 0 observed stages"
    assert chain_a["likely_next_stage"] == "", "Benign input should have empty likely_next_stage"
    assert chain_a["predicted_next_move"] == "No malicious next move identified"
    assert chain_a["attacker_goal"] == "None detected"
    assert 0 <= chain_a["prediction_confidence"] <= 100

    # ----------------------------------------------------
    # TEST CASE B: Fake Bank Login URL (Phishing produces Initial Access)
    # ----------------------------------------------------
    bank_url = "https://chase-security-verify.xyz/login"
    res_b = analyze_input({"type": "url", "data": bank_url})
    chain_b = res_b.get("attack_chain", {})

    print(f"\n[TEST B - Fake Bank Login URL]")
    print(f"Current Stage: {chain_b.get('current_stage')}")
    print(f"Likely Next: {chain_b.get('likely_next_stage')}")
    print(f"Predicted Move: {chain_b.get('predicted_next_move')}")

    assert REQUIRED_KEYS.issubset(chain_b.keys())
    assert chain_b["current_stage"] == "Initial Access", f"Expected Initial Access, got {chain_b['current_stage']}"
    assert "Credential / Account Capture" in chain_b["likely_next_stage"]
    assert 0 <= chain_b["prediction_confidence"] <= 100
    assert len(chain_b["reasoning"]) > 0

    # ----------------------------------------------------
    # TEST CASE C: Credential Harvesting Message
    # ----------------------------------------------------
    cred_msg = "URGENT: Your account access has been restricted. Sign in and enter your password immediately to verify your identity."
    res_c = analyze_input({"type": "message", "data": cred_msg})
    chain_c = res_c.get("attack_chain", {})

    print(f"\n[TEST C - Credential Harvesting Message]")
    print(f"Current Stage: {chain_c.get('current_stage')}")
    print(f"Likely Next: {chain_c.get('likely_next_stage')}")

    assert REQUIRED_KEYS.issubset(chain_c.keys())
    assert chain_c["current_stage"] == "Credential / Account Capture", f"Expected Credential / Account Capture, got {chain_c['current_stage']}"
    assert chain_c["likely_next_stage"] in ("Account Takeover", "Data Theft")
    assert 0 <= chain_c["prediction_confidence"] <= 100

    # ----------------------------------------------------
    # TEST CASE D: OTP / MFA Phishing (Predicts Account Takeover)
    # ----------------------------------------------------
    otp_msg = "Microsoft Alert: An authentication OTP was sent to your mobile phone. Reply with the 6-digit verification code to keep your session active."
    res_d = analyze_input({"type": "message", "data": otp_msg})
    chain_d = res_d.get("attack_chain", {})

    print(f"\n[TEST D - OTP/MFA Phishing Message]")
    print(f"Current Stage: {chain_d.get('current_stage')}")
    print(f"Likely Next: {chain_d.get('likely_next_stage')}")
    print(f"Predicted Move: {chain_d.get('predicted_next_move')}")

    assert REQUIRED_KEYS.issubset(chain_d.keys())
    assert chain_d["current_stage"] == "Credential / Account Capture"
    assert chain_d["likely_next_stage"] == "Account Takeover", f"Expected Account Takeover, got {chain_d['likely_next_stage']}"
    assert "otp" in chain_d["predicted_next_move"].lower() or "mfa" in chain_d["predicted_next_move"].lower() or "account" in chain_d["predicted_next_move"].lower()
    assert 0 <= chain_d["prediction_confidence"] <= 100

    # ----------------------------------------------------
    # TEST CASE E: Suspicious Executable Attachment
    # ----------------------------------------------------
    malware_msg = "Attached is your overdue invoice summary: invoice_scan.exe. Please download and execute it immediately."
    res_e = analyze_input({"type": "message", "data": malware_msg})
    chain_e = res_e.get("attack_chain", {})

    print(f"\n[TEST E - Malicious Executable Attachment]")
    print(f"Current Stage: {chain_e.get('current_stage')}")
    print(f"Likely Next: {chain_e.get('likely_next_stage')}")

    assert REQUIRED_KEYS.issubset(chain_e.keys())
    assert chain_e["current_stage"] == "Execution / Exploitation", f"Expected Execution / Exploitation, got {chain_e['current_stage']}"
    assert chain_e["likely_next_stage"] in ("Persistence", "Data Theft")
    assert 0 <= chain_e["prediction_confidence"] <= 100

    # ----------------------------------------------------
    # TEST CASE F: Payment / Financial Scam
    # ----------------------------------------------------
    wire_msg = "Immediate wire transfer of $12,500 required for urgent vendor payment to avoid legal default. Wire details attached."
    res_f = analyze_input({"type": "message", "data": wire_msg})
    chain_f = res_f.get("attack_chain", {})

    print(f"\n[TEST F - Payment / Financial Scam]")
    print(f"Current Stage: {chain_f.get('current_stage')}")
    print(f"Likely Next: {chain_f.get('likely_next_stage')}")

    assert REQUIRED_KEYS.issubset(chain_f.keys())
    assert chain_f["current_stage"] in ("Initial Access", "Execution / Exploitation")
    assert 0 <= chain_f["prediction_confidence"] <= 100
    assert len(chain_f["attacker_goal"]) > 0

    # ----------------------------------------------------
    # TEST CASE G: Multi-Stage Phishing Direct Engine Call
    # ----------------------------------------------------
    print(f"\n[TEST G - Multi-Stage Phishing Direct Engine Invocation]")
    custom_evidence = [
        {"signal": "Brand Impersonation (Microsoft)", "severity": "high", "explanation": "Spoofed Microsoft login"},
        {"signal": "Credential Harvesting", "severity": "critical", "explanation": "Solicits user password"},
        {"signal": "OTP Intercept", "severity": "critical", "explanation": "Demands 2FA verification token"}
    ]
    chain_g = analyze_attack_chain(
        input_data="https://login.microsoftonline.xyz/auth",
        evidence=custom_evidence
    )
    print(f"Current Stage: {chain_g['current_stage']}")
    print(f"Observed: {chain_g['observed_stages']}")
    print(f"Likely Next: {chain_g['likely_next_stage']}")
    print(f"Timeline Node Count: {len(chain_g['timeline'])}")

    assert REQUIRED_KEYS.issubset(chain_g.keys())
    assert chain_g["current_stage"] == "Credential / Account Capture"
    assert chain_g["likely_next_stage"] == "Account Takeover"
    assert len(chain_g["observed_stages"]) >= 2
    assert len(chain_g["timeline"]) == len(ATTACK_STAGES)

    print("\n==================================================")
    print("✅ ALL 7 ATTACK CHAIN TEST CASES PASSED SUCCESSFULLY!")
    print("==================================================")


if __name__ == "__main__":
    run_attack_chain_tests()
