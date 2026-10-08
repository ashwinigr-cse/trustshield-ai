"""
TRUSTSHIELD - Forensic Evidence & Red-Flag Intelligence Test Suite
Tests:
A. Legitimate message (No fabricated evidence)
B. Fake bank login URL
C. Typosquatting URL
D. OTP phishing message
E. Payment scam message
F. Suspicious attachment message
G. Multiple overlapping signals that must be deduplicated
"""

import sys
import os

# Add root directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.analyzer import analyze_input
from core.evidence_engine import extract_local_message_evidence, correlate_and_deduplicate_evidence
from utils.url_utils import analyze_url

VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def run_forensic_tests():
    print("==================================================")
    print("🔬 RUNNING TRUSTSHIELD FORENSIC EVIDENCE TESTS")
    print("==================================================")

    # ----------------------------------------------------
    # TEST CASE A: Legitimate Message (Benign - No Fabricated Evidence)
    # ----------------------------------------------------
    clean_msg = "Good morning team, please find the quarterly project timeline notes attached in our shared workspace. Have a great day!"
    res_a = analyze_input({"type": "message", "data": clean_msg})
    evidence_a = res_a.get("forensic_evidence", [])
    print(f"\n[TEST A - Legitimate Message]")
    print(f"Evidence items detected: {len(evidence_a)} | Summary: {res_a.get('evidence_summary')}")
    assert len(evidence_a) == 0, f"Expected 0 evidence items for benign input, got {len(evidence_a)}"
    assert "No significant malicious indicators detected" in res_a.get("evidence_summary", "")

    # ----------------------------------------------------
    # TEST CASE B: Fake Bank Login URL
    # ----------------------------------------------------
    bank_url = "http://chase-bank-verify-account.xyz/signin/password"
    res_b = analyze_input({"type": "url", "data": bank_url})
    evidence_b = res_b.get("forensic_evidence", [])
    print(f"\n[TEST B - Fake Bank Login URL]")
    print(f"Evidence items detected: {len(evidence_b)}")
    assert len(evidence_b) > 0, "Expected forensic evidence items for fake bank URL"
    for item in evidence_b:
        assert item["severity"] in VALID_SEVERITIES, f"Invalid severity: {item['severity']}"
        assert 0 <= item["confidence"] <= 100, f"Confidence out of range: {item['confidence']}"
        assert len(item["explanation"]) > 0
        assert len(item["why_it_matters"]) > 0

    # Ensure brand impersonation or high-risk TLD was flagged
    signals_b = [item["signal"].lower() for item in evidence_b]
    assert any("brand" in s or "tld" in s or "keyword" in s for s in signals_b), "Expected brand or TLD signal"

    # ----------------------------------------------------
    # TEST CASE C: Typosquatting URL
    # ----------------------------------------------------
    typo_url = "https://paypa1-security-check.com/update"
    res_c = analyze_input({"type": "url", "data": typo_url})
    evidence_c = res_c.get("forensic_evidence", [])
    print(f"\n[TEST C - Typosquatting URL]")
    print(f"Evidence items detected: {len(evidence_c)}")
    assert len(evidence_c) > 0, "Expected evidence for typosquatting URL"
    signals_c = [item["signal"].lower() for item in evidence_c]
    assert any("typosquatting" in s or "brand" in s for s in signals_c), f"Expected typosquatting or brand in signals: {signals_c}"

    # ----------------------------------------------------
    # TEST CASE D: OTP Phishing Message
    # ----------------------------------------------------
    otp_msg = "URGENT: Microsoft Security has sent an OTP code to your phone. Reply with the 6-digit verification code immediately to prevent account suspension."
    res_d = analyze_input({"type": "message", "data": otp_msg})
    evidence_d = res_d.get("forensic_evidence", [])
    print(f"\n[TEST D - OTP Phishing Message]")
    print(f"Evidence items detected: {len(evidence_d)}")
    assert len(evidence_d) > 0, "Expected evidence for OTP phishing message"
    severities_d = [item["severity"] for item in evidence_d]
    assert "critical" in severities_d, "Expected at least one CRITICAL severity evidence item for OTP lure"
    assert any("otp" in item["signal"].lower() or "mfa" in item["signal"].lower() for item in evidence_d)

    # ----------------------------------------------------
    # TEST CASE E: Payment Scam Message
    # ----------------------------------------------------
    payment_msg = "Overdue invoice notification: wire transfer of $4,850 due today immediately to avoid court summons."
    res_e = analyze_input({"type": "message", "data": payment_msg})
    evidence_e = res_e.get("forensic_evidence", [])
    print(f"\n[TEST E - Payment Scam Message]")
    print(f"Evidence items detected: {len(evidence_e)}")
    assert len(evidence_e) > 0, "Expected evidence for payment scam"
    assert any("payment" in item["signal"].lower() or "financial" in item["signal"].lower() or "urgency" in item["signal"].lower() for item in evidence_e)

    # ----------------------------------------------------
    # TEST CASE F: Suspicious Attachment Message
    # ----------------------------------------------------
    malware_msg = "Attached is the urgent wire receipt: payment_receipt.exe. Please download and run it now."
    res_f = analyze_input({"type": "message", "data": malware_msg})
    evidence_f = res_f.get("forensic_evidence", [])
    print(f"\n[TEST F - Suspicious Attachment Message]")
    print(f"Evidence items detected: {len(evidence_f)}")
    assert len(evidence_f) > 0, "Expected evidence for malware attachment"
    assert any("executable" in item["signal"].lower() or "attachment" in item["signal"].lower() or "payload" in item["signal"].lower() for item in evidence_f)

    # ----------------------------------------------------
    # TEST CASE G: Multiple Overlapping Signals Deduplication
    # ----------------------------------------------------
    print(f"\n[TEST G - Deduplication & Composite Correlation]")
    local_sigs = [
        {"signal": "Credential Harvesting Request", "severity": "critical", "explanation": "Demands password", "source": "local", "concept": "credential_request"},
        {"signal": "Artificial Urgency Trigger", "severity": "medium", "explanation": "Urgent deadline", "source": "local", "concept": "urgency"},
        {"signal": "Claimed Institutional Identity (PayPal)", "severity": "medium", "explanation": "Claims PayPal", "source": "local", "concept": "brand_reference"}
    ]
    # Redundant flags from AI repeating the exact same observations
    ai_flags = [
        "Demands user credentials and password",
        "High urgency detected in message",
        "PayPal brand impersonation detected",
        "Suspicious tone"
    ]
    deduped_evidence, summary = correlate_and_deduplicate_evidence(local_sigs, ai_flags, input_type="message")
    print(f"Deduplicated count: {len(deduped_evidence)} items")
    print(f"Summary: {summary}")

    # Verify deduplication happened (should not be 3 + 4 = 7 items)
    # Plus composite signal: "Social-Engineering Credential Lure (Correlated Composite)"
    assert len(deduped_evidence) <= 5, f"Expected <= 5 items after deduplication, got {len(deduped_evidence)}"
    
    # Check that dual-source findings elevated to source='combined'
    combined_items = [item for item in deduped_evidence if item["source"] == "combined"]
    assert len(combined_items) >= 1, "Expected at least one combined-source elevated finding"
    for item in combined_items:
        assert item["confidence"] >= 90, f"Expected confidence >= 90 for combined finding, got {item['confidence']}"

    print("\n==================================================")
    print("✅ ALL 7 FORENSIC EVIDENCE TEST CASES PASSED SUCCESSFULLY!")
    print("==================================================")


if __name__ == "__main__":
    run_forensic_tests()
