"""
TRUSTSHIELD - Artifact Input & Analysis UI Component
Provides modular submission views for suspicious URLs, text messages/emails, and screenshots.
"""

from typing import Optional, Dict, Any
import streamlit as st
from utils.validators import validate_url, validate_text_message, validate_image_bytes
from utils.url_utils import analyze_url_heuristics


def render_analysis_inputs() -> Optional[Dict[str, Any]]:
    """
    Renders input forms for URLs, Emails/Texts, and Screenshots, along with quick demo sample buttons.
    Returns submitted payload dictionary or None if no action taken.
    """
    # Demo sample presets
    SAMPLES = {
        "phishing_url": {
            "type": "url",
            "data": "http://paypal-security-update.account-verification-alert.com/login"
        },
        "fake_bank": {
            "type": "text",
            "context": "Email Message",
            "data": "URGENT: Chase Online Banking Security Alert - Your account has been temporarily restricted due to unauthorized login attempts. Verify your identity immediately at https://chase-security-verify-login.com to prevent permanent suspension."
        },
        "otp_phishing": {
            "type": "text",
            "context": "SMS / Smishing Text",
            "data": "ALERT: Your bank account will be suspended in 24 hours. Click https://secure-bank-login.xyz to verify your identity. Do not ignore! Reply with your 6-digit one-time passcode immediately to restore access."
        },
        "malicious_attachment": {
            "type": "text",
            "context": "Corporate BEC / Invoice",
            "data": "Attached is your overdue invoice INV-2026-99342. Please enable macros and open Invoice_Payment_Receipt.exe immediately to confirm transaction clearance."
        },
        "payment_scam": {
            "type": "text",
            "context": "Chat / Direct Message",
            "data": "URGENT WIRE TRANSFER REQUIRED: Due to audit deadlines, please wire $45,000 immediately to the following updated account details before 5 PM today."
        },
        "benign_msg": {
            "type": "text",
            "context": "Email Message",
            "data": "Hey Alex, could you send over the slides from yesterday's team meeting when you get a chance? Thanks!"
        }
    }

    st.subheader("🔍 Submit Suspicious Artifact for Forensic Inspection")

    # Interactive Demo Sample Buttons
    st.markdown("**⚡ Quick Demo Scenarios (Click to test instantly):**")
    d1, d2, d3, d4, d5, d6 = st.columns(6)
    demo_triggered = None

    with d1:
        if st.button("🔗 Phishing URL", use_container_width=True, help="Load suspicious typosquatting URL"):
            demo_triggered = SAMPLES["phishing_url"]
            st.session_state["preset_url"] = demo_triggered["data"]
    with d2:
        if st.button("🏦 Fake Bank Login", use_container_width=True, help="Load fake Chase bank verification lure"):
            demo_triggered = SAMPLES["fake_bank"]
            st.session_state["preset_text"] = demo_triggered["data"]
            st.session_state["preset_context"] = demo_triggered["context"]
    with d3:
        if st.button("🔐 OTP/MFA Phishing", use_container_width=True, help="Load 2FA/OTP interception attack"):
            demo_triggered = SAMPLES["otp_phishing"]
            st.session_state["preset_text"] = demo_triggered["data"]
            st.session_state["preset_context"] = demo_triggered["context"]
    with d4:
        if st.button("📎 Malicious Attachment", use_container_width=True, help="Load executable attachment lure"):
            demo_triggered = SAMPLES["malicious_attachment"]
            st.session_state["preset_text"] = demo_triggered["data"]
            st.session_state["preset_context"] = demo_triggered["context"]
    with d5:
        if st.button("💰 Payment Scam", use_container_width=True, help="Load urgent wire transfer request"):
            demo_triggered = SAMPLES["payment_scam"]
            st.session_state["preset_text"] = demo_triggered["data"]
            st.session_state["preset_context"] = demo_triggered["context"]
    with d6:
        if st.button("🟢 Benign Message", use_container_width=True, help="Load harmless team communication"):
            demo_triggered = SAMPLES["benign_msg"]
            st.session_state["preset_text"] = demo_triggered["data"]
            st.session_state["preset_context"] = demo_triggered["context"]

    # If demo button was clicked, directly return it for instant analysis
    if demo_triggered:
        return demo_triggered

    tab_url, tab_text, tab_image = st.tabs([
        "🔗 Suspicious URL",
        "✉️ Email / Message / SMS",
        "📸 Screenshot / Image Lure"
    ])

    submitted_payload: Optional[Dict[str, Any]] = None

    # --- TAB 1: URL ANALYSIS ---
    with tab_url:
        st.markdown("Analyze deceptive links, brand spoofing, shortened URLs, or typosquatting.")
        default_url = st.session_state.get("preset_url", "")
        url_input = st.text_input(
            "Target URL",
            value=default_url,
            placeholder="e.g. http://secure-paypal-verify-login.xyz/update-account",
            key="input_url"
        )

        # Realtime quick static preview if URL is provided
        if url_input and url_input.strip():
            quick_check = analyze_url_heuristics(url_input)
            if quick_check["flags"]:
                with st.expander("⚡ Pre-Scan Heuristic Signals Detected", expanded=False):
                    for flag in quick_check["flags"]:
                        st.warning(f"⚠️ {flag}", icon="⚠️")

        if st.button("🚀 Analyze URL Threat", type="primary", key="btn_analyze_url"):
            is_valid, err = validate_url(url_input)
            if not is_valid:
                st.error(f"Validation Error: {err}")
            else:
                submitted_payload = {
                    "type": "url",
                    "data": url_input.strip()
                }

    # --- TAB 2: TEXT MESSAGE / EMAIL ANALYSIS ---
    with tab_text:
        st.markdown("Analyze urgent emails, smishing texts, fake invoices, or impersonation attempts.")
        channels = ["Email Message", "SMS / Smishing Text", "Chat / Direct Message", "Corporate BEC / Invoice"]
        preset_ctx = st.session_state.get("preset_context", "Email Message")
        default_channel_idx = channels.index(preset_ctx) if preset_ctx in channels else 0

        context_type = st.selectbox(
            "Communication Channel",
            channels,
            index=default_channel_idx,
            key="input_text_channel"
        )
        default_body = st.session_state.get("preset_text", "")
        text_input = st.text_area(
            "Message Body or Header Content",
            value=default_body,
            height=160,
            placeholder="Paste suspicious message text, email body, or payment request here...",
            key="input_text_body"
        )

        if st.button("🚀 Analyze Communication Threat", type="primary", key="btn_analyze_text"):
            is_valid, err = validate_text_message(text_input)
            if not is_valid:
                st.error(f"Validation Error: {err}")
            else:
                submitted_payload = {
                    "type": "text",
                    "context": context_type,
                    "data": text_input.strip()
                }

    # --- TAB 3: SCREENSHOT ANALYSIS ---
    with tab_image:
        st.markdown("Upload screenshots of fake login forms, error dialogues, suspicious QR codes, or security warnings.")
        uploaded_file = st.file_uploader(
            "Upload Screenshot (PNG, JPG, WEBP)",
            type=["png", "jpg", "jpeg", "webp"],
            key="input_image_file"
        )
        image_notes = st.text_input(
            "Additional Context (Optional)",
            placeholder="e.g. This popped up while browsing on my phone claiming a virus was found",
            key="input_image_notes"
        )

        if uploaded_file is not None:
            st.image(uploaded_file, caption="Preview of Uploaded Screenshot", use_container_width=True)

        if st.button("🚀 Analyze Visual Threat", type="primary", key="btn_analyze_image"):
            if not uploaded_file:
                st.error("Please upload an image file first.")
            else:
                image_bytes = uploaded_file.getvalue()
                is_valid, err, _ = validate_image_bytes(image_bytes)
                if not is_valid:
                    st.error(f"Validation Error: {err}")
                else:
                    submitted_payload = {
                        "type": "screenshot",
                        "data": image_bytes,
                        "mime_type": uploaded_file.type or "image/png",
                        "notes": image_notes
                    }

    return submitted_payload
