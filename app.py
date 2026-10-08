"""
TRUSTSHIELD - AI Digital Trust & Cybersecurity Agent
Main Streamlit Application Entrypoint
"""

import os
import streamlit as st
# Load environment configuration safely
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from core.analyzer import analyze_input, analyzer_engine
from core.gemini import gemini_engine
from components.dashboard import render_dashboard_header, render_stats_metrics
from components.analysis import render_analysis_inputs
from components.report import render_threat_report

# Configure Streamlit page
st.set_page_config(
    page_title="TrustShield — AI Digital Trust Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply sleek security aesthetic styling
st.markdown(
    """
    <style>
    .main {
        background-color: #0b0f19;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 48px;
        border-radius: 6px 6px 0 0;
        padding-left: 16px;
        padding-right: 16px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

def main():
    # Render top dashboard branding
    render_dashboard_header()

    # Sidebar: System status, configuration & methodology
    with st.sidebar:
        st.header("⚙️ Agent Controls")
        
        # Check API key status
        if gemini_engine.is_configured:
            st.success("API Key Attached (Environment)", icon="🔒")
            st.markdown(
                """
                <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.35); border-radius: 6px; padding: 8px 10px; margin-top: 4px; margin-bottom: 8px; font-size: 0.82rem; color: #34d399; font-weight: 600;">
                    🟢 Gemini AI Reasoning: ACTIVE<br/>
                    <span style="font-size: 0.74rem; color: #a7f3d0; font-weight: 400;">Powered by Google Gemini</span>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.warning("GEMINI_API_KEY not configured in .env file.", icon="⚠️")
            st.markdown(
                """
                <div style="background: rgba(234, 179, 8, 0.15); border: 1px solid rgba(234, 179, 8, 0.35); border-radius: 6px; padding: 8px 10px; margin-top: 4px; margin-bottom: 8px; font-size: 0.82rem; color: #facc15; font-weight: 600;">
                    🟡 Local Forensic Fallback<br/>
                    <span style="font-size: 0.74rem; color: #fef08a; font-weight: 400;">Deterministic Heuristic Engine Active</span>
                </div>
                """,
                unsafe_allow_html=True
            )
            st.caption("Add `GEMINI_API_KEY=\"your_key\"` to your `.env` file to enable live cognitive reasoning.")

        st.markdown("---")
        st.subheader("🛡️ TrustShield Capabilities")
        st.markdown(
            """
            - **Threat Classification**
            - **Risk Scoring (0-100)**
            - **Confidence Rating**
            - **Forensic Red Flags**
            - **Attack-Stage Mapping**
            - **Predictive Adversary Moves**
            - **Attack Chain Forensics**
            - **Actionable Defense Steps**
            - **Safe Response Generator**
            - **Plain-English Explanations**
            """
        )
        st.markdown("---")
        st.caption("Hackathon Challenge: AI-Powered Cybersecurity & Digital Safety")
        st.caption("Engine: Google Gemini API")

    # Render summary metrics
    render_stats_metrics()

    # Render artifact input tabs
    submitted = render_analysis_inputs()

    # Process submission when triggered
    if submitted:
        with st.spinner("🤖 TrustShield AI Agent is conducting forensic cognitive analysis..."):
            try:
                # Primary analysis through core.analyzer.analyze_input
                report = analyze_input(submitted)

                if report:
                    # Save into session state for persistence
                    st.session_state["latest_report"] = report
            except Exception as e:
                st.error("Analysis could not be completed. Please check your input and try again.")

    # Render latest report if present in session state
    if "latest_report" in st.session_state:
        render_threat_report(st.session_state["latest_report"])


if __name__ == "__main__":
    main()
