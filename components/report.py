"""
TRUSTSHIELD - Forensic Report UI Component
Renders comprehensive threat reports satisfying all 10 core cybersecurity capabilities.
"""

from typing import Dict, Any
import streamlit as st


def render_threat_report(report: Dict[str, Any]):
    """
    Renders an interactive, comprehensive cybersecurity trust report:
    1. Threat Classification
    2. Risk Score (0-100)
    3. Confidence Score
    4. Evidence / Red Flags
    5. Attack-Stage Identification
    6. Predicted Attacker Next Move
    7. Attack Chain Visualization
    8. Actionable Safety Recommendations
    9. Safe Response Generation
    10. Clear, Beginner-Friendly Explanation
    """
    risk_info = report.get("risk_profile", {})
    risk_score = report.get("risk_score", risk_info.get("risk_score", 0))
    confidence = report.get("confidence_score", risk_info.get("confidence_score", 0))
    
    # Derive risk tier if not explicitly present
    risk_tier = risk_info.get("risk_tier")
    if not risk_tier:
        if risk_score < 20:
            risk_tier = "Safe"
        elif risk_score < 45:
            risk_tier = "Low"
        elif risk_score < 70:
            risk_tier = "Medium"
        elif risk_score < 88:
            risk_tier = "High"
        else:
            risk_tier = "Critical"

    # Color code risk tiers
    tier_colors = {
        "Safe": "#10b981",       # green
        "Low": "#06b6d4",        # cyan
        "Medium": "#f59e0b",     # amber
        "High": "#ef4444",       # red
        "Critical": "#7f1d1d",   # dark red
    }
    tier_color = tier_colors.get(risk_tier, "#ef4444")

    threat_title = report.get("threat_type") or report.get("threat_classification") or "Threat Assessment"
    target_value = report.get("input_preview") or report.get("artifact_value") or "Target Artifact"
    is_fallback = report.get("is_fallback", False)
    analysis_mode = report.get("analysis_mode", "AI Cognitive Analysis")
    attacker_goal = report.get("attacker_goal")

    st.markdown("---")
    st.markdown("## 📋 Forensic Trust Assessment Report")

    # Mode indicator distinguishing AI analysis from fallback
    if is_fallback:
        st.warning(
            f"⚠️ **Analysis Mode: {analysis_mode}** — Gemini API is currently offline or unconfigured. Displaying heuristic baseline scan. Configure `GEMINI_API_KEY` for deep cognitive AI reasoning.",
            icon="ℹ️"
        )
    else:
        st.success(
            f"✨ **Analysis Mode: {analysis_mode}** — Real-time multi-modal cyber reasoning powered by Google Gemini.",
            icon="🛡️"
        )

    # Disagreement / Contradiction Alert
    if report.get("analysis_disagreement"):
        st.warning(
            f"⚠️ **Forensic Disagreement Flagged:** {report.get('disagreement_reason')}",
            icon="⚖️"
        )

    # --- 1, 2, 3: CLASSIFICATION, RISK GAUGE, CONFIDENCE ---
    c1, c2, c3 = st.columns([2, 1, 1])

    with c1:
        st.markdown(f"### **{threat_title}**")
        st.markdown(f"**Target Artifact:** `{target_value}`")
        if attacker_goal:
            st.markdown(f"🎯 **Attacker Goal:** *{attacker_goal}*")
        st.markdown(
            f"""
            <span style="background-color: {tier_color}22; color: {tier_color}; border: 1px solid {tier_color}; border-radius: 6px; padding: 4px 10px; font-weight: 700; font-size: 0.9rem;">
                ● {risk_tier.upper()} SEVERITY
            </span>
            """,
            unsafe_allow_html=True
        )

    with c2:
        st.metric(
            label="Risk Score (0-100)",
            value=f"{risk_score} / 100",
            delta=f"Severity: {risk_tier}"
        )
        st.progress(min(1.0, max(0.0, risk_score / 100.0)))

    with c3:
        st.metric(
            label="Forensic Confidence",
            value=f"{confidence}%",
            delta="Calibrated"
        )
        st.progress(min(1.0, max(0.0, confidence / 100.0)))

    # Risk Intelligence Reasoning Breakdown
    if report.get("reasoning") or report.get("risk_factors"):
        with st.expander("🔬 TrustShield Risk Intelligence Breakdown", expanded=False):
            if report.get("reasoning"):
                st.markdown(f"```text\n{report.get('reasoning')}\n```")
            if report.get("risk_factors"):
                st.markdown("**Identified Risk Factors:**")
                for rf in report.get("risk_factors", []):
                    st.markdown(f"- 🔸 {rf}")

    st.markdown("---")

    # --- 10: PLAIN-ENGLISH BEGINNER FRIENDLY EXPLANATION ---
    st.subheader("💡 Beginner-Friendly Summary (Plain English)")
    plain_explanation = report.get(
        "plain_english_explanation",
        "This artifact has been evaluated for deceptive indicators, identity spoofing, and digital threats."
    )
    st.info(plain_explanation, icon="ℹ️")

    # --- 4: FORENSIC EVIDENCE & RED FLAGS ---
    st.subheader("🔎 FORENSIC EVIDENCE")

    forensic_items = report.get("forensic_evidence", [])
    evidence_summary = report.get("evidence_summary")

    # If no structured forensic_items, check if string flags exist
    if not forensic_items:
        legacy_flags = report.get("evidence_flags") or report.get("red_flags") or []
        for f in legacy_flags:
            forensic_items.append({
                "signal": "Observed Security Indicator",
                "severity": "medium",
                "confidence": 85,
                "explanation": str(f),
                "why_it_matters": "Deceptive patterns or technical anomalies are frequently leveraged in cyber attacks.",
                "source": "local"
            })

    if forensic_items:
        crit_count = sum(1 for e in forensic_items if e.get("severity") == "critical")
        high_count = sum(1 for e in forensic_items if e.get("severity") == "high")
        med_count = sum(1 for e in forensic_items if e.get("severity") == "medium")
        low_count = sum(1 for e in forensic_items if e.get("severity") == "low")
        total_signals = len(forensic_items)

        # Evidence Summary Bar
        st.markdown(
            f"""
            <div style="background: rgba(15, 23, 42, 0.6); border-left: 4px solid #ef4444; border-radius: 6px; padding: 10px 14px; margin-bottom: 14px;">
                <div style="font-size: 0.95rem; font-weight: 600; color: #f8fafc;">
                    🛡️ TrustShield identified {total_signals} independent warning signal{'s' if total_signals != 1 else ''}
                </div>
                <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px; display: flex; gap: 14px;">
                    <span style="color: #ef4444; font-weight: bold;">🔴 Critical: {crit_count}</span>
                    <span style="color: #f97316; font-weight: bold;">🟠 High: {high_count}</span>
                    <span style="color: #eab308; font-weight: bold;">🟡 Medium: {med_count}</span>
                    <span style="color: #38bdf8; font-weight: bold;">🔵 Low: {low_count}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        sev_colors = {
            "critical": ("#ef4444", "🔴 CRITICAL"),
            "high": ("#f97316", "🟠 HIGH"),
            "medium": ("#eab308", "🟡 MEDIUM"),
            "low": ("#38bdf8", "🔵 LOW"),
        }

        # Render structured cards
        for idx, item in enumerate(forensic_items, start=1):
            sev_key = item.get("severity", "medium").lower()
            color, sev_label = sev_colors.get(sev_key, ("#94a3b8", "⚪ UNKNOWN"))
            signal_name = item.get("signal", f"Signal #{idx}")
            item_confidence = item.get("confidence", 85)
            explanation_text = item.get("explanation", "")
            why_text = item.get("why_it_matters", "")
            raw_source = str(item.get("source", "verified")).lower()
            is_combined = raw_source in ("combined", "corroborated")

            source_label = "🤝 Combined / Corroborated" if is_combined else f"[{raw_source.capitalize()}]"

            corroboration_banner = ""
            if is_combined:
                corroboration_banner = """
                <div style="margin-top: 6px; margin-bottom: 6px; background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 4px; padding: 4px 8px; font-size: 0.76rem; color: #60a5fa; font-weight: 600;">
                    🤝 Dual Engine Corroboration: Independently validated by both Local Heuristic Forensics and Google Gemini AI.
                </div>
                """

            st.markdown(
                f"""
                <div style="background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(148, 163, 184, 0.15); border-left: 4px solid {color}; border-radius: 8px; padding: 12px 16px; margin-bottom: 12px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <span style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">
                            {signal_name}
                        </span>
                        <div style="display: flex; gap: 8px; align-items: center;">
                            <span style="background: {color}22; color: {color}; border: 1px solid {color}44; border-radius: 4px; padding: 2px 6px; font-size: 0.75rem; font-weight: 700;">
                                {sev_label}
                            </span>
                            <span style="background: rgba(148, 163, 184, 0.1); color: #cbd5e1; border-radius: 4px; padding: 2px 6px; font-size: 0.75rem;">
                                Confidence: {item_confidence}%
                            </span>
                            <span style="color: {'#60a5fa' if is_combined else '#94a3b8'}; font-size: 0.72rem; font-weight: 600;">
                                {source_label}
                            </span>
                        </div>
                    </div>
                    {corroboration_banner}
                    <div style="color: #cbd5e1; font-size: 0.88rem; margin-bottom: 8px; line-height: 1.4;">
                        {explanation_text}
                    </div>
                    <div style="background: rgba(15, 23, 42, 0.4); border-radius: 6px; padding: 8px 10px; font-size: 0.8rem; color: #94a3b8;">
                        <strong style="color: #38bdf8;">💡 Why this matters:</strong> {why_text}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
    else:
        st.markdown(
            """
            <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 8px; padding: 14px 16px; margin-bottom: 12px;">
                <div style="color: #10b981; font-weight: 700; font-size: 0.95rem; margin-bottom: 4px;">
                    🟢 No significant malicious indicators detected.
                </div>
                <div style="color: #94a3b8; font-size: 0.85rem; line-height: 1.4;">
                    Our multi-layer forensic inspection found no suspicious keywords, brand typosquatting, credential lures, or abnormal domain patterns.
                    <em>Note: The absence of indicators reduces the probability of a threat, but does not guarantee absolute safety. Always verify sensitive requests through established channels.</em>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")

    # --- RISK INTELLIGENCE & CONTRADICTION SAFEGUARD ---
    st.subheader("🧠 TRUSTSHIELD RISK INTELLIGENCE")

    # Disagreement Safeguard Display
    if report.get("analysis_disagreement"):
        st.markdown(
            f"""
            <div style="background: rgba(239, 68, 68, 0.12); border: 2px solid #ef4444; border-radius: 8px; padding: 12px 16px; margin-bottom: 14px;">
                <div style="color: #ef4444; font-weight: 800; font-size: 1rem; display: flex; align-items: center; gap: 6px;">
                    ⚠️ MODEL DISAGREEMENT DETECTED
                </div>
                <div style="color: #fca5a5; font-size: 0.88rem; margin-top: 4px; line-height: 1.4;">
                    {report.get('disagreement_reason', 'Disagreement between AI cognitive model and deterministic local forensic checks.')}
                </div>
                <div style="color: #fecaca; font-size: 0.8rem; margin-top: 6px; font-weight: 600;">
                    🛡️ Deterministic Safety Override Applied: The final risk score was calibrated upward to protect user safety and prevent malicious evasion.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Risk factor and reasoning breakdown
    r1, r2 = st.columns([1, 1])
    with r1:
        st.markdown(f"**Final Evaluated Risk Score:** `{risk_score}/100` ({risk_tier} Severity)")
        st.markdown(f"**Forensic Confidence Rating:** `{confidence}%`")
        if is_fallback:
            st.markdown("- **Local Forensics Contribution:** `65%` (Deterministic Baseline)")
            st.markdown("- **Attack-Stage Contribution:** `20%`")
            st.markdown("- **High-Severity Factor Boost:** Included")
        else:
            st.markdown("- **Google Gemini AI Contribution:** `35%` (Cognitive Deception Analysis)")
            st.markdown("- **Local Forensics Contribution:** `35%` (Deterministic Static Checks)")
            st.markdown("- **Attack-Stage Contribution:** `15%`")
            st.markdown("- **High-Severity Factor Boost:** Included")

    with r2:
        if report.get("risk_factors"):
            st.markdown("**Identified Threat Factors:**")
            for rf in report.get("risk_factors", []):
                st.markdown(f"- 🔸 {rf}")
        else:
            st.markdown("**Identified Threat Factors:**")
            st.markdown("🟢 No high-weight threat factors matched.")

    if report.get("reasoning"):
        with st.expander("🔬 View Detailed Risk Engine Reasoning", expanded=False):
            st.text(report.get("reasoning"))

    st.markdown("---")

    # --- 5, 6, 7: ATTACK CHAIN INTELLIGENCE ---
    st.subheader("⛓️ ATTACK CHAIN INTELLIGENCE")
    
    attack_chain_obj = report.get("attack_chain") or report.get("attack_chain_timeline") or {}
    if not isinstance(attack_chain_obj, dict):
        attack_chain_obj = {}

    current_stage = attack_chain_obj.get("current_stage") or report.get("attack_stage", "Initial Access")
    likely_next = attack_chain_obj.get("likely_next_stage", "")
    pred_move = attack_chain_obj.get("predicted_next_move") or report.get("predicted_next_move", "No malicious next move identified")
    att_goal = attack_chain_obj.get("attacker_goal") or report.get("attacker_goal", "None detected")
    pred_conf = attack_chain_obj.get("prediction_confidence", confidence)

    # Key Stage Metrics
    ac1, ac2 = st.columns(2)
    with ac1:
        st.markdown(f"**Current Attack Stage:**")
        if "no malicious" in str(current_stage).lower():
            st.success(f"🟢 **{current_stage}**")
        else:
            st.warning(f"📍 **{current_stage}**")
        
        if likely_next:
            st.markdown(f"**Likely Next Stage:**")
            st.info(f"⏭️ **{likely_next}**")

    with ac2:
        st.markdown(f"**Predicted Attacker Move:**")
        if "no malicious" in str(pred_move).lower():
            st.success(f"🟢 **{pred_move}**")
        else:
            st.error(f"⚡ **{pred_move}**")

        st.markdown(f"**Attacker Goal:** *{att_goal}* | **Prediction Confidence:** `{pred_conf}%`")

    # 7-Stage Attack Lifecycle Visualizer
    attack_chain_data = attack_chain_obj.get("timeline", [])
    if not attack_chain_data and isinstance(report.get("timeline"), list):
        attack_chain_data = report.get("timeline")

    if attack_chain_data:
        st.markdown("<br/><strong>7-Stage MITRE-Aligned Lifecycle Progression:</strong>", unsafe_allow_html=True)
        stage_cols = st.columns(len(attack_chain_data))
        for idx, node in enumerate(attack_chain_data):
            stage_name = node.get("stage_name", f"Stage {idx+1}")
            status = node.get("status", "projected")
            is_cur = node.get("is_current", False)

            with stage_cols[idx]:
                if is_cur:
                    st.markdown(
                        f"""
                        <div style="background: rgba(239, 68, 68, 0.2); border: 2px solid #ef4444; color: #f8fafc; padding: 8px 4px; border-radius: 6px; text-align: center; min-height: 85px;">
                            <span style="background: #ef4444; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: 800; display: inline-block; margin-bottom: 4px;">CURRENT</span>
                            <div style="font-size: 0.74rem; font-weight: 700; color: #fca5a5; line-height: 1.2;">{stage_name}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                elif likely_next and (likely_next.lower() in stage_name.lower() or stage_name.lower() in likely_next.lower()):
                    st.markdown(
                        f"""
                        <div style="background: rgba(245, 158, 11, 0.15); border: 1px solid #f59e0b; color: #f8fafc; padding: 8px 4px; border-radius: 6px; text-align: center; min-height: 85px;">
                            <span style="background: #f59e0b; color: #1e293b; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: 800; display: inline-block; margin-bottom: 4px;">LIKELY NEXT</span>
                            <div style="font-size: 0.74rem; font-weight: 600; color: #fde68a; line-height: 1.2;">{stage_name}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                elif status == "completed":
                    st.markdown(
                        f"""
                        <div style="background: rgba(59, 130, 246, 0.15); border: 1px solid #3b82f6; color: #cbd5e1; padding: 8px 4px; border-radius: 6px; text-align: center; min-height: 85px;">
                            <span style="background: #3b82f6; color: white; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: 700; display: inline-block; margin-bottom: 4px;">OBSERVED</span>
                            <div style="font-size: 0.74rem; font-weight: 600; color: #bfdbfe; line-height: 1.2;">{stage_name}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                elif status == "inactive":
                    st.markdown(
                        f"""
                        <div style="background: rgba(15, 23, 42, 0.4); border: 1px solid #1e293b; color: #475569; padding: 8px 4px; border-radius: 6px; text-align: center; min-height: 85px;">
                            <span style="background: #1e293b; color: #64748b; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: 600; display: inline-block; margin-bottom: 4px;">INACTIVE</span>
                            <div style="font-size: 0.74rem; color: #64748b; line-height: 1.2;">{stage_name}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                else:
                    st.markdown(
                        f"""
                        <div style="background: rgba(30, 41, 59, 0.4); border: 1px solid rgba(148, 163, 184, 0.1); color: #94a3b8; padding: 8px 4px; border-radius: 6px; text-align: center; min-height: 85px;">
                            <span style="background: #1e293b; color: #94a3b8; padding: 2px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: 600; display: inline-block; margin-bottom: 4px;">PROJECTED</span>
                            <div style="font-size: 0.74rem; color: #94a3b8; line-height: 1.2;">{stage_name}</div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

    st.markdown("---")

    # --- 8: ACTIONABLE RECOMMENDATIONS ---
    st.subheader("🛡️ WHAT SHOULD YOU DO? (Containment & Action)")
    recommendations = report.get("safety_recommendations", [])
    if recommendations:
        for i, step in enumerate(recommendations, start=1):
            st.markdown(f"**Step {i}:** {step}")
    else:
        st.write("No remediation needed at this time.")

    # --- 9: SAFE RESPONSE GENERATION ---
    st.subheader("💬 Deception-Free Safe Response")
    st.markdown(
        "Need to reply or safely disengage without exposing sensitive credentials or confirming receipt? Use this AI-curated response stance:"
    )
    safe_response = report.get("safe_response", "Do not reply. Delete communication immediately.")
    st.code(safe_response, language="text")
