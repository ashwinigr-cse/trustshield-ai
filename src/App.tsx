/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Lock,
  ExternalLink,
  Terminal,
  Activity,
  FileSearch,
  MessageSquare,
  Globe,
  Upload,
  ArrowRight,
  Info,
  Copy,
  Check
} from 'lucide-react';

interface ForensicSignal {
  signal: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  explanation: string;
  why_it_matters: string;
  source: 'local' | 'gemini' | 'combined';
}

interface AnalysisResult {
  threat_type: string;
  risk_score: number;
  confidence_score: number;
  severity: string;
  evidence_summary: string;
  forensic_evidence: ForensicSignal[];
  attack_stage: string;
  predicted_next_move: string;
  attacker_goal: string;
  attack_chain: string[];
  safety_recommendations: string[];
  safe_response: string;
  plain_english_explanation: string;
}

const SAMPLE_DATA: Record<string, AnalysisResult> = {
  url: {
    threat_type: "Brand Impersonation & Typosquatting Phishing",
    risk_score: 93,
    confidence_score: 96,
    severity: "Critical",
    evidence_summary: "TrustShield identified 4 independent warning signals (2 Critical, 1 High, 1 Medium).",
    forensic_evidence: [
      {
        signal: "Social-Engineering Credential Lure (Correlated Composite)",
        severity: "critical",
        confidence: 97,
        explanation: "Correlated pattern: Confluence of urgency pressure, authority brand impersonation, and explicit login credential requests.",
        why_it_matters: "Attackers combine urgency and familiar branding so victims enter passwords before thinking critically.",
        source: "combined"
      },
      {
        signal: "Potential Brand Impersonation (PayPal)",
        severity: "critical",
        confidence: 95,
        explanation: "Suspected unauthorized use of brand identity 'PayPal' in deceptive foreign host 'paypa1-security-check.com'.",
        why_it_matters: "Adversaries mimic trusted institutions to exploit user trust and harvest logins on lookalike sites.",
        source: "combined"
      },
      {
        signal: "Typosquatting Character Substitution",
        severity: "high",
        confidence: 92,
        explanation: "Domain substitutes the letter 'l' with the numeral '1' (paypa1), a hallmark visual homograph trick.",
        why_it_matters: "A domain that visually resembles a legitimate brand but is registered to an unknown party is the foundation of phishing infrastructure.",
        source: "local"
      },
      {
        signal: "Security & Credential Keywords in URL",
        severity: "medium",
        confidence: 88,
        explanation: "URL contains credential lure keywords: security, verify, update, signin.",
        why_it_matters: "Legitimate organizations rarely host login forms on hyphenated multi-word ad-hoc domains.",
        source: "local"
      }
    ],
    attack_stage: "Credential/Account Capture",
    predicted_next_move: "Adversary will intercept submitted passwords, immediately query MFA tokens, and initiate unauthorized fund transfers.",
    attacker_goal: "Unauthorized account takeover and credential exfiltration targeting payment balances.",
    attack_chain: [
      "Reconnaissance (Completed)",
      "Initial Access (Completed)",
      "Credential/Account Capture (Active - Current Phase)",
      "Account Takeover (Projected Goal)"
    ],
    safety_recommendations: [
      "Do NOT enter usernames, passwords, or verification codes on this domain.",
      "Close the browser tab immediately and clear cached session cookies.",
      "Log into PayPal directly through the official mobile app or verified https://www.paypal.com bookmark.",
      "If credentials were submitted, immediately reset your password and verify active devices."
    ],
    safe_response: "I will not utilize this link. I will independently authenticate via official organization channels.",
    plain_english_explanation: "This link is an impersonation scam designed to steal your login credentials. It uses a deceptive spelling ('paypa1' instead of 'paypal') to trick you into entering your password on a clone page."
  },
  otp: {
    threat_type: "MFA / OTP Token Theft Campaign",
    risk_score: 89,
    confidence_score: 95,
    severity: "Critical",
    evidence_summary: "TrustShield identified 3 independent warning signals (2 Critical, 1 Medium).",
    forensic_evidence: [
      {
        signal: "High-Pressure MFA/OTP Intercept Campaign (Correlated Composite)",
        severity: "critical",
        confidence: 98,
        explanation: "Correlated pattern: Combines institutional authority impersonation with aggressive pursuit of two-factor authentication bypass tokens.",
        why_it_matters: "One-Time Passcodes (OTPs) and 2FA tokens are your final line of defense. Attackers intercept them in real-time to bypass two-factor authentication.",
        source: "combined"
      },
      {
        signal: "Explicit OTP Disclosure Demand",
        severity: "critical",
        confidence: 96,
        explanation: "Direct solicitation demanding recipient reply with an SMS verification code.",
        why_it_matters: "Legitimate support representatives and IT systems will NEVER ask you to disclose or reply with your private verification code.",
        source: "combined"
      },
      {
        signal: "Artificial Urgency & Threat Pressure",
        severity: "medium",
        confidence: 85,
        explanation: "Demands compliance 'within 15 minutes' to prevent punitive account termination.",
        why_it_matters: "Artificial deadlines force users to rush and bypass rational verification.",
        source: "local"
      }
    ],
    attack_stage: "Credential/Account Capture",
    predicted_next_move: "Attacker will feed the captured OTP token into their live login session, completing account takeover.",
    attacker_goal: "Bypassing multi-factor authentication (MFA) to compromise corporate access.",
    attack_chain: [
      "Reconnaissance (Completed)",
      "Initial Access (Completed)",
      "Credential/Account Capture (Active - Current Phase)",
      "Lateral Movement / Data Theft (Projected Goal)"
    ],
    safety_recommendations: [
      "NEVER share or forward verification codes to anyone.",
      "Report the telephone number or sender to your IT security department.",
      "Review multi-factor authentication logs for unauthorized sign-in attempts."
    ],
    safe_response: "I will not disclose verification codes. I am reporting this incident to corporate cybersecurity operations.",
    plain_english_explanation: "Someone is attempting to log into your account and needs the verification code sent to your phone to finish signing in. Never tell anyone your code—doing so hands them complete control of your account."
  },
  safe: {
    threat_type: "Legitimate / Unflagged Communication",
    risk_score: 4,
    confidence_score: 92,
    severity: "Safe",
    evidence_summary: "🟢 No significant malicious indicators detected. Note: Absence of known indicators reduces probability of threat but does not guarantee absolute safety.",
    forensic_evidence: [],
    attack_stage: "Reconnaissance (Benign Baseline)",
    predicted_next_move: "No adversarial progression detected.",
    attacker_goal: "Normal legitimate interaction.",
    attack_chain: [
      "Benign Baseline Communication"
    ],
    safety_recommendations: [
      "No remediation required.",
      "Standard digital hygiene: continue verifying senders before sharing confidential data."
    ],
    safe_response: "Thank you for the update, see you then!",
    plain_english_explanation: "This message contains no deceptive patterns, artificial urgency, credential solicitations, or malicious links. It appears to be standard legitimate communication."
  }
};

export default function App() {
  const [activeTab, setActiveTab] = useState<'url' | 'text' | 'screenshot'>('url');
  const [inputVal, setInputVal] = useState('https://paypa1-security-check.com/update-login');
  const [activeResult, setActiveResult] = useState<AnalysisResult>(SAMPLE_DATA.url);
  const [isCopied, setIsCopied] = useState(false);

  const handleRunSample = (sampleKey: 'url' | 'otp' | 'safe') => {
    setActiveResult(SAMPLE_DATA[sampleKey]);
    if (sampleKey === 'url') {
      setActiveTab('url');
      setInputVal('https://paypa1-security-check.com/update-login');
    } else if (sampleKey === 'otp') {
      setActiveTab('text');
      setInputVal('URGENT: Microsoft Security has sent an OTP code to your phone. Reply with the 6-digit verification code immediately to prevent account suspension.');
    } else {
      setActiveTab('text');
      setInputVal('Good morning team, let us meet for project sync at 2pm in conference room B.');
    }
  };

  const copyResponse = () => {
    navigator.clipboard.writeText(activeResult.safe_response);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  const getSeverityBadge = (sev: string) => {
    const s = sev.toLowerCase();
    if (s === 'critical') return 'bg-red-500/10 text-red-400 border-red-500/30';
    if (s === 'high') return 'bg-orange-500/10 text-orange-400 border-orange-500/30';
    if (s === 'medium') return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30';
    if (s === 'low') return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
    return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-blue-600 selection:text-white">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-50 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400 shadow-lg shadow-blue-500/10">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl font-bold tracking-tight text-white">TRUSTSHIELD</h1>
                <span className="px-2 py-0.5 text-xs font-semibold rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                  AI Digital Trust Agent
                </span>
              </div>
              <p className="text-xs text-slate-400">Cybersecurity Forensic Reasoning & Risk Intelligence Engine</p>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <div className="hidden sm:flex items-center space-x-2 px-3 py-1.5 rounded-md bg-slate-800/80 border border-slate-700/60 text-xs text-slate-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>Gemini AI Engine Online</span>
            </div>
            <div className="text-xs text-slate-400 border-l border-slate-800 pl-3">
              Streamlit + Python Architecture
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* Architecture Banner */}
        <div className="mb-8 p-4 rounded-xl bg-slate-900/50 border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <Activity className="w-5 h-5 text-blue-400 shrink-0" />
            <div className="text-xs text-slate-300">
              <span className="font-semibold text-white">Pipeline Architecture: </span>
              User Input → Local Forensics → Gemini Reasoning → Evidence Correlation → Risk Engine → Verdict
            </div>
          </div>
          <div className="flex items-center space-x-2 text-xs">
            <span className="text-slate-400">Load Test Samples:</span>
            <button
              onClick={() => handleRunSample('url')}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 transition"
            >
              Phishing URL
            </button>
            <button
              onClick={() => handleRunSample('otp')}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 transition"
            >
              OTP Intercept
            </button>
            <button
              onClick={() => handleRunSample('safe')}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-emerald-400 transition"
            >
              Benign Safe
            </button>
          </div>
        </div>

        {/* Input Interface */}
        <section className="mb-10 bg-slate-900/40 rounded-xl border border-slate-800 p-6">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4 flex items-center space-x-2">
            <FileSearch className="w-4 h-4 text-blue-400" />
            <span>Artifact Inspection Intake</span>
          </h2>

          <div className="flex space-x-2 border-b border-slate-800 mb-4">
            <button
              onClick={() => setActiveTab('url')}
              className={`pb-3 px-4 text-xs font-medium border-b-2 transition flex items-center space-x-2 ${
                activeTab === 'url' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Suspicious URL</span>
            </button>
            <button
              onClick={() => setActiveTab('text')}
              className={`pb-3 px-4 text-xs font-medium border-b-2 transition flex items-center space-x-2 ${
                activeTab === 'text' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <MessageSquare className="w-3.5 h-3.5" />
              <span>Email / SMS Message</span>
            </button>
            <button
              onClick={() => setActiveTab('screenshot')}
              className={`pb-3 px-4 text-xs font-medium border-b-2 transition flex items-center space-x-2 ${
                activeTab === 'screenshot' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Screenshot / Image Lure</span>
            </button>
          </div>

          <div className="space-y-4">
            {activeTab === 'url' && (
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">Target Web Address</label>
                <input
                  type="text"
                  value={inputVal}
                  onChange={(e) => setInputVal(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500 transition font-mono"
                  placeholder="https://suspicious-domain.xyz/login"
                />
              </div>
            )}

            {activeTab === 'text' && (
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">Communication Body / Email Header</label>
                <textarea
                  value={inputVal}
                  onChange={(e) => setInputVal(e.target.value)}
                  rows={3}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-blue-500 transition"
                  placeholder="Paste message or email content..."
                />
              </div>
            )}

            {activeTab === 'screenshot' && (
              <div className="border border-dashed border-slate-800 rounded-lg p-8 text-center bg-slate-950/50">
                <Upload className="w-8 h-8 text-slate-500 mx-auto mb-2" />
                <p className="text-xs text-slate-400">Upload screenshot for multi-modal visual inspection (PNG, JPG, WEBP)</p>
                <span className="text-[11px] text-slate-600 block mt-1">Processed natively via Gemini Vision API</span>
              </div>
            )}

            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-slate-500">Live inspection engine running in core/analyzer.py</span>
              <button
                onClick={() => {}}
                className="px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs shadow-lg shadow-blue-600/20 transition flex items-center space-x-2"
              >
                <span>Run Forensic Cognitive Scan</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </section>

        {/* Forensic Report Display */}
        <section className="space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Assessment Verdict</span>
              <h3 className="text-xl font-bold text-white mt-1">{activeResult.threat_type}</h3>
            </div>
            <div className="flex items-center space-x-4">
              <div className="text-right">
                <div className="text-xs text-slate-400">Risk Score</div>
                <div className="text-2xl font-black text-red-400">
                  {activeResult.risk_score} <span className="text-xs font-normal text-slate-500">/ 100</span>
                </div>
              </div>
              <div className="text-right border-l border-slate-800 pl-4">
                <div className="text-xs text-slate-400">Confidence</div>
                <div className="text-2xl font-black text-blue-400">{activeResult.confidence_score}%</div>
              </div>
            </div>
          </div>

          {/* Plain English Summary */}
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-sm text-slate-300 leading-relaxed flex items-start space-x-3">
            <Info className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
            <div>
              <div className="font-semibold text-white text-xs mb-1 uppercase tracking-wider">Plain-English Translation</div>
              <p>{activeResult.plain_english_explanation}</p>
            </div>
          </div>

          {/* Forensic Evidence Section */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-sm font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-blue-400" />
                <span>Forensic Evidence Cards</span>
              </h4>
              <span className="text-xs text-slate-400">{activeResult.evidence_summary}</span>
            </div>

            {activeResult.forensic_evidence.length > 0 ? (
              <div className="grid gap-3">
                {activeResult.forensic_evidence.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-lg bg-slate-900/40 border border-slate-800/80 hover:border-slate-700 transition"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="font-semibold text-sm text-white flex items-center space-x-2">
                        <span>{item.signal}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${getSeverityBadge(item.severity)}`}>
                          {item.severity.toUpperCase()}
                        </span>
                        <span className="text-xs text-slate-400">Confidence: {item.confidence}%</span>
                        <span className="text-[11px] text-slate-500 uppercase">[{item.source}]</span>
                      </div>
                    </div>
                    <p className="text-xs text-slate-300 mb-2 leading-relaxed">{item.explanation}</p>
                    <div className="p-2.5 rounded bg-slate-950/60 text-xs text-slate-400 border border-slate-800/50">
                      <span className="font-semibold text-blue-400">💡 Why this matters: </span>
                      {item.why_it_matters}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-xs">
                🟢 No significant malicious indicators detected. Absence of indicators reduces threat probability but does not guarantee absolute safety.
              </div>
            )}
          </div>

          {/* Attack Chain & Predictive Trajectory */}
          <div className="grid md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Identified Attack Stage
              </div>
              <div className="text-sm font-bold text-white mb-3 flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded-full bg-red-400 animate-ping"></span>
                <span>{activeResult.attack_stage}</span>
              </div>
              <div className="space-y-1.5 text-xs text-slate-400">
                {activeResult.attack_chain.map((chainItem, idx) => (
                  <div key={idx} className="flex items-center space-x-2">
                    <span className="text-slate-600">⛓️</span>
                    <span className={chainItem.includes('Active') ? 'text-red-400 font-semibold' : ''}>
                      {chainItem}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Predicted Attacker Next Move
              </div>
              <p className="text-xs text-slate-300 mb-3 leading-relaxed">
                {activeResult.predicted_next_move}
              </p>
              <div className="text-xs text-slate-400 border-t border-slate-800/80 pt-2.5">
                <span className="font-semibold text-slate-300">Target Objective: </span>
                {activeResult.attacker_goal}
              </div>
            </div>
          </div>

          {/* Recommendations & Safe Response */}
          <div className="grid md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800">
              <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
                Actionable Containment Steps
              </h5>
              <ul className="space-y-2 text-xs text-slate-300">
                {activeResult.safety_recommendations.map((step, idx) => (
                  <li key={idx} className="flex items-start space-x-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{step}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 flex flex-col justify-between">
              <div>
                <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  Safe Deception-Free Response
                </h5>
                <p className="text-xs text-slate-400 mb-2">
                  Use this canned, neutral reply to disengage or verify safely:
                </p>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono">
                  "{activeResult.safe_response}"
                </div>
              </div>
              <button
                onClick={copyResponse}
                className="mt-3 w-full py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 transition flex items-center justify-center space-x-1.5"
              >
                {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{isCopied ? "Copied to Clipboard!" : "Copy Safe Response"}</span>
              </button>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 mt-16 py-6 text-center text-xs text-slate-500">
        <p>TRUSTSHIELD — AI-Powered Cybersecurity & Digital Safety Hackathon Project</p>
        <p className="mt-1">Powered by Google Gemini API & Multi-Tier Independent Risk Intelligence Engine</p>
      </footer>
    </div>
  );
}
