# TrustShield — Your AI Digital Trust Agent

> **Google AI Hackathon:** AI-Powered Cybersecurity, Digital Trust & Consumer Safety  
> **Core Cognitive Engine:** Google Gemini API (`gemini-2.5-flash` via `@google/genai` Python SDK)  
> **UI Layer:** Streamlit Forensic Intelligence Dashboard  

---

## 💡 One-Line Pitch

**TrustShield** is an AI-powered cybersecurity forensic reasoning agent that doesn't just detect suspicious content — it explains the evidence, estimates calibrated risk, reconstructs the adversary's attack lifecycle stage, predicts the attacker's next move, and equips the user with actionable containment steps and deception-free safe replies.

---

## ⚠️ The Problem

Every day, billions of consumers and enterprise employees are bombarded with increasingly sophisticated digital threats:
- **Spear Phishing & Brand Impersonation:** Lookalike banking domains, punycode homographs, and cloned login portals that bypass traditional spam filters.
- **Credential Harvesting:** Deceptive portals engineered to steal enterprise passwords, account pins, and secret keys.
- **OTP & MFA Interception:** Sophisticated smishing and reverse-proxy lures designed to capture real-time 2-factor authentication codes and bypass MFA protections.
- **Malicious Attachments & Executables:** Invoices and shipping notices concealing weaponized macros, disguised executables (`.exe`, `.apk`), or staged payload loaders.
- **Payment & Invoice Scams:** Business Email Compromise (BEC) and urgent wire transfer requests that manipulate human trust.
- **The "Black Box" Detection Problem:** Traditional security software outputs cryptic warnings or binary "Safe/Unsafe" labels. Users **do not understand WHY** something is dangerous, how the attack works, or what concrete steps they should take to protect themselves.

---

## 🛡️ The Solution: Multi-Layer Trust Defense

TrustShield replaces naive binary classifiers with an **explainable digital forensics pipeline**. It functions as an **on-demand security co-pilot**:

1. **Intakes Any Artifact:** URLs, emails, SMS/smishing messages, corporate invoices, and screenshot captures.
2. **Conducts Local Deterministic Forensics:** Evaluates Shannon entropy, domain typosquatting, lookalike banking brands, IP hosts, and keyword patterns.
3. **Applies Google Gemini AI Cognitive Reasoning:** Detects psychological manipulation, brand impersonation, authority pressure, and visual spoofing.
4. **Correlates Forensic Evidence:** Synthesizes independent technical indicators, elevates corroborated signals, and eliminates noise.
5. **Calculates Calibrated Risk with Disagreement Safeguards:** Fuses deterministic and cognitive telemetry while enforcing hard contradiction overrides.
6. **Reconstructs Adversary Attack Chains:** Maps the threat across the 7-stage MITRE ATT&CK lifecycle and forecasts the adversary's next move.
7. **Generates Actionable Defense & Safe Responses:** Delivers plain-English explanations, step-by-step remediation, and deception-free replies.

---

## 🌟 What Makes TrustShield Different

| Capability | Traditional Antivirus / Filters | Naive LLM Wrappers | 🛡️ TrustShield Digital Trust Agent |
| :--- | :--- | :--- | :--- |
| **Artifact Intake** | URLs or Files only | Text only | **Multi-modal (URLs, Messages, SMS, Invoices, Screenshots)** |
| **Engine Architecture** | Static signature database | Black-box prompt | **Dual-Engine: Deterministic Forensics + Gemini Reasoning** |
| **Evidence Corroboration** | None | Hallucinated / Unstructured | **Independent Correlation Engine (`source: combined`)** |
| **Risk Scoring** | Binary (Block / Allow) | Uncalibrated AI rating | **Calibrated 0–100 Fusion with Contradiction Safeguards** |
| **Attack Trajectory** | None | None | **7-Stage MITRE ATT&CK Modeling + Predicted Next Move** |
| **Benign Integrity** | High false positives | Fabricated reasoning | **Clean Non-Fabricating Baseline for Benign Artifacts** |
| **User Empowerment** | "Access Denied" | Generic advice | **Plain-English Summary + Deception-Free Safe Replies** |

### 7 Core Architectural Pillars:
1. **Multi-Modal Artifact Analysis:** Analyzes raw URLs, email headers, SMS smishing lures, payment requests, and image screenshots of fake login dialogs.
2. **Deterministic Local Heuristics + Google Gemini Multimodal Reasoning:** Combines static lexical and domain forensics with deep semantic AI reasoning.
3. **Independent Forensic Evidence Engine (`core/evidence_engine.py`):** Deduplicates signals and generates structured evidence cards showing signal title, severity, confidence, source, and *"Why this matters"*. Corroborated findings are tagged `[Combined]`.
4. **Calibrated Risk Engine with Disagreement Safeguards (`core/risk_engine.py`):** Calculates multi-source risk weights. If an AI model hallucinating safety disagrees with deterministic critical evidence, TrustShield flags `⚠️ MODEL DISAGREEMENT DETECTED` and applies an upward safety override.
5. **MITRE ATT&CK-Aligned Attack Chain Intelligence (`core/attack_chain.py`):** Reconstructs the 7-stage adversarial kill chain and predicts the attacker's trajectory without fabricating attack chains on benign inputs.
6. **Actionable Containment & Deception-Free Safe Reply Generator:** Provides immediate step-by-step containment steps and safe, assertive replies for users needing to disengage without confirming identity or receipt.
7. **Jargon-Free Plain English Explanations:** Translates complex cyber telemetry into understandable language for non-technical users and everyday consumers.

---

## 🏛️ End-to-End Pipeline Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │               1. USER ARTIFACT               │
                    │   (Suspicious URL / Message / Screenshot)   │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │              2. LOCAL FORENSICS              │
                    │   • Shannon Entropy & TLD Reputation         │
                    │   • Punycode & Typosquatting Checks          │
                    │   • Direct IP Hosts & URL Shorteners         │
                    │   • Critical Threat Factor Lexical Scanning  │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │          3. GOOGLE GEMINI REASONING          │
                    │   • Official Google GenAI SDK Client         │
                    │   • Multimodal Visual Threat Inspection      │
                    │   • Cognitive Social Engineering Analysis    │
                    │   • Strict JSON Contract & Fallback Guard    │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │           4. EVIDENCE CORRELATION            │
                    │   • Deduplication & Signal Synthesis         │
                    │   • Dual-Engine Corroboration Detection      │
                    │   • Source Tagging (Local/Gemini/Combined)   │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │             5. RISK ENGINE FUSION            │
                    │   Final Risk = (AI × 0.35) + (Local × 0.35)  │
                    │              + (Stage × 0.15) + High Boost   │
                    │   ⚠️ Contradiction & Safeguard Override      │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │          6. ATTACK CHAIN MODELING            │
                    │   • 7-Stage MITRE ATT&CK Progression         │
                    │   • Forward Adversary Move Prediction        │
                    │   • Attacker Objective Identification        │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
                    ┌──────────────────────────────────────────────┐
                    │           7. ACTION & CONTAINMENT            │
                    │   • Plain-English Executive Summary          │
                    │   • Actionable Remediation Checklist         │
                    │   • Deception-Free Safe Response Stance      │
                    └──────────────────────────────────────────────┘
```

---

## 🤖 Google Gemini Integration Details

TrustShield utilizes Google Gemini (`gemini-2.5-flash`) through the official `google-genai` SDK:

- **Cognitive Social Engineering Detection:** Identifies subtle psychological manipulation triggers (urgency ultimatums, authority impersonation, credential harvesting lures).
- **Multimodal Visual Forensic Analysis:** Ingests raw screenshot bytes (`image/png`, `image/jpeg`, `image/webp`) to inspect fraudulent web interfaces, cloned banking portals, and fake system warnings for visual counterfeit signals.
- **Strict Structured JSON Schema Contract:** The model is constrained to return structured JSON complying with our forensic schema (`threat_type`, `risk_score`, `confidence_score`, `evidence_flags`, `attack_stage`, `predicted_next_move`, `attacker_goal`, `safety_recommendations`, `safe_response`, `plain_english_explanation`).
- **Resilient Fallback Architecture:** If `GEMINI_API_KEY` is unconfigured or the network is unreachable, TrustShield automatically falls back to its deterministic heuristic engine (`Local Forensic Fallback Mode`) without crashing or exposing stack traces.

---

## ⛓️ Attack Chain Intelligence (7-Stage MITRE-Aligned Lifecycle)

TrustShield models cyber attacks across seven standardized phases:

1. **Reconnaissance:** Target profiling, spoofed sender domains, organizational information gathering.
2. **Initial Access:** Delivery of malicious lures via phishing URLs, deceptive SMS texts, or urgent emails.
3. **Credential / Account Capture:** Phishing landing pages soliciting passwords, 2FA/OTP tokens, or secret keys.
4. **Execution / Exploitation:** Weaponized attachments (`.exe`, macros), suspicious file downloads, or drive-by payloads.
5. **Persistence:** Establishing foothold, backdoor installation, scheduled tasks.
6. **Data Theft:** Exfiltration of personal data, corporate intellectual property, or wire fraud.
7. **Account Takeover:** Session hijacking, credential replacement, unauthorized financial liquidation.

### Real-World Attack Progression Examples:
- **Banking Phishing URL:**  
  *Initial Access* → *Credential/Account Capture* → *Account Takeover*  
  *Adversary Prediction:* "The attacker is likely to redirect the victim to a fake login page and attempt to capture credentials."
- **OTP / MFA Intercept:**  
  *Credential / Account Capture* → *Account Takeover*  
  *Adversary Prediction:* "The attacker may attempt to use the captured OTP/MFA code to complete account access and bypass authentication controls."
- **Malicious Attachment:**  
  *Execution / Exploitation* → *Persistence*  
  *Adversary Prediction:* "The attacker is attempting to execute a malicious payload to establish persistence and compromise the host environment."
- **Legitimate / Benign Message:**  
  *Current Stage:* "No malicious activity detected"  
  *Likely Next:* None  
  *Attacker Goal:* "None detected" (No fabricated chain).

---

## 📁 Repository Structure

```
trustshield/
├── app.py                      # Main Streamlit application entrypoint
├── requirements.txt            # Python dependencies (Streamlit, google-genai, etc.)
├── .env.example                # Environment variables template
├── README.md                   # Hackathon project documentation
│
├── core/                       # Core Cybersecurity Intelligence Engine
│   ├── __init__.py
│   ├── analyzer.py             # Pipeline orchestrator & result normalizer
│   ├── gemini.py               # Google Gemini client & multimodal vision prompts
│   ├── risk_engine.py          # Calibrated fusion risk engine & contradiction safeguards
│   ├── evidence_engine.py      # Local signal extractor & dual-engine correlation
│   └── attack_chain.py         # 7-stage MITRE ATT&CK modeling & move prediction
│
├── components/                 # Streamlit UI Presentation Layer
│   ├── __init__.py
│   ├── dashboard.py            # Branding header, engine posture & metrics feed
│   ├── analysis.py             # Multi-modal artifact input forms & demo presets
│   └── report.py               # Forensic evidence cards, risk breakdown & attack chains
│
├── utils/                      # Forensic Utilities & Validation
│   ├── __init__.py
│   ├── url_utils.py            # Entropy, punycode, TLD reputation & homograph checks
│   └── validators.py           # Artifact sanitization & MIME-type validation
│
└── tests/                      # Automated Verification Test Suite
    ├── test_risk_engine.py          # 7 tests: risk fusion, weights, contradiction handling
    ├── test_forensic_evidence.py    # 7 tests: signal extraction & dual correlation
    └── test_attack_chain.py         # 7 tests: 7-stage modeling & benign suppression
```

---

## ⚡ Installation & Quick Start

### 1. Prerequisites
- Python 3.10+
- A Google Gemini API Key from [Google AI Studio](https://aistudio.google.com/)

### 2. Clone & Install Dependencies
```bash
git clone <repository-url>
cd trustshield
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure API Credentials
Copy `.env.example` to `.env` and set your Google Gemini API Key:
```bash
cp .env.example .env
```
In `.env`:
```env
GEMINI_API_KEY="your_actual_gemini_api_key_here"
```
*(Note: If `GEMINI_API_KEY` is omitted, TrustShield automatically operates in Local Forensic Fallback Mode).*

### 4. Launch the Streamlit Dashboard
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 🧪 Comprehensive Verification & Test Suite

TrustShield includes **3 automated test suites** covering **21 deterministic test cases**:

```bash
# 1. Test Risk Intelligence Engine (Fusion, Weights, Contradiction Safeguard)
python3 tests/test_risk_engine.py

# 2. Test Forensic Evidence Engine (Deduplication, Corroboration, Benign Cleanliness)
python3 tests/test_forensic_evidence.py

# 3. Test Attack Chain Intelligence (7-Stage Progression, Predictions, Benign Suppression)
python3 tests/test_attack_chain.py
```

### Verification Results:
- **`tests/test_risk_engine.py`**: **7/7 Passed** (`100%`)
  - Safe Benign Message risk normalization (< 20)
  - Typosquatting Phishing URL risk scaling (High/Critical)
  - Fake Bank Credential Harvesting critical tier (≥ 80)
  - OTP/MFA Phishing threat factor matching
  - Malicious Executable Attachment exploitation weighting
  - Empty Input & Corrupted Payload resilience
  - Contradiction Handling & Safety Override activation
- **`tests/test_forensic_evidence.py`**: **7/7 Passed** (`100%`)
  - Benign artifact non-fabrication (0 false positive items)
  - Multi-signal URL heuristic extraction (7 indicators)
  - Typosquatting detection & brand spoofing identification
  - SMS OTP interception signal extraction
  - Wire fraud & payment diversion signal extraction
  - Executable attachment payload extraction
  - Dual-Engine Signal Deduplication & Composite Correlation
- **`tests/test_attack_chain.py`**: **7/7 Passed** (`100%`)
  - Benign input non-fabrication ("No malicious activity detected")
  - Fake Bank URL Initial Access → Credential Capture progression
  - Credential harvesting Credential Capture → Account Takeover progression
  - OTP Phishing Credential Capture → Account Takeover progression
  - Malicious Executable Execution → Persistence progression
  - Financial Wire Fraud Initial Access → Data Theft progression
  - Multi-Stage 7-node Kill Chain Timeline Generation

**Total Test Suite Status:** **21 / 21 Tests Passing (100% Reliability)**

---

## 🏆 Hackathon Demo Scenarios

TrustShield provides **6 built-in instant demo scenarios** on the top toolbar:

1. **🔗 Phishing URL:** Typosquatted PayPal account verification URL with deceptive subdomains.
2. **🏦 Fake Bank Login:** Chase security verification alert threatening urgent suspension.
3. **🔐 OTP/MFA Phishing:** SMS smishing lure demanding real-time 6-digit one-time passcodes.
4. **📎 Malicious Attachment:** Corporate overdue invoice instructing user to open executable payload.
5. **💰 Payment Scam:** Urgent wire transfer request demanding immediate $45,000 disbursement.
6. **🟢 Benign Message:** Harmless colleague message requesting slides from yesterday's meeting.

Clicking any scenario instantly populates the artifact and runs real-time forensic analysis.

---

## 🔒 Security & Privacy Notice
- TrustShield never transmits sensitive local credentials or environment secrets.
- Deterministic safeguards prevent prompt injection and model evasion.
- Safe response recommendations strictly enforce deceptive disengagement and out-of-band verification.
