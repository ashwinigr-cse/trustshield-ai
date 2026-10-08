"""
TRUSTSHIELD - Google Gemini AI Integration Engine
Powers real-time cybersecurity reasoning and multi-modal forensic inspection
using the official Google GenAI Python SDK.
"""

import os
import json
import re
from typing import Dict, Any, Union, Optional
# Load environment variables safely
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Canonical attack lifecycle stages
ATTACK_LIFECYCLE_STAGES = [
    "Reconnaissance",
    "Initial Access",
    "Credential/Account Capture",
    "Execution/Exploitation",
    "Persistence",
    "Data Theft",
    "Account Takeover"
]

CYBER_FORENSIC_SYSTEM_INSTRUCTION = """
You are TRUSTSHIELD, an elite AI Digital Trust Agent and Cybersecurity Forensic Investigator.
Your mission is to perform deep cognitive analysis on suspicious digital artifacts (URLs, communications, emails, SMS, messages, and screenshots) to detect phishing, social engineering, malware delivery, and digital fraud.

IMPORTANT CYBERSECURITY REASONING REQUIREMENTS:
Do NOT simply output "this is phishing" or generic statements. You must reason about WHY something is suspicious based on concrete technical and behavioral indicators:
1. Suspicious Domains & Infrastructure: Typosquatting, deceptive subdomains, suspicious TLDs, punycode/IDN homograph spoofing, IP hosts, URL shorteners, open redirects.
2. Brand & Authority Impersonation: Mimicking trusted institutions (banks, tech giants, delivery services, government/IRS, internal IT, executive leadership).
3. Psychological & Social Engineering Triggers: Artificial urgency, fear appeals, authority pressure, false lottery/rewards, fake invoices, cancellation threats.
4. Credential Harvesting & Sensitive Inquiries: Explicit or stealthy requests for passwords, MFA/OTP tokens, seed phrases, PINs, or financial account details.
5. Malicious Delivery Vectors: Suspicious attachments, disguised APK/executable links, malicious macros, drive-by downloads, fake browser updates.
6. Attacker Objective & Threat Modeling: Unmasking what the attacker ultimately aims to achieve (e.g., initial wire fraud, session hijacking, identity theft).

ATTACK-STAGE ANALYSIS:
Map the observed artifact strictly to one of the following recognized lifecycle stages:
- Reconnaissance
- Initial Access
- Credential/Account Capture
- Execution/Exploitation
- Persistence
- Data Theft
- Account Takeover

PREDICT ATTACKER NEXT MOVE:
Forecast the attacker's trajectory based on current stage and observed evidence (e.g., "Initial Access → Credential harvesting → OTP/MFA intercept request → Account Takeover and unauthorized funds transfer").

SAFE RESPONSE GENERATION:
Formulate an assertive, neutral response the user can safely send if communication is required (e.g., "I will not use the link provided. I will independently verify this request via official organizational channels.").
CRITICAL SAFETY CONSTRAINT: The safe response must NEVER encourage clicking any link, downloading an attachment, calling unverified phone numbers, or revealing credentials, OTPs, passwords, or personal data.

JSON OUTPUT CONTRACT:
You MUST return ONLY a valid, parseable JSON object matching this exact schema:
{
  "threat_type": "Specific classification (e.g., Credential Harvesting Phishing, CEO Fraud / BEC, Smishing 2FA Intercept, Fake Invoice Scam, Tech Support Extortion, Malicious APK Download, Legitimate / Benign)",
  "risk_score": 85,
  "confidence_score": 92,
  "severity": "Critical | High | Medium | Low | Safe",
  "evidence_flags": [
    "Specific technical or linguistic red flag #1",
    "Specific technical or linguistic red flag #2"
  ],
  "attack_stage": "One of: Reconnaissance | Initial Access | Credential/Account Capture | Execution/Exploitation | Persistence | Data Theft | Account Takeover",
  "predicted_next_move": "Concrete evidence-based forecast of what the attacker will do next if victim complies",
  "attacker_goal": "Clear summary of the adversary's primary objective",
  "attack_chain": [
    "Reconnaissance (Completed)",
    "Initial Access (Active - Current Phase)",
    "Credential/Account Capture (Projected Next)",
    "Account Takeover (Projected Goal)"
  ],
  "safety_recommendations": [
    "Actionable immediate step 1",
    "Actionable immediate step 2",
    "Longer-term containment step 3"
  ],
  "safe_response": "Neutral, safe canned response or 'Do not reply - Block sender immediately'",
  "plain_english_explanation": "Beginner-friendly explanation in warm, plain English explaining the threat and what to do without technical jargon."
}
"""


def get_gemini_api_key() -> Optional[str]:
    """Retrieves and validates the GEMINI_API_KEY environment variable."""
    key = os.getenv("GEMINI_API_KEY")
    if not key or not key.strip() or key.strip() == "your_gemini_api_key_here":
        return None
    return key.strip()


def is_gemini_available() -> bool:
    """Checks whether the Gemini client can be initialized."""
    api_key = get_gemini_api_key()
    if not api_key:
        return False
    try:
        from google import genai
        return True
    except ImportError:
        return False


def get_gemini_client():
    """Initializes the official Google GenAI client instance."""
    api_key = get_gemini_api_key()
    if not api_key:
        raise ValueError("GEMINI_API_KEY is not configured. Please add GEMINI_API_KEY to your environment or .env file.")

    try:
        from google import genai
        return genai.Client(api_key=api_key)
    except ImportError as e:
        raise ImportError(
            "The 'google-genai' Python package is required. Install it with 'pip install google-genai'."
        ) from e


def analyze_with_gemini(
    input_data: Union[str, bytes, Dict[str, Any]],
    input_type: str,
    additional_context: Optional[str] = None,
    model: str = "gemini-2.5-flash"
) -> Dict[str, Any]:
    """
    Submits artifact content to Google Gemini for cognitive threat analysis.
    Supports URLs, emails/messages, and screenshots (multimodal image bytes).
    Returns a strictly validated dictionary conforming to the required schema.
    """
    client = get_gemini_client()

    context_prompt = CYBER_FORENSIC_SYSTEM_INSTRUCTION
    if additional_context:
        context_prompt += f"\n\nADDITIONAL TECHNICAL CONTEXT / HEURISTICS:\n{additional_context}\n"

    contents = []

    # Handle multimodal screenshot / image input
    if input_type == "screenshot" or isinstance(input_data, bytes):
        from google.genai import types

        image_bytes = input_data
        if isinstance(input_data, dict):
            image_bytes = input_data.get("data", b"")
            mime_type = input_data.get("mime_type", "image/png")
        else:
            mime_type = "image/png"

        contents.append(
            types.Part.from_bytes(
                data=image_bytes,
                mime_type=mime_type
            )
        )
        user_prompt = f"{context_prompt}\n\nARTIFACT TYPE: Screenshot / Visual Security Artifact.\nInspect the uploaded image carefully for visual deception, counterfeit logos, fake login prompts, urgency banners, or malware download triggers."
        contents.append(user_prompt)

    # Handle URL input
    elif input_type == "url":
        url_str = input_data.get("data", "") if isinstance(input_data, dict) else str(input_data)
        user_prompt = f"{context_prompt}\n\nARTIFACT TYPE: Suspicious URL\nTARGET URL: {url_str}\nConduct a deep forensic evaluation of this URL for credential harvesting, brand spoofing, malicious redirects, and phishing infrastructure."
        contents.append(user_prompt)

    # Handle Email / Message text input
    else:
        text_str = input_data.get("data", "") if isinstance(input_data, dict) else str(input_data)
        channel = input_data.get("context", "Message") if isinstance(input_data, dict) else "Message / Email"
        user_prompt = f"{context_prompt}\n\nARTIFACT TYPE: {channel}\nCONTENT TO ANALYZE:\n\"\"\"{text_str}\"\"\"\nInvestigate this communication for social engineering manipulation, artificial urgency, payment diversion, and deception."
        contents.append(user_prompt)

    # Execute Gemini API call with strict JSON response configuration
    response = client.models.generate_content(
        model=model,
        contents=contents,
        config={
            "response_mime_type": "application/json",
            "temperature": 0.2,
        }
    )

    response_text = (response.text or "{}").strip()

    # Robust JSON parsing handling code blocks
    if response_text.startswith("```json"):
        response_text = response_text[7:]
    if response_text.startswith("```"):
        response_text = response_text[3:]
    if response_text.endswith("```"):
        response_text = response_text[:-3]

    try:
        parsed_result = json.loads(response_text.strip())
    except json.JSONDecodeError as err:
        # Emergency JSON regex extraction fallback
        match = re.search(r"\{.*\}", response_text, re.DOTALL)
        if match:
            parsed_result = json.loads(match.group(0))
        else:
            raise ValueError("Gemini returned non-JSON response structure.") from err

    return parsed_result


class GeminiClient:
    """Wrapper class providing backward-compatible access for other modules."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or get_gemini_api_key()

    @property
    def is_configured(self) -> bool:
        return is_gemini_available()

    def generate_threat_assessment(
        self,
        prompt: str,
        image_bytes: Optional[bytes] = None,
        mime_type: Optional[str] = "image/png",
        model: Optional[str] = "gemini-2.5-flash"
    ) -> Dict[str, Any]:
        if image_bytes:
            return analyze_with_gemini(
                input_data={"data": image_bytes, "mime_type": mime_type},
                input_type="screenshot",
                additional_context=prompt,
                model=model
            )
        return analyze_with_gemini(
            input_data=prompt,
            input_type="text",
            model=model
        )


# Global singleton instance
gemini_engine = GeminiClient()
