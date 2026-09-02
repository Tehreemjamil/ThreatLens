"""
app.py

ThreatLens - Smart Threat Intelligence Scanner
Handles: UI, input validation, orchestration, Gemini prompting, results display.

Dependency direction: app.py -> sources.py (one-way only)
"""

import os
import ipaddress
import re
from urllib.parse import urlparse

import streamlit as st

from sources import SOURCES

try:
    import google.generativeai as genai
except ImportError:
    genai = None


# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------

st.set_page_config(page_title="ThreatLens", page_icon="🔍", layout="wide")

st.title("🔍 ThreatLens")
st.subheader("Smart Threat Intelligence Scanner")
st.write(
    "Check IP addresses, domains, and URLs using VirusTotal and WHOIS intelligence."
)
st.divider()


# ---------------------------------------------------------------------------
# Sidebar: API key entry
# ---------------------------------------------------------------------------

with st.sidebar:
    st.header("Settings")
    vt_key_input = st.text_input("VirusTotal API key", type="password")
    gemini_key_input = st.text_input("Gemini API key", type="password")

    if vt_key_input:
        os.environ["VIRUSTOTAL_API_KEY"] = vt_key_input
    if gemini_key_input:
        os.environ["GEMINI_API_KEY"] = gemini_key_input

    st.divider()
    st.caption("Active intelligence sources")
    for name in SOURCES:
        st.write(f"• {name}")


# ---------------------------------------------------------------------------
# Helpers: API keys
# ---------------------------------------------------------------------------

def get_secret(name):
    value = os.environ.get(name)
    if value:
        return value
    try:
        return st.secrets.get(name)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Helpers: Validation
# ---------------------------------------------------------------------------

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def validate_ip(value):
    try:
        ipaddress.ip_address(value.strip())
        return True, None
    except ValueError:
        return False, "That doesn't look like a valid IP address."


def validate_domain(value):
    value = value.strip()
    if DOMAIN_PATTERN.match(value):
        return True, None
    return False, "That doesn't look like a valid domain (example: example.com)."


def validate_url(value):
    value = value.strip()
    try:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https"):
            return False, "URL must start with http:// or https://"
        if not parsed.netloc:
            return False, "URL is missing a valid network location (domain)."
        return True, None
    except Exception:
        return False, "That doesn't look like a valid URL."


def validate_input(value, target_type):
    if not value or not value.strip():
        return False, "Please enter a value to analyze."
    if target_type == "IP Address":
        return validate_ip(value)
    if target_type == "Domain":
        return validate_domain(value)
    if target_type == "URL":
        return validate_url(value)
    return False, "Unknown target type."


# ---------------------------------------------------------------------------
# Verdict logic (based only on collected source data)
# ---------------------------------------------------------------------------

def compute_verdict(results):
    """
    Determine SAFE / SUSPICIOUS / DANGEROUS / UNKNOWN based on VirusTotal data,
    falling back to UNKNOWN when no reliable data is available.
    """
    vt = results.get("VirusTotal", {})

    if not vt.get("available"):
        return "UNKNOWN", "Insufficient information to make a reliable assessment."

    malicious = vt.get("malicious") or 0
    suspicious = vt.get("suspicious") or 0

    if malicious >= 3:
        return "DANGEROUS", "Multiple threat indicators detected."
    if malicious > 0 or suspicious > 0:
        return "SUSPICIOUS", "Potential warning indicators detected. Proceed with caution."
    return "SAFE", "No significant threats detected from available intelligence."


VERDICT_STYLE = {
    "SAFE": ("🟢", "#1e7d32", "#e8f5e9"),
    "SUSPICIOUS": ("🟡", "#8a6d00", "#fff8e1"),
    "DANGEROUS": ("🔴", "#b71c1c", "#fdecea"),
    "UNKNOWN": ("⚪", "#424242", "#f5f5f5"),
}


def render_verdict_card(verdict, message):
    emoji, text_color, bg_color = VERDICT_STYLE.get(verdict, VERDICT_STYLE["UNKNOWN"])
    st.markdown(
        f"""
        <div style="
            background-color:{bg_color};
            border-left: 6px solid {text_color};
            padding: 1.2rem 1.5rem;
            border-radius: 8px;
            margin-bottom: 1rem;
        ">
            <span style="font-size:1.4rem; font-weight:700; color:{text_color};">
                {emoji} {verdict}
            </span>
            <p style="margin-top:0.5rem; margin-bottom:0; color:{text_color};">
                {message}
            </p>
            <p style="margin-top:0.5rem; margin-bottom:0; font-size:0.85rem; color:{text_color};">
                This assessment is based only on available VirusTotal and WHOIS
                information. It is not a guarantee.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Results rendering (generic — supports any source in the registry)
# ---------------------------------------------------------------------------

def render_source_results(results):
    st.subheader("Source Results")

    for source_name, data in results.items():
        with st.expander(source_name, expanded=True):
            if data.get("error"):
                st.warning(data["error"])

            display_data = {
                k: v for k, v in data.items()
                if k not in ("source", "available", "error") and v is not None
            }

            if not display_data:
                if not data.get("error"):
                    st.info("No additional data available.")
                continue

            cols = st.columns(min(4, len(display_data)) or 1)
            for i, (key, value) in enumerate(display_data.items()):
                label = key.replace("_", " ").title()
                cols[i % len(cols)].metric(label, value)


# ---------------------------------------------------------------------------
# Gemini prompting
# ---------------------------------------------------------------------------

def build_prompt(value, target_type, knowledge_level, results):
    vt = results.get("VirusTotal", {})
    whois_data = results.get("WHOIS", {})

    shared_context = f"""
You are a cybersecurity analyst assistant. Analyze the following threat intelligence
data about a target. Base your analysis ONLY on the data provided below. Do not invent
or assume any facts that are not present in this data. If information is missing or
unavailable, clearly say so.

Target: {value}
Target type: {target_type}

VirusTotal data:
{vt}

WHOIS data:
{whois_data}

Rules you must follow:
1. Do not claim the target is definitely safe.
2. Do not claim the target is definitely malicious unless the evidence strongly supports it.
3. Do not invent missing information.
4. Clearly distinguish facts from interpretation.
5. Explain that VirusTotal and WHOIS data alone are limited and not a complete picture.
6. If information is unavailable, state that clearly.
7. End with a confidence level: Low, Medium, or High.
"""

    if knowledge_level == "Beginner":
        style_instructions = """
Write for a beginner with no cybersecurity background.
- Use simple, everyday language.
- Briefly explain any technical term you use.
- Avoid unnecessary jargon.
- Clearly state a verdict: Safe, Suspicious, Dangerous, or Unknown / Insufficient Data.
- Explain why using simple bullet points.
- Mention limitations of the data in plain language.
Follow this style:

Verdict: <verdict>

Why:
• point
• point

What this means:
<one short plain-language paragraph>

Confidence: <Low/Medium/High>
"""
    elif knowledge_level == "Intermediate":
        style_instructions = """
Write for someone with moderate technical familiarity.
- Include technical context: detection ratios, suspicious indicators, domain age, reputation.
- Explain confidence and limitations clearly.
- Avoid overclaiming certainty.
- Keep it organized with short headers or bullet points.
- End with a confidence level.
"""
    else:  # Expert
        style_instructions = """
Write for a security expert.
- Be concise and technically dense; skip basic explanations.
- Focus on: VirusTotal detection signals, reputation, WHOIS metadata, domain age,
  inconsistencies, and evidentiary limitations.
- End with a confidence level and a one-line rationale for that confidence.
"""

    return shared_context + "\n" + style_instructions


def call_gemini(prompt):
    api_key = get_secret("GEMINI_API_KEY")
    if not api_key:
        return None, "Gemini API key is missing. AI analysis is unavailable."

    if genai is None:
        return None, "The 'google-generativeai' package is not installed."

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-3.6-flash")
        response = model.generate_content(prompt)
        text = getattr(response, "text", None)
        if not text:
            return None, "Gemini returned an empty response."
        return text, None
    except Exception as exc:
        return None, f"Gemini API error: {exc}"


# ---------------------------------------------------------------------------
# UI: Input
# ---------------------------------------------------------------------------

col1, col2 = st.columns(2)
with col1:
    target_type = st.selectbox("Target type", ["IP Address", "Domain", "URL"])
with col2:
    knowledge_level = st.selectbox("Knowledge level", ["Beginner", "Intermediate", "Expert"])

placeholders = {
    "IP Address": "Example: 8.8.8.8",
    "Domain": "Example: example.com",
    "URL": "Example: https://example.com",
}

value = st.text_input("Enter a value to analyze", placeholder=placeholders[target_type])

analyze_clicked = st.button("Analyze", type="primary")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

if analyze_clicked:
    is_valid, error_message = validate_input(value, target_type)

    if not is_valid:
        st.error(error_message)
    else:
        results = {}

        with st.status("Running threat intelligence analysis...", expanded=True) as status:
            for source_name, source_function in SOURCES.items():
                st.write(f"Querying {source_name}...")
                try:
                    results[source_name] = source_function(value.strip(), target_type)
                except Exception as exc:
                    results[source_name] = {
                        "source": source_name,
                        "available": False,
                        "error": f"{source_name} failed unexpectedly: {exc}",
                    }
            status.update(label="Analysis complete.", state="complete")

        verdict, verdict_message = compute_verdict(results)

        st.divider()
        render_verdict_card(verdict, verdict_message)
        render_source_results(results)

        st.divider()
        st.subheader("AI Insight")

        with st.spinner("Generating AI analysis..."):
            prompt = build_prompt(value.strip(), target_type, knowledge_level, results)
            ai_text, ai_error = call_gemini(prompt)

        if ai_error:
            st.info(f"AI analysis is temporarily unavailable: {ai_error}")
        else:
            st.markdown(
                f"""
                <div style="
                    background-color:#f0f4ff;
                    border-left: 6px solid #2954E8;
                    padding: 1.2rem 1.5rem;
                    border-radius: 8px;
                ">
                {ai_text}
                </div>
                """,
                unsafe_allow_html=True,
            )
