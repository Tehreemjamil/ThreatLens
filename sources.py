"""
sources.py

Contains all external threat-intelligence source functions for ThreatLens.

Rules:
- This file must NEVER import from app.py.
- No Streamlit / UI code belongs here.
- Every source function follows the same signature: function(value, target_type)
- Every source function returns a plain dictionary.
- New sources are added by writing one function and registering it in SOURCES.
"""

import os
import requests
from datetime import datetime, timezone

try:
    import whois  # python-whois
except ImportError:
    whois = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_api_key(name):
    """Read an API key from environment variables or Streamlit secrets."""
    key = os.environ.get(name)
    if key:
        return key
    try:
        import streamlit as st
        return st.secrets.get(name)
    except Exception:
        return None


def _safe_str(value):
    """Convert dates / weird objects returned by whois into clean strings."""
    if value is None:
        return None
    if isinstance(value, list):
        return _safe_str(value[0]) if value else None
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    return str(value)


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def get_virustotal(value, target_type):
    """
    Query VirusTotal for an IP address, Domain, or URL.

    Returns a consistent dictionary:
    {
        "source": "VirusTotal",
        "available": bool,
        "malicious": int | None,
        "suspicious": int | None,
        "harmless": int | None,
        "undetected": int | None,
        "reputation": int | None,
        "error": str | None,
    }
    """
    result = {
        "source": "VirusTotal",
        "available": False,
        "malicious": None,
        "suspicious": None,
        "harmless": None,
        "undetected": None,
        "reputation": None,
        "error": None,
    }

    api_key = _get_api_key("VIRUSTOTAL_API_KEY")
    if not api_key:
        result["error"] = "VirusTotal API key is missing."
        return result

    headers = {"x-apikey": api_key}

    try:
        if target_type == "IP Address":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
            response = requests.get(url, headers=headers, timeout=15)

        elif target_type == "Domain":
            url = f"https://www.virustotal.com/api/v3/domains/{value}"
            response = requests.get(url, headers=headers, timeout=15)

        elif target_type == "URL":
            # VirusTotal requires the URL to be submitted as a base64 (no padding) id
            import base64
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(url, headers=headers, timeout=15)

            # If VirusTotal has no record yet, submit it for analysis instead of failing outright
            if response.status_code == 404:
                submit_url = "https://www.virustotal.com/api/v3/urls"
                submit_resp = requests.post(
                    submit_url, headers=headers, data={"url": value}, timeout=15
                )
                if submit_resp.status_code in (200, 201):
                    result["error"] = (
                        "URL was not previously scanned by VirusTotal. "
                        "It has been submitted for analysis; try again shortly."
                    )
                else:
                    result["error"] = "VirusTotal has no existing data for this URL."
                return result
        else:
            result["error"] = f"Unsupported target type for VirusTotal: {target_type}"
            return result

        if response.status_code == 401:
            result["error"] = "VirusTotal authentication failed. Check your API key."
            return result

        if response.status_code == 429:
            result["error"] = "VirusTotal rate limit exceeded. Please try again later."
            return result

        if response.status_code == 404:
            result["error"] = "No VirusTotal data found for this target."
            return result

        if response.status_code != 200:
            result["error"] = f"VirusTotal returned an unexpected status: {response.status_code}"
            return result

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        result["available"] = True
        result["malicious"] = stats.get("malicious")
        result["suspicious"] = stats.get("suspicious")
        result["harmless"] = stats.get("harmless")
        result["undetected"] = stats.get("undetected")
        result["reputation"] = attributes.get("reputation")

    except requests.exceptions.Timeout:
        result["error"] = "VirusTotal request timed out."
    except requests.exceptions.RequestException as exc:
        result["error"] = f"VirusTotal network error: {exc}"
    except Exception as exc:
        result["error"] = f"Unexpected VirusTotal error: {exc}"

    return result


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def get_whois(value, target_type):
    """
    Perform a WHOIS lookup. Primarily supports Domain lookups.

    Returns a consistent dictionary:
    {
        "source": "WHOIS",
        "available": bool,
        "domain_name": str | None,
        "registrar": str | None,
        "creation_date": str | None,
        "expiration_date": str | None,
        "updated_date": str | None,
        "domain_age_days": int | None,
        "error": str | None,
    }
    """
    result = {
        "source": "WHOIS",
        "available": False,
        "domain_name": None,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "domain_age_days": None,
        "error": None,
    }

    if target_type != "Domain":
        result["error"] = (
            "WHOIS lookups are only applicable to domains. "
            f"Not applicable for target type: {target_type}."
        )
        return result

    if whois is None:
        result["error"] = "The 'python-whois' package is not installed."
        return result

    try:
        record = whois.whois(value)

        if not record or not record.get("domain_name"):
            result["error"] = "No WHOIS data could be retrieved for this domain."
            return result

        creation_date = record.get("creation_date")
        updated_date = record.get("updated_date")
        expiration_date = record.get("expiration_date")

        result["available"] = True
        result["domain_name"] = _safe_str(record.get("domain_name"))
        result["registrar"] = _safe_str(record.get("registrar"))
        result["creation_date"] = _safe_str(creation_date)
        result["expiration_date"] = _safe_str(expiration_date)
        result["updated_date"] = _safe_str(updated_date)

        # Safely calculate domain age
        try:
            first_creation = creation_date[0] if isinstance(creation_date, list) else creation_date
            if isinstance(first_creation, datetime):
                if first_creation.tzinfo is None:
                    first_creation = first_creation.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - first_creation).days
                result["domain_age_days"] = age_days
        except Exception:
            result["domain_age_days"] = None

    except Exception as exc:
        result["error"] = f"WHOIS lookup failed: {exc}"

    return result


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
# To add a new intelligence source later:
#   1. Write a function: def get_new_source(value, target_type): ...
#   2. Add it here: "New Source": get_new_source
# No changes are needed anywhere else in the application.

SOURCES = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
