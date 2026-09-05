import base64
from urllib.parse import urlparse
from google import genai
import requests
import streamlit as st
import whois

# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------


def extract_domain(input_string):
    """Extracts a bare domain from a URL or raw domain string."""
    cleaned = input_string.strip()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "http://" + cleaned
    parsed = urlparse(cleaned)
    domain = parsed.netloc.split(":")[0]  # Remove port if present
    return domain.lower()


def get_virustotal_data(analysis_type, target, api_key):
    """Fetches analysis data from VirusTotal API v3 based on the selected type."""
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        if analysis_type == "URL":
            # VirusTotal v3 requires URLs to be base64url-encoded without '=' padding
            url_id = (
                base64.urlsafe_b64encode(target.strip().encode())
                .decode()
                .strip("=")
            )
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        elif analysis_type == "Domain":
            domain = extract_domain(target)
            endpoint = f"https://www.virustotal.com/api/v3/domains/{domain}"
        elif analysis_type == "IP Address":
            ip = target.strip()
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        else:
            return None, "Invalid analysis type."

        response = requests.get(endpoint, headers=headers, timeout=15)

        if response.status_code == 200:
            return response.json(), None
        elif response.status_code == 404:
            return (
                None,
                "The target was not found in VirusTotal's database yet.",
            )
        elif response.status_code == 401:
            return None, "Invalid VirusTotal API Key. Please check your credentials."
        elif response.status_code == 429:
            return None, "VirusTotal API rate limit reached. Please wait and try again."
        else:
            return (
                None,
                f"VirusTotal API returned an error (Status code: {response.status_code}).",
            )

    except requests.exceptions.RequestException as e:
        return None, f"Network error contacting VirusTotal: {str(e)}"


def get_whois_data(analysis_type, target):
    """Queries WHOIS records for domains and URLs.

    Errors are caught gracefully.
    """
    if analysis_type == "IP Address":
        # python-whois is primarily designed for domains
        return {
            "Domain": target,
            "Note": "WHOIS lookup skipped for IP address.",
        }

    try:
        domain = extract_domain(target)
        record = whois.whois(domain)

        # Helper to format values that can be single items or lists
        def format_field(val):
            if not val:
                return "Not available"
            if isinstance(val, list):
                return ", ".join(
                    [
                        item.strftime("%Y-%m-%d")
                        if hasattr(item, "strftime")
                        else str(item)
                        for item in val
                    ]
                )
            if hasattr(val, "strftime"):
                return val.strftime("%Y-%m-%d")
            return str(val)

        return {
            "Domain": format_field(record.domain_name),
            "Registrar": format_field(record.registrar),
            "Creation date": format_field(record.creation_date),
            "Updated date": format_field(record.updated_date),
            "Expiration date": format_field(record.expiration_date),
            "Domain status": format_field(record.status),
            "Name servers": format_field(record.name_servers),
        }
    except Exception as e:
        return {"Error": f"Unable to retrieve WHOIS information: {str(e)}"}


def generate_gemini_explanation(
    analysis_type, target, vt_data, whois_info, level, gemini_api_key
):
    """Uses Google Gemini API to interpret and explain the scan results."""
    try:
        client = genai.Client(api_key=gemini_api_key)

        prompt = f"""
You are LinkLens, a cybersecurity explanation assistant. 

Explain the following security analysis results for the {analysis_type}: '{target}'.

Explanation Level: {level}

Level Guidelines:
- Beginner: Use very simple language. Explain technical terms in plain English. For example, explain that VirusTotal checks against many vendor engines, that 1-2 flags might just be false positives, and what risks exist.
- Intermediate: Assume basic security knowledge. Discuss detections, reputation, domain age from WHOIS, vendor classifications, and why they matter.
- Expert: Provide a technical breakdown covering engine results, reputation scores, classifications, WHOIS metadata, and technical indicators.

Strict Rules:
1. Only base your conclusions on the supplied data below. Never invent or hallucinate findings.
2. Clearly distinguish between factual findings and your interpretation.
3. Do NOT automatically classify something as malicious just because one vendor flagged it; explain false positive possibilities.
4. Never state that an entity is "100% safe" or "guaranteed clean".
5. Never state something is definitely malicious unless evidence is overwhelming.
6. Explain the limitations of the data.
7. Provide practical, actionable safety recommendations.

Data Provided:
- VirusTotal Information: {vt_data}
- WHOIS Information: {whois_info}
"""

        response = client.models.generate_content(
            model="gemini-3.6-flash", contents=prompt
        )
        return response.text, None

    except Exception as e:
        return None, f"Gemini API error: {str(e)}"


# ---------------------------------------------------------
# Streamlit User Interface
# ---------------------------------------------------------

st.title("LinkLens")
st.caption("URL, Domain & IP Security Analyzer")

# Control 1: Analysis Type
analysis_type = st.selectbox(
    "What do you want to check?", ["URL", "Domain", "IP Address"]
)

# Control 2: Explanation Level
explanation_level = st.selectbox(
    "Explanation Level", ["Beginner", "Intermediate", "Expert"]
)

# Control 3: Input
target_input = st.text_input(
    "Enter URL, Domain or IP Address", placeholder="example.com"
)

# Analysis Action
if st.button("Analyze"):
    # Step 1: Input Validation
    if not target_input.strip():
        st.error("Please enter a valid URL, Domain, or IP Address.")
        st.stop()

    # Step 2: Validate API Keys from secrets
    vt_api_key = st.secrets.get("VIRUSTOTAL_API_KEY")
    gemini_api_key = st.secrets.get("GEMINI_API_KEY")

    if not vt_api_key:
        st.error("Missing `VIRUSTOTAL_API_KEY` in Streamlit secrets.")
        st.stop()

    if not gemini_api_key:
        st.error("Missing `GEMINI_API_KEY` in Streamlit secrets.")
        st.stop()

    with st.spinner("Analyzing target across security sources..."):
        # Fetch VirusTotal Data
        vt_raw, vt_error = get_virustotal_data(
            analysis_type, target_input, vt_api_key
        )

        # Fetch WHOIS Data
        whois_data = get_whois_data(analysis_type, target_input)

    # Handle VirusTotal failure
    if vt_error:
        st.error(vt_error)
        st.stop()

    # Extract metrics from VirusTotal response
    attributes = vt_raw.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    reputation = attributes.get("reputation", "Not available")
    categories = attributes.get("categories", {})

    # 1. Analysis Summary
    st.subheader("Analysis Summary")
    st.write(f"**Input:** `{target_input}`")
    st.write(f"**Input Type:** {analysis_type}")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Malicious", malicious)
    col2.metric("Suspicious", suspicious)
    col3.metric("Harmless", harmless)
    col4.metric("Undetected", undetected)

    st.markdown("---")

    # 2. VirusTotal Results
    st.subheader("VirusTotal Results")
    st.write(f"**Reputation Score:** {reputation}")

    if categories:
        category_list = [f"{v} ({k})" for k, v in categories.items()]
        st.write(f"**Categories:** {', '.join(category_list)}")
    else:
        st.write("**Categories:** Not available")

    with st.expander("View Raw VirusTotal Data"):
        st.json(vt_raw)

    st.markdown("---")

    # 3. WHOIS Information
    st.subheader("WHOIS Information")

    if "Error" in whois_data:
        st.warning(whois_data["Error"])

    elif analysis_type == "IP Address":
        st.info("WHOIS lookup is not performed for IP addresses in this version.")

    else:
        # Get WHOIS fields
        domain = whois_data.get("Domain", "Not available")
        registrar = whois_data.get("Registrar", "Not available")
        creation_date = whois_data.get("Creation date", "Not available")
        updated_date = whois_data.get("Updated date", "Not available")
        expiration_date = whois_data.get("Expiration date", "Not available")
        domain_status = whois_data.get("Domain status", "Not available")
        name_servers = whois_data.get("Name servers", "Not available")

        # Calculate approximate domain age
        domain_age = "Not available"

        try:
            from datetime import datetime

            if creation_date != "Not available":
                first_date = creation_date.split(",")[0].strip()
                created = datetime.strptime(first_date, "%Y-%m-%d")
                today = datetime.today()

                years = today.year - created.year

                if (today.month, today.day) < (created.month, created.day):
                    years -= 1

                domain_age = f"About {years} years"

        except Exception:
            domain_age = "Not available"

        # Translate technical WHOIS status codes
        status_text = str(domain_status)
        status_explanations = []

        if "clientDeleteProhibited" in status_text:
            status_explanations.append("Deletion protection is enabled")

        if "clientTransferProhibited" in status_text:
            status_explanations.append(
                "Unauthorized domain transfer is restricted"
            )

        if "clientUpdateProhibited" in status_text:
            status_explanations.append(
                "Unauthorized domain changes are restricted"
            )

        if "serverDeleteProhibited" in status_text:
            status_explanations.append(
                "Server-side deletion protection is enabled"
            )

        if "serverTransferProhibited" in status_text:
            status_explanations.append(
                "Server-side transfer protection is enabled"
            )

        if "serverUpdateProhibited" in status_text:
            status_explanations.append(
                "Server-side update protection is enabled"
            )

        if status_explanations:
            friendly_status = " • ".join(status_explanations)
        else:
            friendly_status = "No specific status information available"

        # Display clean WHOIS information
        col1, col2 = st.columns(2)

        with col1:
            st.write(f"**Domain:** {domain}")
            st.write(f"**Registrar:** {registrar}")
            st.write(f"**Registered:** {creation_date}")
            st.write(f"**Domain age:** {domain_age}")

        with col2:
            st.write(f"**Last updated:** {updated_date}")
            st.write(f"**Expires:** {expiration_date}")
            st.write(f"**Status:** {friendly_status}")

        st.write(f"**DNS / Name servers:** {name_servers}")

        # Simple explanation
        st.info(
            "💡 **What does this mean?**\n\n"
            "WHOIS information shows basic registration details about a domain. "
            "A long registration history can provide useful context, but domain age "
            "or registration information alone does not prove that a website is safe."
        )

        # Advanced technical information
        with st.expander("View Advanced WHOIS Details"):
            st.write(
                "The information below contains the original technical WHOIS fields."
            )

            for key, value in whois_data.items():
                st.write(f"**{key}:** {value}")

        st.markdown("---")

    # 4. Gemini Explanation
    st.subheader(f"{explanation_level} Explanation")

    with st.spinner("Generating explanation..."):
        summary_payload = {
            "detection_stats": stats,
            "reputation": reputation,
            "categories": categories,
        }

        explanation, gemini_error = generate_gemini_explanation(
            analysis_type,
            target_input,
            summary_payload,
            whois_data,
            explanation_level,
            gemini_api_key,
        )

        if gemini_error:
            st.warning(gemini_error)
        else:
            st.write(explanation)