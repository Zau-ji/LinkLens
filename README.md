# 🔍 LinkLens

### URL, Domain & IP Security Analyzer

LinkLens is a simple cybersecurity web application that analyzes **URLs, domains, and IP addresses** using security intelligence from VirusTotal and registration information from WHOIS.

It also uses **Google Gemini** to explain the results in an easy-to-understand way.

🌐 **Live Demo:** https://linklens.streamlit.app/

---

## 🚀 Features

- 🔗 **URL Analysis**
  - Analyze URLs for security-related information
  - Extracts the domain for additional WHOIS information

- 🌐 **Domain Analysis**
  - Check domain reputation and security findings
  - Retrieve domain registration information

- 🌍 **IP Address Analysis**
  - Analyze IPv4/IPv6 addresses using VirusTotal

- 🛡️ **VirusTotal Integration**
  - Malicious detections
  - Suspicious detections
  - Harmless detections
  - Undetected results
  - Reputation score
  - Security categories

- 📋 **WHOIS Information**
  - Registrar
  - Registration date
  - Last updated date
  - Expiration date
  - Domain age
  - Domain status
  - Name servers

- 🤖 **Gemini AI Explanation**
  - Explains technical security findings
  - Supports three explanation levels:
    - Beginner
    - Intermediate
    - Expert

- ⚠️ **Graceful Error Handling**
  - Invalid inputs
  - API errors
  - Rate limits
  - WHOIS lookup failures
  - AI/API failures

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Application development |
| Streamlit | Web application interface |
| VirusTotal API | Security and reputation analysis |
| WHOIS | Domain registration information |
| Google Gemini API | Security result explanations |

---

## 📂 Project Structure

```text
Linklens/
│
├── app.py
├── requirements.txt
├── .gitignore
│
└── .streamlit/
    └── secrets.toml
