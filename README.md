# Cerberus

Cerberus is a professional vulnerability scanning framework designed for network and web security assessment.  
It focuses on **accuracy**, **clarity**, and **actionable security insights** rather than noisy results.

---

## Key Capabilities

- Network and service discovery
- Enhanced banner grabbing
- Service and version fingerprinting
- Version-aware CVE detection using NIST NVD
- CVSS severity analysis and prioritization
- Automated remediation recommendations
- SQL Injection detection  
  - Error-based detection  
  - Boolean-based detection
- Cross-Site Scripting (XSS) detection with multiple payloads
- Security header analysis
- Admin panel discovery
- Directory enumeration using wordlists
- Rich terminal UI with progress indicators
- Professional PDF vulnerability reports

---


## CVE Intelligence

Cerberus integrates directly with the **NIST National Vulnerability Database (NVD)**.

- Uses CPE configurations for matching
- Requires exact or ranged version matches
- Excludes client-only and unrelated vulnerabilities
- Prevents CVE flooding and false positives
- Returns:
  - CVE ID
  - Severity (CVSS)
  - Description
  - Remediation recommendation

---

## Web Vulnerability Scanning

Cerberus performs targeted web security checks:

- SQL Injection
  - Error-based detection
  - Boolean-based detection
  - Payload-level evidence
- Cross-Site Scripting (XSS)
  - 20+ reflected payloads
  - Reflection verification
- Security header analysis
- Admin panel enumeration
- Directory brute forcing

---

## Reporting

Cerberus generates professional reports:

- Console-based summaries
- Structured JSON output
- Styled PDF reports inspired by industry tools

Reports include:
- Detected services
- Open ports
- CVE severity breakdown
- Web vulnerabilities
- Security recommendations

---

## Usage

Cerberus supports both interactive and command-line execution.

Targets may include:
- IP addresses
- Domain names
- Optional web URLs for application scanning

---

## Legal Disclaimer

This tool is intended **only for authorized security testing**.  
Scanning systems without explicit permission is illegal.

---

## Data Sources

- National Vulnerability Database (NVD)
- CVSS scoring standards


