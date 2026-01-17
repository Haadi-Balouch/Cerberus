import requests
import re
from packaging import version as pkg_version
import time
import threading

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=2000"

# Global rate limiter for thread-safe API calls
_last_request_time = 0
_rate_lock = threading.Lock()

# Service name mapping for better CVE matching
SERVICE_ALIASES = {
    "ssh": ["openssh", "ssh"],
    "ftp": ["ftp"],
    "vsftpd": ["vsftpd"],
    "proftpd": ["proftpd"],
    "apache": ["apache", "httpd"],
    "nginx": ["nginx"],
    "mysql": ["mysql"],
    "mariadb": ["mariadb"],
    "postgresql": ["postgresql", "postgres"],
    "samba": ["samba", "smb"],
    "telnet": ["telnet"],
    "postfix": ["postfix"],
    "sendmail": ["sendmail"],
    "exim": ["exim"],
    "smtp": ["smtp"],
}


def rate_limit():
    """
    Thread-safe rate limiting for NVD API.
    Ensures minimum 600ms between API requests to avoid rate limiting.
    """
    global _last_request_time
    
    with _rate_lock:
        current_time = time.time()
        elapsed = current_time - _last_request_time
        
        # If less than 600ms has passed since last request, wait
        if elapsed < 0.6:
            sleep_time = 0.6 - elapsed
            time.sleep(sleep_time)
        
        # Update the last request time
        _last_request_time = time.time()


def get_search_terms(service: str) -> list:
    """Get all possible search terms for a service"""
    service = service.lower()
    
    # Check if service is in our aliases
    for key, aliases in SERVICE_ALIASES.items():
        if service in aliases or service == key:
            return aliases if key == service else [service]
    
    return [service]


def generate_recommendation(severity: str) -> str:
    """Generate security recommendation based on severity level"""
    severity = severity.upper()
    
    if severity == "CRITICAL":
        return "Patch immediately, restrict network exposure."
    elif severity == "HIGH":
        return "Update software to the latest stable version and apply vendor patches."
    elif severity == "MEDIUM":
        return "Improve configuration and apply security hardening."
    elif severity == "LOW":
        return "Optional patching; monitor system activity."
    else:
        return "No recommendation available."


def version_matches(cve_data, version: str, service: str) -> bool:
    """
    Enhanced version matching with proper semantic versioning.
    
    Args:
        cve_data: CVE data from NVD API
        version: Version string to match (e.g., "7.6")
        service: Service name (e.g., "openssh")
    
    Returns:
        True if the version is affected by this CVE, False otherwise
    """
    # Don't return CVEs for unknown versions
    if not version or version == "unknown":
        return False 

    version = version.strip()
    
    # Check CPE configurations for version matching
    configs = cve_data.get("configurations", [])
    for config in configs:
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                cpe_str = cpe.get("criteria", "").lower()
                
                # Check if this CPE is for the right service
                if service.lower() not in cpe_str:
                    continue
                
                # Exact version match in CPE string
                if f":{version}" in cpe_str or f":{version}:" in cpe_str:
                    return True
                
                # Check version ranges with proper semantic versioning
                if cpe.get("vulnerable", True):
                    version_start_inc = cpe.get("versionStartIncluding")
                    version_end_inc = cpe.get("versionEndIncluding")
                    version_start_exc = cpe.get("versionStartExcluding")
                    version_end_exc = cpe.get("versionEndExcluding")
                    
                    try:
                        # Parse version using packaging library for proper comparison
                        current_ver = pkg_version.parse(version)
                        
                        # Check if version is within vulnerable range
                        # versionStartIncluding: current_ver >= start
                        if version_start_inc:
                            if current_ver < pkg_version.parse(version_start_inc):
                                continue
                        
                        # versionEndIncluding: current_ver <= end
                        if version_end_inc:
                            if current_ver > pkg_version.parse(version_end_inc):
                                continue
                        
                        # versionStartExcluding: current_ver > start
                        if version_start_exc:
                            if current_ver <= pkg_version.parse(version_start_exc):
                                continue
                        
                        # versionEndExcluding: current_ver < end
                        if version_end_exc:
                            if current_ver >= pkg_version.parse(version_end_exc):
                                continue
                        
                        # If we passed all range checks, version is vulnerable
                        if any([version_start_inc, version_end_inc, 
                               version_start_exc, version_end_exc]):
                            return True
                            
                    except Exception:
                        # Fallback to string comparison if version parsing fails
                        # This handles non-standard version formats
                        pass
    
    # Fallback: Search in CVE description (less reliable but catches some cases)
    try:
        desc = cve_data["descriptions"][0]["value"].lower()
        
        # More precise description matching using word boundaries
        version_pattern = rf'\b{re.escape(version)}\b'
        if re.search(version_pattern, desc):
            return True
        
        # Check for service + version combination in description
        service_version_pattern = rf'{re.escape(service.lower())}\s+{re.escape(version)}'
        if re.search(service_version_pattern, desc):
            return True
    except:
        pass

    return False


def auto_cve_lookup(service: str, version: str):
    """
    Enhanced CVE lookup with rate limiting, version filtering, and error handling.
    
    Args:
        service: Service name (e.g., "openssh", "apache")
        version: Version string (e.g., "7.6", "2.4.41")
    
    Returns:
        List of matching CVEs with severity, description, and recommendations
    """
    # Skip lookup for unknown services
    if not service or service == "unknown":
        return []

    # Apply rate limiting to prevent NVD API blocks
    rate_limit()
    
    matched = []
    search_terms = get_search_terms(service)
    
    # Search with primary service name
    primary_term = search_terms[0] if search_terms else service
    url = NVD_API_URL.format(primary_term)
    
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()  # Raise exception for HTTP errors
        data = response.json()
        
    except requests.exceptions.Timeout:
        return [{"error": f"NVD API timeout while searching for {service}"}]
    
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            return [{"error": "NVD API rate limit exceeded - please wait and try again"}]
        elif e.response.status_code == 404:
            return [{"error": f"No CVE data found for {service}"}]
        else:
            return [{"error": f"HTTP error {e.response.status_code} from NVD API"}]
    
    except requests.exceptions.ConnectionError:
        return [{"error": "Cannot connect to NVD API - check your internet connection"}]
    
    except Exception as e:
        return [{"error": f"Failed to fetch CVEs: {str(e)}"}]

    # Parse CVE list from API response
    cve_list = data.get("vulnerabilities", [])

    for entry in cve_list:
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN-CVE")

        # Version filtering - skip CVEs that don't match the version
        if not version_matches(cve, version, service):
            continue

        # Extract severity from CVSS metrics
        severity = "UNKNOWN"
        metrics = cve.get("metrics", {})

        # Try CVSS v3.1 (preferred)
        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        
        # Try CVSS v3.0
        elif "cvssMetricV30" in metrics:
            severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
        
        # Fallback to CVSS v2 (requires manual severity calculation)
        elif "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", None)
            if score is not None:
                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

        # Extract CVE description
        description = ""
        try:
            description = cve["descriptions"][0]["value"]
            
            # Truncate very long descriptions for better readability
            if len(description) > 500:
                description = description[:497] + "..."
                
        except:
            description = "No description provided by NVD."

        # Generate security recommendation based on severity
        recommendation = generate_recommendation(severity)

        # Add to matched CVEs list
        matched.append({
            "cve": cve_id,
            "severity": severity,
            "description": description,
            "recommendation": recommendation
        })
    
    # Sort CVEs by severity (Critical → High → Medium → Low → Unknown)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    matched.sort(key=lambda x: severity_order.get(x.get("severity", "UNKNOWN"), 4))
    
    return matched


