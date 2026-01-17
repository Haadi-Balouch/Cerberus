import requests

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy"
]

def check_headers(url):
    try:
        r = requests.get(url, timeout=5)
        missing = []

        for h in REQUIRED_HEADERS:
            if h not in r.headers:
                missing.append(h)
        return {
            "missing_headers": missing,
            "secure": len(missing) == 0
        }

    except Exception as e:
        return {"error": str(e)}
