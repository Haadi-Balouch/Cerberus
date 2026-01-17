from pathlib import Path
import requests

def find_admin_panels(base_url, wordlist_path="Cerberus/wordlists/admin_paths.txt", workers=10, timeout=4):
    results = []
    if not Path(wordlist_path).exists():
        return results
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        paths = [p.strip() for p in f if p.strip()]
    for p in paths:
        url = base_url.rstrip("/") + "/" + p.lstrip("/")
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
            if r.status_code in (200, 301, 302, 403):
                results.append({"url": url, "status_code": r.status_code})
        except:
            pass
    return results
