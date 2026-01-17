import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from typing import List, Optional
import time


# DEFAULT SAFETY WORDLIST (Used if no file provided)
DEFAULT_WORDLIST = [
    "admin", "login", "dashboard", "wp-admin", "administrator",
    "cpanel", "phpmyadmin", "manage", "upload", "uploads",
    "backup", "config", "config.php", "admin.php", "user",
    "server-status", "portal", "home", "test", "dev", "staging"
]


# SAFE WORDLIST LOADER FOR HUGE LISTS
def load_wordlist(path: str, limit: int = 50000) -> Optional[List[str]]:
    """
    Load a wordlist from file safely.
    - Handles huge SecLists efficiently
    - Prevents memory explosion with a limit
    - Removes empty lines and spaces
    """
    try:
        words = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= limit:       # protection from monster lists
                    break
                line = line.strip()
                if line:
                    words.append(line)
        return words

    except Exception as e:
        print(f"[!] Failed to load wordlist: {e}")
        return None


# CHECK A SINGLE DIRECTORY
def check_path(base_url: str, path: str, timeout: float = 4.0) -> dict:
    """Check a single directory by joining it with the base URL.
    Returns a dictionary with status code or error."""
    base_url = base_url.rstrip("/")
    url = urljoin(base_url + "/", path)

    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        return {
            "url": url,
            "status_code": r.status_code,
            "content_length": len(r.content),
            "redirect": r.url if r.url != url else None
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


# MAIN BRUTE-FORCE FUNCTION
def brute_force_dirs(base_url: str, wordlist: Optional[List[str]] = None, max_workers: int = 15, timeout: float = 4.0, rate_limit: float = 0. ) -> List[dict]:
    """
    Multithreaded directory brute forcer.
    - base_url: target website
    - wordlist: list of directories (or None to use DEFAULT_WORDLIST)
    - max_workers: threading
    - rate_limit: seconds to sleep per request
    """

    if not wordlist:
        print("[i] No wordlist provided → using default list.")
        wordlist = DEFAULT_WORDLIST

    results = []

    def worker(path):
        result = check_path(base_url, path, timeout)
        """if (rate_limit > 0):
        This checks if you set a delay between requests.
        If rate_limit = 0 → send requests as fast as possible
        If rate_limit = 1 → wait 1 second between each request
        If rate_limit = 0.5 → wait half a second
        time.sleep(rate_limit)
        If rate_limit was set, the thread pauses for X seconds.
        Why?
        To avoid getting blocked by servers or avoid too many requests."""
        if rate_limit > 0:
            time.sleep(rate_limit)  # polite scanning
        return result

    # Thread pool
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(worker, p): p for p in wordlist}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                results.append(res)
            except Exception as e:
                results.append({"url": futures[fut], "error": str(e)})

    # Only keep interesting findings
    interesting = [
        r for r in results
        if ("status_code" in r and r["status_code"] in (200, 301, 302, 403))
    ]

    return interesting
