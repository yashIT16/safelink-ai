"""
feature_extractor.py  (v2 — Production Grade)
----------------------------------------------
Extracts 22 numerical features from a URL for phishing detection.
Shared between train_model.py and the Flask API.
"""

import re
import math
from urllib.parse import urlparse, urlencode

# ── Suspicious keywords ──────────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    "login", "verify", "secure", "bank", "account", "update",
    "confirm", "billing", "alert", "suspended", "limited",
    "unlock", "validate", "click", "password", "credential",
    "signin", "paypal", "ebay", "amazon", "apple", "microsoft",
    "netflix", "wellsfargo", "chase", "citibank", "hsbc",
    "refund", "reward", "prize", "winner", "claim",
]

# ── High-risk TLDs ───────────────────────────────────────────────────────────
HIGH_RISK_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".top", ".click", ".link", ".online", ".site", ".info",
    ".biz", ".cc", ".ws", ".me.uk", ".co.cc",
}

# ── Trusted TLDs (low risk) ──────────────────────────────────────────────────
TRUSTED_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".co.uk", ".io"}

FEATURE_NAMES = [
    "url_length",           # 1
    "num_dots",             # 2
    "has_at",               # 3
    "has_dash_in_domain",   # 4
    "has_https",            # 5
    "num_subdomains",       # 6
    "has_ip_address",       # 7
    "num_special_chars",    # 8
    "path_length",          # 9
    "has_suspicious_keyword",# 10
    "keyword_count",        # 11
    "has_www",              # 12
    "num_digits_in_domain", # 13
    "domain_length",        # 14
    "url_entropy",          # 15  NEW
    "digit_ratio",          # 16  NEW
    "letter_ratio",         # 17  NEW
    "has_port",             # 18  NEW
    "has_query",            # 19  NEW
    "query_length",         # 20  NEW
    "high_risk_tld",        # 21  NEW
    "path_depth",           # 22  NEW
]


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((f / total) * math.log2(f / total) for f in freq.values())


def extract_features(url: str) -> list:
    """
    Extract a 22-feature vector from a URL string.
    Returns a list of floats suitable for ML inference.
    """
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        domain_raw = parsed.netloc or ""
        path       = parsed.path or ""
        query      = parsed.query or ""
        scheme     = parsed.scheme or "http"
        full_url   = url.lower()
    except Exception:
        return [0.0] * len(FEATURE_NAMES)

    # Strip port from domain
    domain = domain_raw.split(":")[0].lower()
    parts  = [p for p in domain.split(".") if p]

    # ── 1. URL length
    url_length = len(url)

    # ── 2. Number of dots
    num_dots = url.count(".")

    # ── 3. Has @ symbol
    has_at = 1 if "@" in url else 0

    # ── 4. Dash in domain
    has_dash_in_domain = 1 if "-" in domain else 0

    # ── 5. HTTPS
    has_https = 1 if scheme == "https" else 0

    # ── 6. Number of subdomains (parts beyond domain + TLD)
    num_subdomains = max(0, len(parts) - 2)

    # ── 7. IP address as domain
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    has_ip_address = 1 if ip_pattern.match(domain) else 0

    # ── 8. Special characters count
    num_special_chars = len(re.findall(r"[?=&%#!@~]", url))

    # ── 9. Path length
    path_length = len(path)

    # ── 10. Has suspicious keyword
    has_suspicious_keyword = 1 if any(kw in full_url for kw in PHISHING_KEYWORDS) else 0

    # ── 11. Keyword count
    keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in full_url)

    # ── 12. Has www
    has_www = 1 if domain.startswith("www.") else 0

    # ── 13. Digits in domain
    num_digits_in_domain = len(re.findall(r"\d", domain))

    # ── 14. Domain length
    domain_length = len(domain)

    # ── 15. URL entropy (high entropy = more random = suspicious)
    url_entropy = round(_entropy(url), 4)

    # ── 16. Digit ratio in full URL
    digits_in_url = len(re.findall(r"\d", url))
    digit_ratio   = round(digits_in_url / max(len(url), 1), 4)

    # ── 17. Letter ratio in full URL
    letters_in_url = len(re.findall(r"[a-zA-Z]", url))
    letter_ratio   = round(letters_in_url / max(len(url), 1), 4)

    # ── 18. Has port
    has_port = 1 if ":" in domain_raw and not domain_raw.endswith(":") else 0

    # ── 19. Has query string
    has_query = 1 if query else 0

    # ── 20. Query length
    query_length = len(query)

    # ── 21. High-risk TLD
    tld = "." + parts[-1] if parts else ""
    high_risk_tld = 1 if tld.lower() in HIGH_RISK_TLDS else 0

    # ── 22. Path depth (number of slashes in path)
    path_depth = path.count("/")

    return [
        float(url_length),
        float(num_dots),
        float(has_at),
        float(has_dash_in_domain),
        float(has_https),
        float(num_subdomains),
        float(has_ip_address),
        float(num_special_chars),
        float(path_length),
        float(has_suspicious_keyword),
        float(keyword_count),
        float(has_www),
        float(num_digits_in_domain),
        float(domain_length),
        float(url_entropy),
        float(digit_ratio),
        float(letter_ratio),
        float(has_port),
        float(has_query),
        float(query_length),
        float(high_risk_tld),
        float(path_depth),
    ]
