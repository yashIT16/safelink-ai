"""
generate_dataset.py  (v2 — Real Data + Synthetic Augmentation)
---------------------------------------------------------------
Fetches REAL phishing URLs from URLhaus + OpenPhish feeds.
Falls back to synthetic generation if offline.
Downloads legitimate URLs from a curated list.
Produces a balanced, high-quality training dataset.

Usage:
    python generate_dataset.py
"""

import csv
import random
import urllib.request
import io
import os

# ── Legitimate (safe) URL seeds ───────────────────────────────────────────────
LEGIT_DOMAINS = [
    # Top global sites (Alexa/SimilarWeb inspired)
    "google.com", "youtube.com", "facebook.com", "twitter.com",
    "instagram.com", "linkedin.com", "reddit.com", "wikipedia.org",
    "amazon.com", "netflix.com", "microsoft.com", "apple.com",
    "github.com", "stackoverflow.com", "medium.com", "bbc.com",
    "cnn.com", "nytimes.com", "reuters.com", "theguardian.com",
    "bloomberg.com", "forbes.com", "techcrunch.com", "wired.com",
    "yelp.com", "tripadvisor.com", "booking.com", "airbnb.com",
    "dropbox.com", "slack.com", "zoom.us", "notion.so",
    "stripe.com", "shopify.com", "squarespace.com", "wix.com",
    "wordpress.org", "drupal.org", "mozilla.org", "python.org",
    "nodejs.org", "reactjs.org", "angular.io", "vuejs.org",
    "docker.com", "kubernetes.io", "aws.amazon.com", "cloud.google.com",
    "azure.microsoft.com", "digitalocean.com", "heroku.com", "vercel.com",
]

LEGIT_PATHS = [
    "/", "/home", "/about", "/products", "/services", "/blog",
    "/news", "/contact", "/search?q=test", "/login", "/signup",
    "/account", "/dashboard", "/help", "/faq", "/pricing",
    "/features", "/team", "/careers", "/press", "/legal",
    "/privacy", "/terms", "/support", "/docs", "/api",
]

# ── Phishing URL patterns ─────────────────────────────────────────────────────
PHISHING_WORDS = [
    "secure", "login", "verify", "update", "confirm", "account",
    "bank", "paypal", "ebay", "amazon", "billing", "alert",
    "suspended", "limited", "unlock", "validate", "click",
    "password", "credential", "signin", "apple", "microsoft",
    "netflix", "chase", "wellsfargo", "citibank", "refund",
    "reward", "prize", "winner",
]

HIGH_RISK_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
                  ".top", ".click", ".online", ".site", ".info"]

REAL_BRANDS = ["amazon", "paypal", "google", "microsoft", "apple",
               "netflix", "facebook", "instagram", "chase", "wellsfargo"]


def fetch_urlhaus_phishing(limit=1000):
    """Fetch real phishing/malware URLs from URLhaus (free, no API key)."""
    urls = []
    try:
        print("[→] Fetching URLhaus phishing feed...")
        req = urllib.request.Request(
            "https://urlhaus.abuse.ch/downloads/text_online/",
            headers={"User-Agent": "SafeLink-AI/1.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            for line in content.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and line.startswith("http"):
                    urls.append(line)
                    if len(urls) >= limit:
                        break
        print(f"    [✓] URLhaus: {len(urls)} URLs fetched")
    except Exception as e:
        print(f"    [!] URLhaus unavailable ({e}), using synthetic data")
    return urls


def fetch_openphish_urls(limit=500):
    """Fetch real phishing URLs from OpenPhish community feed (free)."""
    urls = []
    try:
        print("[→] Fetching OpenPhish feed...")
        req = urllib.request.Request(
            "https://openphish.com/feed.txt",
            headers={"User-Agent": "SafeLink-AI/1.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            for line in content.split("\n"):
                line = line.strip()
                if line.startswith("http"):
                    urls.append(line)
                    if len(urls) >= limit:
                        break
        print(f"    [✓] OpenPhish: {len(urls)} URLs fetched")
    except Exception as e:
        print(f"    [!] OpenPhish unavailable ({e}), using synthetic data")
    return urls


def generate_synthetic_phishing(n=800):
    """Generate realistic synthetic phishing URLs."""
    urls = []
    for _ in range(n):
        style = random.randint(0, 6)

        if style == 0:
            # brand.com.evil-domain.xyz/path
            brand = random.choice(REAL_BRANDS)
            tld   = random.choice(HIGH_RISK_TLDS)
            w     = random.choice(PHISHING_WORDS)
            path  = f"/{w}?token={random.randint(100000,999999)}"
            urls.append(f"http://{brand}.com-{w}{tld}{path}")

        elif style == 1:
            # secure-brand-login.xyz
            w1 = random.choice(PHISHING_WORDS)
            w2 = random.choice(REAL_BRANDS)
            tld = random.choice(HIGH_RISK_TLDS)
            urls.append(f"http://{w1}-{w2}-login{tld}/verify")

        elif style == 2:
            # user@evil.tk/phish
            w   = random.choice(PHISHING_WORDS)
            tld = random.choice(HIGH_RISK_TLDS)
            urls.append(f"http://user@{w}-secure{tld}/account/login")

        elif style == 3:
            # IP address phishing
            ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
            path = "/" + "/".join(random.sample(PHISHING_WORDS, 3))
            urls.append(f"http://{ip}{path}?session={random.randint(1000,9999)}")

        elif style == 4:
            # subdomain abuse: paypal.evil-secure.xyz
            brand = random.choice(REAL_BRANDS)
            tld   = random.choice(HIGH_RISK_TLDS)
            urls.append(f"http://{brand}.secure-login{tld}/account/verify")

        elif style == 5:
            # Very long URL with encoded characters
            brand  = random.choice(REAL_BRANDS)
            tld    = random.choice(HIGH_RISK_TLDS)
            junk   = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=30))
            urls.append(f"http://{brand}-{junk}{tld}/login?redirect=evil&token={junk[:10]}")

        else:
            # HTTP only, suspicious keywords in path
            w1 = random.choice(PHISHING_WORDS)
            w2 = random.choice(PHISHING_WORDS)
            dom = ''.join(random.choices("abcdefghijk", k=8))
            tld = random.choice(HIGH_RISK_TLDS)
            urls.append(f"http://{dom}{tld}/{w1}/{w2}?verify=1")

    return urls


def generate_synthetic_legit(n=800):
    """Generate realistic legitimate URLs."""
    urls = []
    for _ in range(n):
        scheme = "https" if random.random() > 0.05 else "http"
        domain = random.choice(LEGIT_DOMAINS)
        path   = random.choice(LEGIT_PATHS)
        # Sometimes add www
        prefix = "www." if random.random() > 0.5 and not domain.startswith("www") else ""
        urls.append(f"{scheme}://{prefix}{domain}{path}")
    return urls


def generate_dataset(
    output_file="dataset.csv",
    target_per_class=2000,
):
    print("\n" + "="*55)
    print("  SafeLink AI — Dataset Generator v2")
    print("="*55)

    # ── Collect phishing URLs ──────────────────────────────────────────────
    phishing = []

    # Try real feeds first
    real_phishing = fetch_urlhaus_phishing(limit=1500)
    phishing.extend(real_phishing)

    real_openphish = fetch_openphish_urls(limit=500)
    phishing.extend(real_openphish)

    # Remove duplicates
    phishing = list(dict.fromkeys(phishing))

    needed = max(0, target_per_class - len(phishing))
    if needed > 0:
        print(f"[→] Generating {needed} synthetic phishing URLs to reach target...")
        phishing.extend(generate_synthetic_phishing(needed))

    phishing = phishing[:target_per_class]

    # ── Collect legit URLs ─────────────────────────────────────────────────
    print("[→] Generating legitimate URLs...")
    legit = generate_synthetic_legit(target_per_class)
    print(f"    [✓] Legit: {len(legit)} URLs")

    # ── Build dataset ──────────────────────────────────────────────────────
    rows = [{"url": u, "label": 0} for u in legit] + \
           [{"url": u, "label": 1} for u in phishing]
    random.shuffle(rows)

    # Remove extremely short/long URLs
    rows = [r for r in rows if 10 < len(r["url"]) < 600]

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)

    safe_count    = sum(1 for r in rows if r["label"] == 0)
    phish_count   = sum(1 for r in rows if r["label"] == 1)
    real_count    = len(real_phishing) + len(real_openphish)

    print(f"\n[✓] Dataset saved → {output_file}")
    print(f"    Total: {len(rows)} | Safe: {safe_count} | Phishing: {phish_count}")
    print(f"    Real phishing URLs: {min(real_count, phish_count)}")
    print(f"    Synthetic phishing URLs: {max(0, phish_count - real_count)}")
    print("="*55 + "\n")
    return output_file


if __name__ == "__main__":
    generate_dataset()
