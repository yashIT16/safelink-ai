"""
fetch_top_domains.py
--------------------
Downloads the Tranco Top 1 Million list, unzips it in memory,
extracts the top 200,000 domains, and saves them to a text file.
This creates an enterprise-grade global allowlist to completely
eliminate false positives on real websites.
"""

import os
import urllib.request
import zipfile
import io

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TOP_N = 200000  # We will whitelist the top 200k global domains natively
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
OUTPUT_FILE = os.path.join(DATA_DIR, "top_200k_whitelist.txt")

def main():
    print(f"[→] Downloading Tranco Top 1 Million list from {TRANCO_URL}")
    print("    (This might take a minute...)")
    
    try:
        req = urllib.request.Request(TRANCO_URL, headers={"User-Agent": "SafeLink-AI/1.0"})
        with urllib.request.urlopen(req) as resp:
            zip_data = resp.read()
    except Exception as e:
        print(f"[!] Target unavailable: {e}. Trying secondary mirror...")
        # Fallback to Cisco Umbrella Top 1M if Tranco is blocking or down
        fallback_url = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
        req = urllib.request.Request(fallback_url, headers={"User-Agent": "SafeLink-AI/1.0"})
        with urllib.request.urlopen(req) as resp:
            zip_data = resp.read()

    print("[✓] Download complete. Extracting top 200,000 domains...")
    
    domains = []
    with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
        # Get the first filename in the zip
        filename = z.namelist()[0]
        with z.open(filename) as f:
            for i, line in enumerate(f):
                if i >= TOP_N:
                    break
                # Tranco lines look like: 1,google.com
                # Umbrella lines look like: 1,google.com
                try:
                    parts = line.decode("utf-8").strip().split(",")
                    if len(parts) >= 2:
                        domains.append(parts[1].lower())
                except:
                    continue

    print(f"[→] Found {len(domains)} domains. Saving to {OUTPUT_FILE}")
    
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        for dom in domains:
            out.write(dom + "\n")
            
    print("[✓] Global Allowlist built successfully!")

if __name__ == "__main__":
    main()
