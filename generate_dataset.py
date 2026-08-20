"""
generate_dataset.py
--------------------
Builds a labeled training dataset of phishing vs legitimate URLs.

Uses a curated list of real, well-known legitimate domains (label=0)
and programmatically generates realistic phishing-style URLs (label=1)
based on common attack patterns: brand impersonation, IP-based hosting,
suspicious keywords, lookalike domains, and URL shorteners.

This keeps the project self-contained (no external dataset download
required) while still producing believable, feature-diverse data.
"""

import random
import csv

random.seed(42)

LEGIT_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "amazon.com", "wikipedia.org",
    "apple.com", "netflix.com", "linkedin.com", "stackoverflow.com", "nytimes.com",
    "bbc.com", "reddit.com", "yahoo.com", "twitter.com", "instagram.com",
    "dropbox.com", "spotify.com", "adobe.com", "salesforce.com", "paypal.com",
    "chase.com", "bankofamerica.com", "irs.gov", "nasa.gov", "harvard.edu",
    "mit.edu", "who.int", "un.org", "cnn.com", "espn.com",
]

LEGIT_PATHS = [
    "", "/about", "/products", "/blog/2024/update", "/docs/getting-started",
    "/careers", "/contact", "/help/support", "/news/latest", "/user/settings",
]

BRANDS_TO_SPOOF = [
    "paypal", "amazon", "apple", "microsoft", "netflix", "chase", "bankofamerica",
    "google", "facebook", "instagram", "wellsfargo", "americanexpress", "dhl", "usps",
]

SUSPICIOUS_TLDS = ["xyz", "top", "club", "info", "tk", "gq", "ml", "cf", "buzz", "click"]

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "signin",
    "password", "suspend", "urgent", "unlock", "recover", "billing", "support-center",
]

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly"]


def random_alnum(n):
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(n))


def make_legit_url():
    domain = random.choice(LEGIT_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = "https"
    return f"{scheme}://www.{domain}{path}"


def make_phishing_url():
    style = random.choice(["ip", "lookalike", "keyword_subdomain", "shortener", "hyphen_brand"])

    if style == "ip":
        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        word = random.choice(SUSPICIOUS_WORDS)
        return f"http://{ip}/{word}/{random_alnum(6)}.php"

    if style == "lookalike":
        brand = random.choice(BRANDS_TO_SPOOF)
        tld = random.choice(SUSPICIOUS_TLDS)
        word = random.choice(SUSPICIOUS_WORDS)
        return f"http://{brand}-{word}-{random_alnum(4)}.{tld}"

    if style == "keyword_subdomain":
        brand = random.choice(BRANDS_TO_SPOOF)
        word = random.choice(SUSPICIOUS_WORDS)
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"http://{word}.{brand}.{random_alnum(5)}.{tld}"

    if style == "shortener":
        shortener = random.choice(SHORTENERS)
        return f"http://{shortener}/{random_alnum(7)}"

    if style == "hyphen_brand":
        brand = random.choice(BRANDS_TO_SPOOF)
        word1 = random.choice(SUSPICIOUS_WORDS)
        word2 = random.choice(SUSPICIOUS_WORDS)
        tld = random.choice(SUSPICIOUS_TLDS)
        return f"http://{brand}-{word1}-{word2}.{tld}"

    return f"http://{random_alnum(10)}.{random.choice(SUSPICIOUS_TLDS)}"


def build_dataset(n_per_class=500):
    rows = []
    for _ in range(n_per_class):
        rows.append((make_legit_url(), 0))
    for _ in range(n_per_class):
        rows.append((make_phishing_url(), 1))
    random.shuffle(rows)
    return rows


if __name__ == "__main__":
    data = build_dataset(600)
    with open("urls_dataset.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(data)
    print(f"Wrote {len(data)} rows to urls_dataset.csv")
    print("Sample phishing URLs:")
    for url, label in data[:5]:
        print(" ", url, "->", "PHISHING" if label == 1 else "LEGIT")
