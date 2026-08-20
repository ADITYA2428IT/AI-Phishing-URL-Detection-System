"""
feature_extraction.py
----------------------
Extracts security-relevant features from a URL for phishing classification.

Each feature corresponds to a real-world phishing indicator used by
ethical hackers / SOC analysts when triaging suspicious links.
"""

import re
import math
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "signin", "password", "webscr", "ebayisapi",
    "suspend", "urgent", "click", "limited", "unlock", "recover"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st"
]


def shannon_entropy(s: str) -> float:
    """Measure randomness of a string. Phishing domains often use
    randomly generated subdomains, which have higher entropy."""
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def has_ip_address(hostname: str) -> bool:
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(pattern, hostname or ""))


def extract_features(url: str) -> dict:
    """
    Returns a dict of numeric/boolean features for a given URL.
    This dict is later converted into a feature vector for the ML model.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url_for_parse = "http://" + url
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full = url.lower()

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "num_dots": hostname.count("."),
        "num_hyphens": hostname.count("-"),
        "num_subdomains": max(hostname.count(".") - 1, 0),
        "has_ip_address": int(has_ip_address(hostname)),
        "has_at_symbol": int("@" in url),
        "has_https": int(parsed.scheme == "https"),
        "is_shortened": int(any(s in hostname for s in SHORTENERS)),
        "num_suspicious_keywords": sum(1 for k in SUSPICIOUS_KEYWORDS if k in full),
        "hostname_entropy": round(shannon_entropy(hostname), 3),
        "has_double_slash_redirect": int("//" in path),
        "digit_ratio_in_hostname": round(
            sum(c.isdigit() for c in hostname) / len(hostname), 3
        ) if hostname else 0.0,
        "path_length": len(path),
    }
    return features


def features_to_vector(features: dict) -> list:
    """Fixed feature order used consistently for training and inference."""
    order = [
        "url_length", "hostname_length", "num_dots", "num_hyphens",
        "num_subdomains", "has_ip_address", "has_at_symbol", "has_https",
        "is_shortened", "num_suspicious_keywords", "hostname_entropy",
        "has_double_slash_redirect", "digit_ratio_in_hostname", "path_length",
    ]
    return [features[k] for k in order]


FEATURE_ORDER = [
    "url_length", "hostname_length", "num_dots", "num_hyphens",
    "num_subdomains", "has_ip_address", "has_at_symbol", "has_https",
    "is_shortened", "num_suspicious_keywords", "hostname_entropy",
    "has_double_slash_redirect", "digit_ratio_in_hostname", "path_length",
]


if __name__ == "__main__":
    test_urls = [
        "http://secure-login-verify-account.xyz",
        "https://www.google.com",
        "http://192.168.1.1/login/signin.php",
        "https://github.com/anthropics",
    ]
    for u in test_urls:
        print(u, "->", extract_features(u))
