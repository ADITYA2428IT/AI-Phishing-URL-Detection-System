"""
soc_alert.py
------------
Converts a raw model prediction into a SOC-style security alert:
risk score, severity level, human-readable reasons, and a logged
alert record (simulating a SOC alert queue / SIEM entry).
"""

import json
import os
from datetime import datetime, timezone

ALERT_LOG_PATH = "alert_log.jsonl"


def compute_risk_score(features: dict, phishing_probability: float) -> int:
    """
    Combine model confidence with rule-based signal boosts to produce
    a 0-100 risk score. This mirrors how real SOC tools blend ML
    output with deterministic indicators for analyst trust/explainability.
    """
    score = phishing_probability * 100

    # Rule-based boosts (bounded so ML probability still dominates)
    if features["has_ip_address"]:
        score += 8
    if features["has_at_symbol"]:
        score += 5
    if not features["has_https"]:
        score += 5
    if features["is_shortened"]:
        score += 5
    if features["num_suspicious_keywords"] >= 2:
        score += 5

    return int(min(round(score), 100))


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "INFO"


def build_reasons(features: dict) -> list:
    """Human-readable justifications, the way a SOC analyst would
    annotate an alert ticket."""
    reasons = []

    if features["has_ip_address"]:
        reasons.append("URL uses a raw IP address instead of a domain name")
    if features["has_at_symbol"]:
        reasons.append("URL contains '@' symbol, often used to obscure the real destination")
    if not features["has_https"]:
        reasons.append("Connection is not secured with HTTPS")
    if features["is_shortened"]:
        reasons.append("URL uses a link-shortening service, which can hide the true destination")
    if features["num_suspicious_keywords"] >= 1:
        reasons.append(f"Contains {features['num_suspicious_keywords']} phishing-associated keyword(s) (e.g. login, verify, secure)")
    if features["num_subdomains"] >= 2:
        reasons.append("Unusually high number of subdomains, a common brand-impersonation tactic")
    if features["hostname_entropy"] >= 3.8:
        reasons.append("Domain name shows high randomness, suggesting an auto-generated phishing domain")
    if features["num_hyphens"] >= 2:
        reasons.append("Multiple hyphens in domain, often used to mimic legitimate brand names")
    if features["has_double_slash_redirect"]:
        reasons.append("Path contains a redirect pattern ('//') sometimes used to disguise destinations")

    if not reasons:
        reasons.append("No major structural red flags detected in URL")

    return reasons


def generate_alert(url: str, features: dict, prediction: int, phishing_probability: float) -> dict:
    risk_score = compute_risk_score(features, phishing_probability)
    severity = severity_from_score(risk_score)
    reasons = build_reasons(features)

    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "prediction": "PHISHING" if prediction == 1 else "LEGITIMATE",
        "phishing_probability": round(phishing_probability, 4),
        "risk_score": risk_score,
        "severity": severity,
        "reasons": reasons,
        "recommended_action": recommended_action(severity),
    }
    return alert


def recommended_action(severity: str) -> str:
    return {
        "CRITICAL": "Block URL immediately and notify SOC team for incident response.",
        "HIGH": "Block URL and flag associated user activity for review.",
        "MEDIUM": "Warn user before allowing access; log for monitoring.",
        "LOW": "Allow with logging; no immediate action required.",
        "INFO": "No action needed. URL appears legitimate.",
    }[severity]


def log_alert(alert: dict, path: str = ALERT_LOG_PATH):
    """Append alert to a JSONL log, simulating a SOC alert queue / SIEM feed."""
    with open(path, "a") as f:
        f.write(json.dumps(alert) + "\n")


def load_alert_log(path: str = ALERT_LOG_PATH, limit: int = 50) -> list:
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        lines = f.readlines()[-limit:]
    return [json.loads(line) for line in reversed(lines)]
