# AI-Based Phishing Detection & Security Alert System

An end-to-end system that takes a URL, extracts security-relevant features,
classifies it as phishing or legitimate using a machine learning model, and
generates a SOC-style security alert with a risk score and recommended action.

Built to connect three areas:
- **Cyber Security** — protecting users from malicious links
- **Ethical Hacking** — understanding real phishing attack patterns to engineer detection features
- **AI for Cyber Security (Threat Detection / SOC Automation)** — ML-based classification and automated alert generation

---

## Project Structure

```
phishing_detector/
├── feature_extraction.py   # Extracts 14 phishing-indicative features from a URL
├── generate_dataset.py     # Builds a labeled dataset of phishing/legit URLs
├── train_model.py          # Trains and evaluates the Random Forest classifier
├── soc_alert.py            # Risk scoring, severity levels, alert generation & logging
├── app.py                  # Streamlit web app (main demo interface)
├── urls_dataset.csv        # Generated training dataset (1,200 labeled URLs)
├── phishing_model.pkl      # Trained model (ready to use)
├── training_report.json    # Accuracy/precision/recall + feature importances
└── requirements.txt
```

## How to Run

```bash
pip install -r requirements.txt

# (Optional — a trained model is already included)
python generate_dataset.py
python train_model.py

# Launch the app
streamlit run app.py
```

The app opens in your browser with three tabs:
1. **Analyze URL** — paste a URL, get an instant phishing verdict + alert
2. **Alert Dashboard** — simulated SOC alert queue with severity breakdown
3. **How It Works** — architecture diagram + certificate mapping (useful slide content)

## How It Works

```
URL Input
    ↓
Feature Extraction (14 features: entropy, keywords, IP usage, HTTPS, etc.)
    ↓
ML Model (Random Forest Classifier)
    ↓
Phishing Probability
    ↓
Risk Scoring Engine (ML confidence + rule-based signal boosts)
    ↓
SOC Alert (severity, reasons, recommended action)
    ↓
Logged to alert queue
```

## Key Features Extracted
| Category | Features |
|---|---|
| Structural | URL length, hostname length, path length |
| Domain | subdomain count, hyphens, dots, entropy (randomness) |
| Security | HTTPS presence, IP-based hosting, `@` symbol |
| Content | phishing keywords (login, verify, secure, account...) |
| Evasion | URL shorteners, redirect patterns |

## Model Notes
- **Algorithm:** Random Forest (chosen for explainability via feature importance — important for justifying SOC alerts to an analyst)
- **Training data:** Programmatically generated from real legitimate domains + realistic phishing patterns (IP hosting, brand lookalikes, suspicious TLDs, keyword stuffing, shorteners)
- **Note for presentation:** this synthetic dataset is clearly separable, so the model scores ~100% on it. In a real deployment you'd train on a live-labeled dataset (e.g. PhishTank, OpenPhish) where classes overlap more and accuracy would be lower (~90-97% is typical in published research). Mentioning this shows you understand the limitation, not just the result.

## Example
**Input:** `http://secure-login-verify-account.xyz`

**Output:**
```
⚠️ PHISHING DETECTED
Risk Score: 100/100
Severity: CRITICAL
Reasons:
 • Connection is not secured with HTTPS
 • Contains 4 phishing-associated keywords (login, verify, secure)
 • Domain shows high randomness
 • Multiple hyphens in domain
Recommended Action: Block URL immediately and notify SOC team.
```

## Possible Extensions (good for a "future work" slide)
- Email header/body analysis (not just URLs)
- Live domain age lookup via WHOIS API
- Integration with a real SIEM (e.g. Splunk, ELK) instead of local JSONL log
- Browser extension front-end
