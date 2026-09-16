"""
app.py
------
Streamlit interface for the AI-Based Phishing Detection & Security
Alert System.

Run with:  streamlit run app.py
"""

import pickle
import pandas as pd
import streamlit as st

from feature_extraction import extract_features, FEATURE_ORDER
from soc_alert import generate_alert, log_alert, load_alert_log

st.set_page_config(
    page_title="AI Phishing Detection & SOC Alert System",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_resource
def load_model():
    with open("phishing_model.pkl", "rb") as f:
        return pickle.load(f)


model = load_model()

SEVERITY_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#dc2626",
    "MEDIUM": "#d97706",
    "LOW": "#65a30d",
    "INFO": "#16a34a",
}

st.title("🛡️ AI-Based Phishing Detection & Security Alert System")
st.caption("Cyber Security · Ethical Hacking · AI Threat Detection · SOC Automation")

tab1, tab2, tab3 = st.tabs(["🔍 Analyze URL", "📊 Alert Dashboard", "ℹ️ How It Works"])

# ---------------- TAB 1: Analyze ----------------
with tab1:
    st.subheader("Check a URL for phishing indicators")

    example_col, _ = st.columns([2, 1])
    with example_col:
        st.markdown("**Try an example:**")
        ex_cols = st.columns(3)
        examples = [
            "http://secure-login-verify-account.xyz",
            "https://www.github.com",
            "http://192.168.10.4/signin/verify.php",
        ]
        for i, ex in enumerate(examples):
            if ex_cols[i].button(ex, use_container_width=True):
                st.session_state["url_input"] = ex

    url = st.text_input(
        "Enter a URL or paste an email link:",
        value=st.session_state.get("url_input", ""),
        placeholder="e.g. http://secure-login-verify-account.xyz",
    )

    analyze = st.button("🔎 Analyze", type="primary")

    if analyze and url.strip():
        features = extract_features(url)
        X = pd.DataFrame([features])[FEATURE_ORDER]

        prediction = model.predict(X)[0]
        probability = model.predict_proba(X)[0][1]  # probability of class 1 (phishing)

        alert = generate_alert(url, features, prediction, probability)
        log_alert(alert)

        color = SEVERITY_COLORS[alert["severity"]]

        if prediction == 1:
            st.markdown(
                f"""
                <div style="padding:20px;border-radius:10px;background-color:{color}22;
                border:2px solid {color};">
                <h3 style="color:{color};margin-top:0;">⚠️ PHISHING DETECTED</h3>
                <b>Risk Score:</b> {alert['risk_score']} / 100 &nbsp;|&nbsp;
                <b>Severity:</b> <span style="color:{color};font-weight:bold;">{alert['severity']}</span><br>
                <b>Model Confidence:</b> {alert['phishing_probability']*100:.1f}%
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
                <div style="padding:20px;border-radius:10px;background-color:{color}22;
                border:2px solid {color};">
                <h3 style="color:{color};margin-top:0;">✅ LIKELY LEGITIMATE</h3>
                <b>Risk Score:</b> {alert['risk_score']} / 100 &nbsp;|&nbsp;
                <b>Severity:</b> <span style="color:{color};font-weight:bold;">{alert['severity']}</span><br>
                <b>Model Confidence (legitimate):</b> {(1-alert['phishing_probability'])*100:.1f}%
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("#### 📋 Reasons")
        for r in alert["reasons"]:
            st.markdown(f"- {r}")

        st.markdown("#### 🛠️ Recommended SOC Action")
        st.info(alert["recommended_action"])

        with st.expander("🔬 Extracted features (technical detail)"):
            st.json(features)

    elif analyze:
        st.warning("Please enter a URL first.")

# ---------------- TAB 2: Dashboard ----------------
with tab2:
    st.subheader("Recent Security Alerts (simulated SOC alert queue)")
    alerts = load_alert_log(limit=100)

    if not alerts:
        st.info("No alerts logged yet. Analyze a URL in the first tab to generate one.")
    else:
        df = pd.DataFrame(alerts)
        df_display = df[["timestamp", "url", "prediction", "risk_score", "severity"]]
        st.dataframe(df_display, use_container_width=True, hide_index=True)

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Scanned", len(df))
        col2.metric("Phishing Flagged", int((df["prediction"] == "PHISHING").sum()))
        col3.metric("Critical/High Severity", int(df["severity"].isin(["CRITICAL", "HIGH"]).sum()))

        st.markdown("#### Severity Breakdown")
        st.bar_chart(df["severity"].value_counts())

# ---------------- TAB 3: How It Works ----------------
with tab3:
    st.subheader("System Architecture")
    st.markdown(
        """
        ```
        URL Input
            ↓
        Feature Extraction (14 security-relevant features)
            ↓
        ML Model (Random Forest Classifier)
            ↓
        Phishing Probability
            ↓
        Risk Scoring Engine (ML + rule-based signal boosts)
            ↓
        SOC Alert Generation (severity, reasons, recommended action)
            ↓
        Alert Logged to Queue
        ```
        """
    )

    st.markdown("#### Features analyzed")
    st.markdown(
        """
        - **Structural**: URL length, hostname length, path length
        - **Domain**: subdomain count, hyphens, dots, entropy (randomness)
        - **Security**: HTTPS presence, IP-based hosting, `@` symbol usage
        - **Content**: phishing-associated keywords (login, verify, secure, etc.)
        - **Evasion**: URL shortener usage, redirect patterns
        """
    )

    st.markdown("#### Why Random Forest?")
    st.markdown(
        """
        - Provides **feature importance**, so every alert can be explained —
          critical for SOC analyst trust and for your presentation.
        - Performs well on structured/tabular data without heavy tuning.
        - Fast inference, suitable for near real-time detection.
        """
    )

    st.markdown("#### Certificate mapping")
    st.table(pd.DataFrame({
        "Certificate": ["Cyber Security", "Ethical Hacking", "AI for Cyber Security", "SOC Automation"],
        "Project Connection": [
            "Protects users by detecting malicious URLs before access",
            "Uses knowledge of real phishing tactics to engineer detection features",
            "ML model classifies threats from structural/behavioral patterns",
            "Automatically generates, scores, and logs security alerts",
        ],
    }))
