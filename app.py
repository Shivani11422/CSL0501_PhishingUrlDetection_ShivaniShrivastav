from flask import Flask, render_template, request
import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

# -----------------------------
# LOAD DATA
# -----------------------------
data = pd.read_csv("phishing_dataset.csv")
data = data.dropna()
data['label'] = data['label'].astype(int)

# -----------------------------
# TRUSTED DOMAINS
# -----------------------------
def is_trusted(domain):
    trusted = [
        "google.com", "accounts.google.com",
        "amazon.in", "facebook.com",
        "youtube.com", "youtu.be",
        "paytm.com", "instagram.com"
    ]

    for t in trusted:
        if domain == t or domain.endswith("." + t):
            return True
    return False

# -----------------------------
# URL VALIDATION
# -----------------------------
def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

# -----------------------------
# FEATURE EXTRACTION
# -----------------------------
def url_features(url):
    suspicious_words = [
        "login", "verify", "update", "secure",
        "account", "bank", "signin", "confirm", "otp"
    ]

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    features = [
        url.count('@'),
        url.count('-'),
        url.count('.'),
        len(url),
        len(domain),
        int(url.startswith("https://")),
        int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),
        sum(word in url.lower() for word in suspicious_words),
        domain.count('.'),
        url.count('//')
    ]

    return features

# -----------------------------
# TRAIN MODEL
# -----------------------------
X = np.array([url_features(u) for u in data["url"]])
y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=12,
    random_state=42
)

model.fit(X_train, y_train)

# -----------------------------
# FLASK ROUTE
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"].strip()

        if not is_valid_url(url):
            return render_template("index.html", result="⚠️ Invalid URL", analysis=[])

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        analysis = []

        # -----------------------------
        # SPOOFING DETECTION
        # -----------------------------
        brands = ["google", "amazon", "facebook", "paypal", "paytm", "instagram"]

        for b in brands:
            if b in domain.split(".")[:-1] and not is_trusted(domain):
                return render_template(
                    "blocked.html",
                    url=url,
                    analysis=[
                        "🚨 Fake brand impersonation detected",
                        "⚠️ Suspicious domain structure",
                        "🚨 High Risk Phishing Website"
                    ]
                )

        # -----------------------------
        # WHITELIST
        # -----------------------------
        if is_trusted(domain):
            return render_template(
                "index.html",
                result="✅ Legitimate Website (Trusted)",
                analysis=["Trusted domain detected"]
            )

        # -----------------------------
        # ML PREDICTION
        # -----------------------------
        features = np.array([url_features(url)])
        prob = model.predict_proba(features)[0][1]

        confidence = round(prob * 100, 2)

        analysis.append(f"Phishing Confidence: {confidence}%")

        # -----------------------------
        # REASONS (EXPLAINABLE AI)
        # -----------------------------
        if "login" in url:
            analysis.append("⚠️ Suspicious keyword: login")

        if "verify" in url:
            analysis.append("⚠️ Suspicious keyword: verify")

        if "secure" in url:
            analysis.append("⚠️ Suspicious keyword: secure")

        if len(url) > 50:
            analysis.append("⚠️ Long URL detected")

        if re.search(r'\d+\.\d+\.\d+\.\d+', url):
            analysis.append("⚠️ IP address used instead of domain")

        # -----------------------------
        # FINAL DECISION
        # -----------------------------
        if prob >= 0.65:

            if prob >= 0.85:
                analysis.append("🚨 High Risk Phishing Website")

            return render_template(
                "blocked.html",
                url=url,
                analysis=analysis + ["🚨 Phishing Website Detected"]
            )
        else:
            return render_template(
                "index.html",
                result=" Legitimate Website",
                analysis=analysis
            )

    return render_template("index.html", result="", analysis=[])

# -----------------------------
# RUN APP
# -----------------------------
if __name__ == "__main__":
    print("Server running...")
    app.run(debug=True)