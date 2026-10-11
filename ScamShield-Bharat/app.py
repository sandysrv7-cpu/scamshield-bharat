from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re
import ipaddress

app = Flask(__name__)

URGENT_TERMS = [
    "urgent", "immediately", "account blocked", "suspended", "verify now",
    "within 24 hours", "act now", "உடனே", "கணக்கு முடக்கம்", "तुरंत", "खाता बंद"
]
CREDENTIAL_TERMS = [
    "password", "otp", "one-time password", "pin", "cvv", "bank details",
    "உங்கள் otp", "கடவுச்சொல்", "ओटीपी", "पासवर्ड", "बैंक विवरण"
]
MONEY_TERMS = [
    "pay now", "send money", "processing fee", "claim prize", "won a prize",
    "gift card", "வெகுமதி", "பணம் அனுப்ப", "इनाम", "पैसे भेजें"
]
SUSPICIOUS_TERMS = [
    "click this link", "click here", "verify your account", "kyc update",
    "free gift", "job offer", "work from home", "உடனே கிளிக்", "यहां क्लिक"
]

def analyze_message(message):
    text = (message or "").strip()
    if not text:
        return {"error": "Please enter a message to analyze."}

    lower = text.lower()
    findings = []
    score = 0

    for phrase in URGENT_TERMS:
        if phrase in lower:
            findings.append(f"Urgency or pressure language detected: “{phrase}”.")
            score += 2
            break
    for phrase in CREDENTIAL_TERMS:
        if phrase in lower:
            findings.append(f"Possible request for sensitive information: “{phrase}”.")
            score += 3
            break
    for phrase in MONEY_TERMS:
        if phrase in lower:
            findings.append(f"Money, prize, or payment wording detected: “{phrase}”.")
            score += 2
            break
    for phrase in SUSPICIOUS_TERMS:
        if phrase in lower:
            findings.append(f"Potential scam wording detected: “{phrase}”.")
            score += 2
            break
    if re.search(r'https?://|www\.', lower):
        findings.append("The message contains a web link. Check the destination independently.")
        score += 1
    if re.search(r'\b\d{6}\b', text):
        findings.append("A six-digit number appears. Never share an OTP with another person.")
    if not findings:
        findings.append("No known warning patterns were detected. This does not prove the message is safe.")

    level = "high" if score >= 5 else "medium" if score >= 2 else "low"
    advice = {
        "high": "Treat this message as suspicious. Do not click links, pay, or share credentials. Verify through an official app or number.",
        "medium": "Be cautious. Independently verify the sender and request before taking action.",
        "low": "Few known warning patterns were detected, but remain cautious and verify important requests."
    }
    return {"level": level, "score": min(score, 10), "findings": findings, "advice": advice[level],
            "notice": "This is a rule-based screening result, not a guarantee or a trained AI verdict."}

def analyze_url(raw_url):
    value = (raw_url or "").strip()
    if not value:
        return {"error": "Please enter a URL to check."}
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parsed = urlparse(value)
    if not parsed.hostname:
        return {"error": "That URL does not appear to be valid. Check the spelling and try again."}

    findings = []
    score = 0
    host = parsed.hostname.lower()

    try:
        ipaddress.ip_address(host)
        findings.append("The address uses a raw IP address instead of a typical domain name.")
        score += 2
    except ValueError:
        pass

    if parsed.scheme.lower() != "https":
        findings.append("The URL does not use HTTPS.")
        score += 1
    if "@" in parsed.netloc:
        findings.append("The URL contains an @ symbol in its network location, which can be misleading.")
        score += 2
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"]
    if any(host == domain or host.endswith("." + domain) for domain in shorteners):
        findings.append("This appears to use a URL-shortening service, which hides the final destination.")
        score += 2
    if len(host) > 45 or host.count("-") >= 3:
        findings.append("The domain has an unusual length or many hyphens. Check it carefully.")
        score += 1
    if not findings:
        findings.append("No basic URL warning patterns were detected. This does not prove the site is trustworthy.")

    level = "high" if score >= 4 else "medium" if score >= 2 else "low"
    advice = {
        "high": "Avoid opening this link unless you can verify it through a trusted official source.",
        "medium": "Check the exact domain carefully and navigate to the official website yourself.",
        "low": "No basic warning pattern was detected, but do not enter personal or payment details unless you trust the site."
    }
    return {"level": level, "score": min(score, 10), "findings": findings, "advice": advice[level],
            "notice": "The checker does not visit the URL or confirm website reputation. It uses simple URL heuristics."}

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/api/analyze/message")
def message_api():
    data = request.get_json(silent=True) or {}
    result = analyze_message(data.get("message", ""))
    return jsonify(result), (400 if "error" in result else 200)

@app.post("/api/analyze/url")
def url_api():
    data = request.get_json(silent=True) or {}
    result = analyze_url(data.get("url", ""))
    return jsonify(result), (400 if "error" in result else 200)

if __name__ == "__main__":
    app.run(debug=True)
