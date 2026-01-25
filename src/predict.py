import re
from src.preprocess import clean_email
from src.emotion import get_emotion_score

SHORTENERS = ["bit.ly", "tinyurl", "t.co"]
BRANDS = ["google", "paypal", "microsoft", "bank"]
EXECUTABLES = [".exe", ".zip", ".js"]

def predict_email(email_text, model, vectorizer):
    reasons = []
    threat_type = "Benign / Informational"

    cleaned = clean_email(email_text)
    vector = vectorizer.transform([cleaned])
    proba = model.predict_proba(vector)[0][1]

    urls = re.findall(r"http[s]?://\S+", email_text.lower())
    url_count = len(urls)

    if url_count > 0:
        reasons.append("Contains external link")

    for u in urls:
        if any(s in u for s in SHORTENERS):
            reasons.append("Uses shortened URL")
        if any(ext in u for ext in EXECUTABLES):
            reasons.append("Executable file link detected")
            threat_type = "Malware Delivery"

    if any(b in email_text.lower() for b in BRANDS):
        reasons.append("Possible brand impersonation")
        threat_type = "Credential Harvesting"

    if any(w in email_text.lower() for w in ["urgent", "immediately", "verify", "suspend"]):
        reasons.append("Urgent or threatening language")

    emotion_score = get_emotion_score(email_text)

    final_score = (0.65 * proba) + (0.35 * emotion_score)

    if final_score >= 0.75:
        label = "Phishing Email"
        risk = "High"
    elif final_score >= 0.5:
        label = "Suspicious Email"
        risk = "Medium"
    else:
        label = "Safe Email"
        risk = "Low"

    if threat_type == "Benign / Informational" and label != "Safe Email":
        threat_type = "Social Engineering"

    return {
        "prediction": label,
        "confidence": round(final_score, 2),
        "emotion_score": emotion_score,
        "risk_level": risk,
        "url_count": url_count,
        "threat_type": threat_type,
        "reasons": reasons
    }
