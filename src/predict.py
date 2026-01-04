from src.preprocess import clean_email
from src.rules import extract_attack_features
from src.emotion import get_emotion_score
from src.explain import generate_explanation
from src.threat import classify_threat

# Keywords for newsletters and BEC attacks
NEWSLETTER_WORDS = ["newsletter", "weekly", "unsubscribe", "highlights"]
BEC_KEYWORDS = [
    "transfer funds", "wire transfer", "send money",
    "urgent request", "need you to", "asap",
    "confidential", "do not tell", "im in a meeting"
]

def predict_email(email_text, model, vectorizer):
    cleaned = clean_email(email_text)
    vec = vectorizer.transform([cleaned])

    ml_proba = float(model.predict_proba(vec)[0][1])
    features = extract_attack_features(email_text)

    # Base score
    score = ml_proba

    # Emotion score (only if ML suggests risk)
    emotion_score = 0.0
    if ml_proba > 0.4:
        emotion_score = get_emotion_score(email_text)
        score = (0.65 * ml_proba) + (0.35 * emotion_score)

    # Threat type default
    threat_type = classify_threat(features)

    # Initialize reasons
    reasons = generate_explanation(features, emotion_score)

    # Cyber overrides
    if features["brand_impersonation"] and features["url_count"]:
        score = max(score, 0.8)

    if features["shortened_url"]:
        score = max(score, 0.85)

    if features["executable_link"]:
        score = max(score, 0.9)

    if features["urgent_words"] >= 2 and emotion_score > 0.4:
        score = max(score, 0.6)

    # Newsletter downgrade
    if sum(w in email_text.lower() for w in NEWSLETTER_WORDS) >= 2:
        score *= 0.5

    # BEC / CEO fraud detection
    bec_hits = [k for k in BEC_KEYWORDS if k in email_text.lower()]
    if bec_hits:
        reasons.append("Possible CEO fraud / BEC attack")
        threat_type = "Business Email Compromise"
        score = max(score, 0.75)

    # Final decision
    if score >= 0.7:
        label, risk = "Phishing Email", "High"
    elif score >= 0.5:
        label, risk = "Suspicious Email", "Medium"
    else:
        label, risk = "Safe Email", "Low"

    return {
        "prediction": label,
        "confidence": round(score, 2),
        "risk_level": risk,
        "url_count": features["url_count"],
        "emotion_score": round(emotion_score, 2),
        "threat_type": threat_type,
        "reasons": reasons
    }
