from transformers import pipeline

# Lightweight emotion classifier (CPU friendly)
emotion_classifier = pipeline(
    "text-classification",
    model="j-hartmann/emotion-english-distilroberta-base",
    top_k=None
)

def get_emotion_score(text: str) -> float:
    """
    Returns normalized emotional manipulation score (0–1)
    Focused on fear, urgency, anger
    """

    try:
        results = emotion_classifier(text[:512])[0]  # truncate for safety
    except Exception:
        return 0.0

    high_risk_emotions = {"fear", "anger", "sadness"}

    score = 0.0
    for item in results:
        if item["label"].lower() in high_risk_emotions:
            score += item["score"]

    return round(min(score, 1.0), 2)
