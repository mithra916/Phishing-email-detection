'''
from transformers import pipeline

_emotion_model = None

def get_emotion_score(text):
    if len(text.strip()) < 20:
        return 0.0

    results = emotion_classifier(text[:512])[0]
    score = sum(r["score"] for r in results if r["label"].lower() in RISKY)
    return min(score, 1.0)
