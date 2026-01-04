from transformers import pipeline

emotion_classifier = pipeline(
    "text-classification",
    model="j-hartmann/emotion-english-distilroberta-base",
    top_k=None,
    device=-1
)

RISKY = ["fear", "anger", "sadness", "surprise"]

def get_emotion_score(text):
    if len(text.strip()) < 20:
        return 0.0

    results = emotion_classifier(text[:512])[0]
    score = sum(r["score"] for r in results if r["label"].lower() in RISKY)
    return min(score, 1.0)
