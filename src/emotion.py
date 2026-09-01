from transformers import pipeline


_emotion_model = None

RISKY = {
    "fear",
    "anger",
    "sadness",
    "disgust",
}


def _get_emotion_model():
    global _emotion_model

    if _emotion_model is None:
        _emotion_model = pipeline(
            "text-classification",
            model="j-hartmann/emotion-english-distilroberta-base",
            top_k=None,
        )

    return _emotion_model


def get_emotion_score(text):
    if not isinstance(text, str):
        return 0.0

    if len(text.strip()) < 20:
        return 0.0

    emotion_classifier = _get_emotion_model()

    results = emotion_classifier(
        text[:512]
    )[0]

    score = sum(
        result["score"]
        for result in results
        if result["label"].lower() in RISKY
    )

    return min(score, 1.0)