EMOTIONAL_TRIGGERS = {
    "fear": ["scared", "afraid", "panic", "compromised"],
    "urgency": ["urgent", "immediately", "now", "asap", "24 hours"],
    "threat": ["suspend", "disable", "terminate", "blocked"],
    "pressure": ["verify", "confirm", "act now"]
}

def get_emotion_score(text):
    text = text.lower()
    hits = 0

    for group in EMOTIONAL_TRIGGERS.values():
        for word in group:
            if word in text:
                hits += 1

    return round(min(hits / 6, 1.0), 2)
