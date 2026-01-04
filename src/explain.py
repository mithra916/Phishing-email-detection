def generate_explanation(features, emotion_score):
    reasons = []

    if features["url_count"] > 0:
        reasons.append("Contains external link")

    if features["shortened_url"]:
        reasons.append("Uses shortened URL")

    if features["brand_impersonation"]:
        reasons.append("Possible brand impersonation")

    if features["urgent_words"] >= 2:
        reasons.append("Urgent or threatening language")

    if features["executable_link"]:
        reasons.append("Executable file link detected")

    if emotion_score > 0.4:
        reasons.append("Emotional manipulation detected")

    return reasons
