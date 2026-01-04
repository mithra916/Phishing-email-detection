def classify_threat(features):
    if features["brand_impersonation"] and features["url_count"]:
        return "Credential Harvesting"

    if features["shortened_url"]:
        return "Financial Scam"

    if features["executable_link"]:
        return "Malware Delivery"

    if features["urgent_words"] >= 2:
        return "Social Engineering"

    return "Benign / Informational"
