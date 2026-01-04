import re

PHISHING_KEYWORDS = [
    "urgent", "verify", "account", "login", "password",
    "suspended", "confirm", "immediately", "update"
]

BRAND_KEYWORDS = [
    "google", "paypal", "amazon", "apple", "microsoft", "bank"
]

def extract_attack_features(text):
    t = text.lower()

    return {
        "url_count": len(re.findall(r"http[s]?://", t)),
        "shortened_url": bool(re.search(r"(bit\.ly|tinyurl|t\.co)", t)),
        "urgent_words": sum(w in t for w in PHISHING_KEYWORDS),
        "brand_impersonation": sum(w in t for w in BRAND_KEYWORDS),
        "executable_link": bool(re.search(r"\.(exe|scr|js|bat|zip)", t)),
        "exclamations": text.count("!"),
        "caps_ratio": sum(c.isupper() for c in text) / max(len(text), 1)
    }
