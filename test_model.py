import joblib
from src.predict import predict_email

# Load your saved model and vectorizer
model = joblib.load("models/catboost.pkl")
vectorizer = joblib.load("models/tfidf_vectorizer.pkl")

# Test emails
test_emails = [
    {
        "subject": "Urgent – Account Verification Required",
        "body": """Your Google account will be disabled in 24 hours.
Verify your identity immediately:
https://accounts-google-security.com/login
Failure to comply will result in permanent suspension."""
    },
    {
        "subject": "Invoice Payment Required",
        "body": """Dear Customer,
Your invoice #54892 remains unpaid.
Please complete payment at the link below to avoid penalties:
http://bit.ly/pay-invoice-now"""
    },
    {
        "subject": "Document Shared With You",
        "body": """You have received a secure document.
Download immediately:
https://docs-share-download.net/file.exe"""
    },
    {
        "subject": "Immediate Assistance Needed",
        "body": """Hi,
I’m stuck in a meeting and urgently need you to help me.
Please respond as soon as possible.
Thanks"""
    },
    {
        "subject": "Weekly Tech Newsletter",
        "body": """This week’s highlights:
- AI trends
- Cybersecurity updates
- Cloud best practices
Read more on our website."""
    },
    {
        "subject": "Meeting Follow-Up",
        "body": """Hi,
Following up on our earlier discussion.
Please review the attached details and confirm.
Best, Admin Team"""
    },
    {
        "subject": "Please help me",
        "body": """I’m really scared right now.
My account was accessed and I might lose everything.
Can you please verify this link?"""
    },
    {
        "subject": "Urgent request",
        "body": """I’m in a meeting.
Need you to transfer funds immediately."""
    }
]

print("\n=== PHISHING EMAIL DETECTION TEST ===\n")

for i, email in enumerate(test_emails, 1):
    print(f"--- Test Email {i} ---")
    print(f"Subject: {email['subject']}")
    print(f"Body: {email['body']}\n")

    result = predict_email(email['body'], model, vectorizer)

    print("Analyze Email")
    print(f"Prediction: {result['prediction']}")
    print(f"Confidence: {result['confidence']*100:.2f}%")
    print(f"Emotion Risk Score: {result['emotion_score']*100:.1f}%")
    print(f"Risk Level: {result['risk_level']}")
    print(f"URLs Found: {result['url_count']}")
    print(f"Threat Type: {result['threat_type']}")
    if result['reasons']:
        print("Reasons:")
        for r in result['reasons']:
            print(f"- {r}")
    print("\n")
