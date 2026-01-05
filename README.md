# Phishing Email Detection System

## Project Overview

Phishing emails are one of the most common cybersecurity threats, exploiting human trust through deceptive language and urgency.
This project detects whether an email is Safe, Suspicious, or Phishing by combining:
- Classical ML (TF-IDF + classifiers)
- Rule-based cyber heuristics
- Emotional manipulation detection
- Explainable risk analysis
The goal is not just accuracy, but understanding why an email is flagged, which is critical in real-world cybersecurity workflows.

## Key Features
### ML-Based Classification
TF-IDF vectorization (unigrams + bigrams)
Trained models:
- CatBoost (primary)
- Logistic Regression
- Random Forest
- SVM
- Naive Bayes
Final system uses CatBoost for best balance of performance and interpretability

### Explainability (Cyber-Focused)
Instead of returning only a label, the system explains:
- Why the email was flagged
- Which risk indicators were detected

### Emotional Manipulation Detection
Uses a transformer-based emotion model to detect:
- Fear
- Urgency
- Pressure
- Manipulative tone
Emotional score is combined with ML prediction to reduce false negatives in social engineering attacks.

### Rule-Based Attack Feature Engineering
Cyber-specific heuristics:
- URL presence & shortened URLs
- Executable file links (.exe, .zip)
- Urgency keywords (verify, urgent, suspend)
- Financial scam indicators
- Brand impersonation keywords
- Excessive capitalization
These rules help reduce false positives and false negatives, especially in edge cases like CEO fraud (BEC).

### Threat Categorization
Instead of binary output, emails are categorized into:
- Credential Harvesting
- Financial Scam
- Malware Delivery
- Social Engineering
- Benign / Informational
This mirrors real SOC alert classification.

### Risk Scoring System
Final output includes:
- Prediction (Safe / Suspicious / Phishing)
- Confidence score
- Risk level (Low / Medium / High)
- Emotion risk score
- URL count
- Threat type
- Reasons (explainability)

## How to Run
1.Install dependencies : 
pip install -r requirements.txt

2️.Train the model : 
python train_models.py

3️.Run the web app : 
python app.py

Open browser:
http://127.0.0.1:5000/

## Limitations (Honest)
This is not a production-grade email gateway
Model depends on dataset quality
Emotion detection adds latency on CPU
Advanced spear-phishing may bypass heuristics

## Future Improvements
Header analysis (SPF, DKIM, DMARC)
Domain reputation checks
Attachment scanning
Online learning with feedback loop
SOC-style alert dashboard with logs
