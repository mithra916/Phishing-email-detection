# Phishing Email Detection System (ML + NLP + Flask)

## Live Demo

Live Application: [<PASTE_YOUR_LIVE_LINK_HERE>](https://phishing-email-detection-su6j.onrender.com/)

## Project Overview

Phishing emails are one of the most common cybersecurity threats, exploiting human trust through deceptive language and urgency.
This project implements an end-to-end phishing email detection system using Natural Language Processing (NLP) and Machine Learning, deployed as a live web application.

Users can paste email content into a web dashboard and instantly receive:

Phishing / Safe classification

Confidence score

Risk assessment

## Features

NLP-based text preprocessing

TF-IDF feature extraction

Multiple ML models trained and compared

High phishing recall (~98%)

Live prediction using Flask API

Interactive web dashboard (HTML, CSS, JavaScript)

Deployed and publicly accessible


## Machine Learning Models Used

The following models were trained and evaluated:

Logistic Regression

Random Forest

XGBoost

CatBoost ✅ (Best performing model)

Support Vector Machine (SVM)

Naive Bayes

CatBoost was selected for deployment due to its strong balance between precision and recall.


## Model Performance

Phishing Recall: ~97–98%

Low False Negatives, which is critical for cybersecurity systems

Evaluation done using:

Confusion Matrix

Precision, Recall, F1-score

## Tech Stack

Backend

Python

Flask

Scikit-learn

CatBoost

XGBoost

NLP

TF-IDF Vectorization

Text cleaning and normalization

Frontend

HTML

CSS

JavaScript

Deployment

Flask-based web service

Deployed on cloud platform

## Project Structure
```
phishing-email-detection/
│
├── app.py
├── train_models.py
├── test_model.py
├── requirements.txt
├── README.md
│
├── models/
│   ├── catboost.pkl
│   └── tfidf_vectorizer.pkl
│
├── src/
│   ├── preprocess.py
│   ├── predict.py
│   └── __init__.py
│
├── templates/
│   └── index.html
│
└── static/
    ├── style.css
    └── script.js
```


## How It Works

Email text is cleaned and normalized

TF-IDF converts text into numerical features

Trained ML model predicts phishing probability

Result and confidence are displayed on the dashboard

## API Usage

Endpoint: /predict
Method: POST

Request Body

{
  "email_text": "Urgent! Verify your account immediately."
}


Response

{
  "prediction": "Phishing Email",
  "confidence": 0.73
}

## Future Enhancements

Risk-level classification (Low / Medium / High)

Suspicious keyword explanation

Cross-dataset validation

Transformer-based NLP models (BERT)

## Why This Project Matters

Demonstrates real-world cybersecurity problem solving

Covers full ML lifecycle: data → model → evaluation → deployment

Shows full-stack skills: ML + Backend + Frontend

Production-style thinking with recall-focused evaluation
