from flask import Flask, render_template, request, jsonify
import joblib
from src.predict import predict_email
import os

app = Flask(__name__)

# Load ML model and vectorizer
model = joblib.load("models/catboost.pkl")
vectorizer = joblib.load("models/tfidf_vectorizer.pkl")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    email_text = data.get('email_text', '')
    
    if not email_text.strip():
        return jsonify({"error": "Please enter email content"}), 400
    
    result = predict_email(email_text, model, vectorizer)
    return jsonify(result)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
