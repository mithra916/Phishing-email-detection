from flask import Flask, render_template, request, jsonify
import joblib
import os
from src.predict import predict_email

app = Flask(__name__)

# Load model & vectorizer
MODEL_PATH = "models/catboost.pkl"
VECTORIZER_PATH = "models/tfidf_vectorizer.pkl"

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    email_text = data.get("email_text", "")

    if not email_text.strip():
        return jsonify({"error": "Empty email content"}), 400

    result = predict_email(email_text, model, vectorizer)
    return jsonify(result)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
