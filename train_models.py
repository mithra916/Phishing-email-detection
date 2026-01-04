# ==============================
# train_models.py
# Full training script for Phishing Email Detection
# ==============================
'''
import pandas as pd
import re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.naive_bayes import MultinomialNB
from xgboost import XGBClassifier
from catboost import CatBoostClassifier
import joblib
import os

# -----------------------------
# 1️⃣ Load dataset
# -----------------------------
df = pd.read_csv('data/Phishing_Email.csv')  # update if needed
df = df.dropna(subset=['Email Text'])

# -----------------------------
# 2️⃣ Basic cleaning
# -----------------------------
def clean_email(text):
    text = str(text).lower()
    text = re.sub(r'\r\n', ' ', text)
    text = re.sub(r'<.*?>', '', text)
    text = re.sub(r'http\S+', ' URL ', text)
    return text.strip()

df['Email Text'] = df['Email Text'].apply(clean_email)
df['label'] = df['Email Type'].apply(lambda x: 1 if x=='Phishing Email' else 0)

# -----------------------------
# 3️⃣ Train/Test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    df['Email Text'], df['label'], test_size=0.15, random_state=42, stratify=df['label']
)

# -----------------------------
# 4️⃣ TF-IDF vectorization
# -----------------------------
vectorizer = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1,2),
    stop_words='english'
)
X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

# -----------------------------
# 5️⃣ Define all models
# -----------------------------
models = {
    'Logistic Regression': LogisticRegression(max_iter=500),
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
    'XGBoost': XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42),
    'CatBoost': CatBoostClassifier(verbose=0, random_state=42),
    'Naive Bayes': MultinomialNB(),
    'SVM': LinearSVC()
}

# -----------------------------
# 6️⃣ Train, evaluate, save
# -----------------------------
os.makedirs('models', exist_ok=True)

results = {}

for name, model in models.items():
    print(f"\n===== Training {name} =====")
    model.fit(X_train_tfidf, y_train)
    
    y_pred = model.predict(X_test_tfidf)
    
    # Metrics
    from sklearn.metrics import accuracy_score, classification_report
    acc = accuracy_score(y_test, y_pred)
    results[name] = acc
    print(f"Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred))
    
    # Save model
    filename = f"models/{name.lower().replace(' ', '_')}.pkl"
    joblib.dump(model, filename)
    print(f"✅ {name} saved at {filename}")

# -----------------------------
# 7️⃣ Save TF-IDF vectorizer
# -----------------------------
joblib.dump(vectorizer, 'models/tfidf_vectorizer.pkl')
print("\n✅ TF-IDF Vectorizer saved successfully!")

# -----------------------------
# 8️⃣ Compare all models
# -----------------------------
print("\n===== Model Accuracy Comparison =====")
for name, acc in sorted(results.items(), key=lambda x: x[1], reverse=True):
    print(f"{name}: {acc:.4f}")

print("\nAll models trained, evaluated, and saved in 'models/' folder!")
'''



# ==============================
# train_models.py
# Phishing Email Detection – Model Training
# ==============================

import pandas as pd
import re
import os
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
from catboost import CatBoostClassifier

# -----------------------------
# 1️⃣ Load dataset
# -----------------------------
df = pd.read_csv('data/Phishing_Email.csv')
df = df.dropna(subset=['Email Text'])

# -----------------------------
# 2️⃣ Text cleaning
# -----------------------------
def clean_email(text):
    text = str(text).lower()
    text = re.sub(r'\r\n', ' ', text)
    text = re.sub(r'<.*?>', '', text)
    text = re.sub(r'http\S+', ' URL ', text)
    text = re.sub(r'[^a-zA-Z\s]', ' ', text)
    return text.strip()

df['Email Text'] = df['Email Text'].apply(clean_email)
df['label'] = df['Email Type'].apply(lambda x: 1 if x == 'Phishing Email' else 0)

# -----------------------------
# 3️⃣ Train / Test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    df['Email Text'],
    df['label'],
    test_size=0.15,
    random_state=42,
    stratify=df['label']
)

# -----------------------------
# 4️⃣ TF-IDF Vectorizer
# -----------------------------
vectorizer = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1, 2),
    stop_words='english'
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

# -----------------------------
# 5️⃣ Train CatBoost
# -----------------------------
print("\n===== Training CatBoost =====")

model = CatBoostClassifier(
    loss_function='Logloss',
    class_weights=[1, 1.5],  # penalize phishing errors
    iterations=300,
    verbose=0,
    random_state=42
)


model.fit(X_train_tfidf, y_train)

# -----------------------------
# 6️⃣ Evaluation
# -----------------------------
y_pred = model.predict(X_test_tfidf)

acc = accuracy_score(y_test, y_pred)
print(f"Accuracy: {acc:.4f}")
print(classification_report(y_test, y_pred))

# -----------------------------
# 7️⃣ Save model & vectorizer
# -----------------------------
os.makedirs('models', exist_ok=True)

joblib.dump(model, 'models/catboost.pkl')
joblib.dump(vectorizer, 'models/tfidf_vectorizer.pkl')

print("\n✅ Model saved: models/catboost.pkl")
print("✅ Vectorizer saved: models/tfidf_vectorizer.pkl")
print("🎉 Training complete")
