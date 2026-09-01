# 🛡️ BodWid

### Explainable Phishing Email Detection & Threat Intelligence Platform

<p align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge\&logo=python\&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-API-000000?style=for-the-badge\&logo=flask\&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=for-the-badge\&logo=scikit-learn\&logoColor=white)
![CatBoost](https://img.shields.io/badge/CatBoost-ML-FFCC00?style=for-the-badge)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Threat%20Intel-394EFF?style=for-the-badge)
![Pytest](https://img.shields.io/badge/Tests-102%20passed-0A9F6E?style=for-the-badge\&logo=pytest\&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

</p>

<p align="center">

**BodWid is a multi-layer email security engine that combines machine learning, behavioral heuristics, language analysis, email-header forensics, URL analysis, threat intelligence, and weighted risk scoring to detect and explain phishing attacks.**

</p>

---

## 📌 Overview

Modern phishing attacks rarely rely on a single suspicious characteristic.

An email may contain:

* A legitimate-looking sender address
* A spoofed or mismatched `Reply-To`
* Failed SPF/DKIM/DMARC authentication
* Urgent or threatening language
* Brand impersonation
* A shortened URL
* A malicious external resource
* Social-engineering language
* A domain or IP with a poor reputation

BodWid approaches the problem as a **multi-signal security analysis problem** rather than relying on a single classifier.

```text
                         ┌─────────────────────┐
                         │      RAW EMAIL      │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
       ┌────────────┐       ┌────────────┐       ┌────────────┐
       │    ML      │       │   Header   │       │    URL     │
       │ Detection  │       │  Forensics │       │  Analysis  │
       └─────┬──────┘       └─────┬──────┘       └─────┬──────┘
             │                    │                    │
             ▼                    ▼                    ▼
       ┌────────────┐       ┌────────────┐       ┌────────────┐
       │   Rules    │       │   SPF /    │       │  Threat    │
       │  Engine    │       │ DKIM/DMARC │       │ Intelligence│
       └─────┬──────┘       └─────┬──────┘       └─────┬──────┘
             │                    │                    │
             └────────────────────┼────────────────────┘
                                  ▼
                       ┌────────────────────┐
                       │   Language Layer   │
                       │ Emotion / Social   │
                       │ Engineering Signals│
                       └─────────┬──────────┘
                                 │
                                 ▼
                       ┌────────────────────┐
                       │    RISK ENGINE     │
                       │ Weighted Signals   │
                       └─────────┬──────────┘
                                 │
                                 ▼
                       ┌────────────────────┐
                       │ Threat Classifier  │
                       └─────────┬──────────┘
                                 │
                                 ▼
                       ┌────────────────────┐
                       │ Explainable Result │
                       └────────────────────┘
```

---

# 🎯 Objectives

BodWid is designed around five primary goals:

### 1. Detect

Identify potentially malicious, phishing, and socially engineered emails.

### 2. Correlate

Combine independent security signals instead of trusting a single indicator.

### 3. Enrich

Use email headers, URLs, public IPs, domains, and external threat intelligence to increase context.

### 4. Explain

Provide human-readable reasons behind the final classification.

### 5. Normalize

Convert heterogeneous security signals into a bounded risk score suitable for an API or security dashboard.

---

# 🧠 Detection Philosophy

BodWid does **not** make its final decision from ML probability alone.

Instead:

```text
             ┌─────────────────────┐
             │ ML Probability      │
             └──────────┬──────────┘
                        │
             ┌──────────▼──────────┐
             │ Rule-Based Signals  │
             └──────────┬──────────┘
                        │
             ┌──────────▼──────────┐
             │ Language Analysis   │
             └──────────┬──────────┘
                        │
             ┌──────────▼──────────┐
             │ Emotion Analysis    │
             └──────────┬──────────┘
                        │
             ┌──────────▼──────────┐
             │ Header Forensics    │
             └──────────┬──────────┘
                        │
             ┌──────────▼──────────┐
             │ Threat Intelligence │
             └──────────┬──────────┘
                        │
                        ▼
                 ┌─────────────┐
                 │ Risk Engine │
                 └──────┬──────┘
                        │
                        ▼
                 Final Risk Score
```

This architecture reduces dependence on a single detection mechanism and allows individual signals to contribute independently to the final assessment.

---

# 🏗️ Architecture

## High-Level Architecture

```text
                         ┌───────────────────┐
                         │     Email Input   │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ Email Preprocessor│
                         └─────────┬─────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
              ▼                    ▼                    ▼
       ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
       │ ML Pipeline  │     │ Rule Engine  │     │ Language     │
       │ TF-IDF + ML  │     │ Attack       │     │ Analyzer     │
       └──────┬───────┘     │ Features     │     └──────┬───────┘
              │             └──────┬───────┘            │
              │                    │                    │
              └────────────────────┼────────────────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ Header Analyzer   │
                         │                   │
                         │ From / Reply-To   │
                         │ Return-Path       │
                         │ SPF / DKIM / DMARC│
                         │ Received / IPs    │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │   URL Analyzer    │
                         │                   │
                         │ Extraction        │
                         │ Deduplication     │
                         │ Shorteners        │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ Threat Intel      │
                         │                   │
                         │ Domains           │
                         │ Public IPs        │
                         │ URLs              │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │   Risk Engine     │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ Threat Classifier │
                         └─────────┬─────────┘
                                   │
                                   ▼
                         ┌───────────────────┐
                         │ Explainable JSON  │
                         └───────────────────┘
```

---

# 🔬 Detection Layers

## 01 — Machine Learning Detection

BodWid uses a supervised machine-learning pipeline to estimate the probability that an email belongs to the phishing class.

### Pipeline

```text
Raw Email
   │
   ▼
Preprocessing
   │
   ▼
Text Cleaning
   │
   ▼
TF-IDF Vectorization
   │
   ▼
ML Classifier
   │
   ▼
Phishing Probability
```

The ML probability becomes one of the inputs to the risk engine.

The architecture is intentionally separated so the classifier can be improved independently from the other security-analysis layers.

---

## 02 — Rule-Based Attack Detection

The rule layer identifies deterministic or high-value attack characteristics.

Examples include:

* External URL presence
* Brand impersonation
* Shortened URLs
* Executable links
* Urgency indicators
* Suspicious attack patterns

The rule score is normalized before entering the risk engine.

---

# 🗣️ 03 — Email Language Analysis

Phishing attacks frequently use social-engineering techniques.

BodWid analyzes language patterns associated with:

* Urgency
* Threats
* Credential requests
* Authority
* Pressure
* Financial manipulation

Example:

```text
Language Analysis
       │
       ├── Urgency
       ├── Threat
       ├── Credentials
       ├── Authority
       ├── Pressure
       └── Financial language
                    │
                    ▼
             Language Score
```

The language analyzer produces both a normalized score and structured indicators.

---

# 🧠 04 — Emotion Analysis

Emotional manipulation is a common phishing technique.

BodWid separately analyzes emotional signals and incorporates the resulting score into the overall risk model.

Examples of signals include attempts to create:

* Fear
* Urgency
* Panic
* Pressure
* Emotional dependency

The emotion layer is intentionally kept separate from language analysis so that the risk engine can treat the two as independent signals.

---

# 📧 05 — Email Header Forensics

BodWid performs security-focused analysis of raw email headers.

### Address Extraction

The analyzer extracts:

```text
From
 ├── Display Name
 ├── Email Address
 ├── Local Part
 └── Domain

Reply-To
 ├── Email Address
 └── Domain

Return-Path
 ├── Email Address
 └── Domain
```

### Domain Mismatch Detection

BodWid compares:

```text
From Domain
      │
      ├──────────────► Reply-To Domain
      │
      └──────────────► Return-Path Domain
```

Potential mismatches are converted into structured indicators.

Example:

```text
From:        support@example.com
Reply-To:    attacker@malicious.example
```

Result:

```text
Reply-To domain differs from From domain
```

---

## Authentication Analysis

BodWid parses existing `Authentication-Results` headers.

Supported signals include:

```text
SPF
DKIM
DMARC
```

Possible authentication states are normalized into structured results.

Important:

> BodWid parses authentication results already present in the email. It does not independently perform SPF, DKIM, or DMARC validation.

---

## Received Header Analysis

`Received` headers are analyzed for IP addresses.

Extracted IP information includes:

```text
IP Address
IP Version
Private
Global
Loopback
Reserved
```

Private/internal addresses are not sent to external reputation services.

---

# 🔗 06 — URL Analysis

BodWid extracts URLs from email content before performing additional analysis.

### URL Processing

```text
Email
 │
 ▼
URL Extraction
 │
 ▼
Normalization
 │
 ▼
Duplicate Removal
 │
 ▼
URL Classification
 │
 ├── Normal
 ├── Shortened
 └── Suspicious
```

The analyzer also detects URL-shortening behavior and preserves URL-specific indicators for the final explanation.

---

# 🌐 07 — Threat Intelligence

BodWid optionally integrates with **VirusTotal** for reputation enrichment.

The integration can analyze:

```text
        Threat Intelligence
                │
       ┌────────┼────────┐
       ▼        ▼        ▼
    Domains     IPs      URLs
       │        │        │
       └────────┼────────┘
                ▼
         Reputation Data
                │
                ▼
         Risk Contribution
```

### Domain Intelligence

Sender-related domains can be checked.

### IP Intelligence

Public IP addresses extracted from `Received` headers can be checked.

### URL Intelligence

URLs extracted from the email body can be checked.

### Graceful Failure

Threat intelligence is an optional enrichment layer.

If:

* `VIRUSTOTAL_API_KEY` is not configured
* the API is unavailable
* a lookup fails
* a lookup returns an error

the core email-analysis pipeline continues.

This prevents an external service failure from becoming a complete application failure.

---

# ⚖️ 08 — Risk Engine

The risk engine is the central signal-correlation layer.

Instead of relying on:

```text
ML prediction → final answer
```

BodWid combines multiple normalized signals:

```text
ML Score
     │
Rule Score
     │
Language Score
     │
Emotion Score
     │
Header Score
     │
Threat Intelligence Score
     │
     ▼
┌─────────────────────────┐
│      Risk Engine        │
│                         │
│ Weighted Signal Fusion  │
└────────────┬────────────┘
             │
             ▼
       Final Score
```

Each signal is bounded before being combined.

The final score is also clamped to the normalized range:

```text
0.0 ─────────────────────────────── 1.0
 │                                   │
Safe                              Highest
```

---

# 🚨 Risk Classification

BodWid maps the normalized score into three operational categories:

```text
┌─────────────────────────────────────────┐
│                0.0                      │
│                 │                       │
│                 ▼                       │
│            LOW RISK                     │
│                                         │
│                 │                       │
│                 ▼                       │
│          MEDIUM / SUSPICIOUS            │
│                                         │
│                 │                       │
│                 ▼                       │
│            HIGH / PHISHING              │
│                                         │
│                 ▼                       │
│                1.0                      │
└─────────────────────────────────────────┘
```

The implementation applies additional security-specific overrides for particularly strong indicators.

Examples include:

* Brand impersonation combined with URLs
* Shortened URLs
* Executable links
* Authentication failures
* Header mismatches
* Malicious threat-intelligence results

These overrides prevent a strong security indicator from being hidden by a lower ML probability.

---

# 🧩 09 — Threat Intelligence Overrides

Certain signals represent strong evidence and can raise the minimum final score.

### Malicious Indicator

```text
Malicious reputation detected
           │
           ▼
      High-risk floor
```

### Suspicious Indicator

```text
Suspicious reputation detected
           │
           ▼
    Suspicious-risk floor
```

This provides a security-oriented distinction between:

```text
Statistical probability
        vs.
External security evidence
```

---

# 🧠 10 — Explainability

BodWid does not only return a classification.

It also produces human-readable reasons.

Example signals:

```text
Contains external link
Uses shortened URL
Possible brand impersonation
Urgent or threatening language
Executable file link detected
Emotional manipulation detected
```

Header analysis can add evidence such as:

```text
Header: Reply-To domain differs from From domain
Header: SPF result: fail
Header: DMARC result: fail
```

Threat intelligence can contribute:

```text
Threat intelligence identified a malicious indicator
```

This makes the result more useful for analysts because the output contains **evidence instead of only a label**.

---

# 🧪 Testing

BodWid currently has:

```text
╔══════════════════════════════╗
║        TEST STATUS           ║
║                              ║
║        ✅ 102 PASSED         ║
║        ❌ 0 FAILED           ║
╚══════════════════════════════╝
```

Run the complete suite:

```bash
python -m pytest -v
```

The test suite covers the major security-analysis layers.

### Header Analyzer

Tests include:

* Header extraction
* Sender domains
* Reply-To mismatches
* Return-Path mismatches
* Authentication results
* SPF/DKIM/DMARC indicators
* Received headers
* IP extraction
* Private IP detection
* Duplicate IP removal
* Invalid input handling

### Language Analyzer

Tests include:

* Urgency detection
* Threat detection
* Credential detection
* Authority detection
* Pressure detection
* Financial language
* Case-insensitive matching
* Score boundaries
* Empty/invalid input handling

### Risk Engine

Tests include:

* Default weight validation
* Zero-score behavior
* Maximum-score behavior
* ML contribution
* Threat-intelligence contribution
* Score clamping
* Medium/high thresholds
* Custom weights
* Invalid weights
* Header scoring
* Threat-intelligence scoring

### Threat Intelligence

Tests include:

* API-key handling
* Domain normalization
* Domain lookup
* IP lookup
* URL lookup
* Malicious indicators
* Suspicious indicators
* Empty indicators
* Authentication failures
* Request failures

### URL Analyzer

Tests include:

* URL extraction
* Multiple URLs
* Duplicate removal
* Trailing punctuation
* Shortened URLs
* Subdomain shorteners
* Normal URLs
* Empty input
* Complete URL analysis

### Integration

The prediction pipeline is also tested to ensure the individual analysis layers work together.

---

# 📊 Example Detection Flow

A phishing email might produce:

```text
                     EMAIL
                       │
                       ▼
              ┌─────────────────┐
              │ ML Probability  │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Language Risk   │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Header Evidence │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ URL Reputation  │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Threat Intel    │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   Risk Engine   │
              └────────┬────────┘
                       │
                       ▼
                 HIGH RISK
                       │
                       ▼
              PHISHING EMAIL
```

---

# 📦 Project Structure

```text
phishing-email-detection/
│
├── src/
│   ├── preprocess.py
│   ├── predict.py
│   ├── rules.py
│   ├── emotion.py
│   ├── explain.py
│   ├── threat.py
│   ├── language_analyzer.py
│   ├── header_analyzer.py
│   ├── url_analyzer.py
│   ├── threat_intel.py
│   └── risk_engine.py
│
├── tests/
│   ├── test_header_analyzer.py
│   ├── test_language_analyzer.py
│   ├── test_prediction_integration.py
│   ├── test_risk_engine.py
│   ├── test_threat_intel.py
│   └── test_url_analyzer.py
│
├── data/
│
├── models/
│
├── app.py
│
├── requirements.txt
│
└── README.md
```

---

# 🧱 Core Modules

| Module                 | Responsibility                       |
| ---------------------- | ------------------------------------ |
| `preprocess.py`        | Email text preprocessing             |
| `predict.py`           | Main prediction pipeline             |
| `rules.py`             | Rule-based attack feature extraction |
| `emotion.py`           | Emotional manipulation analysis      |
| `language_analyzer.py` | Social-engineering language analysis |
| `header_analyzer.py`   | Email header security analysis       |
| `url_analyzer.py`      | URL extraction and analysis          |
| `threat_intel.py`      | VirusTotal integration               |
| `risk_engine.py`       | Weighted risk aggregation            |
| `threat.py`            | Threat categorization                |
| `explain.py`           | Human-readable explanations          |

---

# 🚀 Quick Start

## 1. Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd phishing-email-detection
```

## 2. Create a virtual environment

### Windows

```powershell
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 4. Run tests

```bash
python -m pytest -v
```

Expected result:

```text
102 passed
```

## 5. Start the application

```bash
python app.py
```

---

# 🔑 Threat Intelligence Configuration

VirusTotal enrichment is optional.

Set the API key as an environment variable.

### Windows PowerShell

```powershell
$env:VIRUSTOTAL_API_KEY="YOUR_API_KEY"
```

### Linux / macOS

```bash
export VIRUSTOTAL_API_KEY="YOUR_API_KEY"
```

Do **not** hard-code API credentials inside the source code.

Do **not** commit secrets to Git.

---

# 🔐 Security Considerations

BodWid follows a layered security-analysis approach.

### No single signal is trusted

ML, rules, language, headers, URLs, and reputation data are treated as separate evidence sources.

### External intelligence is optional

The application remains functional when VirusTotal is unavailable.

### Scores are bounded

Individual analysis layers and the final risk score are normalized to prevent uncontrolled values.

### Explainable decisions

The system returns indicators that contributed to the final assessment.

### Separation of responsibilities

Individual analysis modules are isolated so that detection logic can be tested and improved independently.

---

# ⚠️ Limitations

BodWid is a security-analysis and decision-support system. It should not be treated as a complete replacement for enterprise email-security infrastructure.

Current limitations include:

* ML performance depends on training data quality.
* Phishing techniques evolve continuously.
* Header information can be incomplete or manipulated.
* Threat-intelligence services can have incomplete coverage.
* URL reputation is dependent on external intelligence.
* Rule-based indicators can produce false positives.
* Legitimate emails can contain language or URLs that resemble phishing signals.
* Detection results should be interpreted alongside additional security context.

---

# 🗺️ Roadmap

## Detection Engine

* [x] ML-based phishing classification
* [x] Rule-based attack detection
* [x] Emotion analysis
* [x] Language analysis
* [x] Email header forensics
* [x] URL extraction
* [x] URL analysis
* [x] Threat intelligence
* [x] Weighted risk engine
* [x] Threat classification
* [x] Explainable detection reasons
* [x] Automated test suite

## Dashboard

* [ ] Advanced security dashboard
* [ ] Risk score visualization
* [ ] Header-forensics panel
* [ ] URL intelligence panel
* [ ] Threat-intelligence visualization
* [ ] Language/emotion indicators
* [ ] Explainable risk timeline
* [ ] Analyst-oriented UI
* [ ] Improved result summaries

## Future Security Capabilities

* [ ] IOC export
* [ ] Analyst investigation workflow
* [ ] Historical email analysis
* [ ] Detection analytics
* [ ] Model evaluation dashboard
* [ ] Production deployment hardening

---

# 📈 Development Status

```text
Core Detection Engine       ████████████████████  Complete
Header Forensics            ████████████████████  Complete
Language Analysis           ████████████████████  Complete
URL Analysis                ████████████████████  Complete
Threat Intelligence         ████████████████████  Complete
Risk Engine                 ████████████████████  Complete
Explainability              ████████████████████  Complete
Automated Testing           ████████████████████  Complete

Dashboard                   ███████████░░░░░░░░░  Next Phase
```

---

# 🧪 Quality Gate

Before considering a change complete:

```bash
python -m pytest -v
```

The project currently passes:

```text
102 tests
0 failures
```

A feature should not be considered complete until its behavior is covered by automated tests.

---

# 🛠️ Technology Stack

| Technology   | Purpose              |
| ------------ | -------------------- |
| Python       | Core implementation  |
| Flask        | API layer            |
| scikit-learn | ML pipeline          |
| CatBoost     | Classification       |
| TF-IDF       | Text representation  |
| pytest       | Automated testing    |
| VirusTotal   | Threat intelligence  |
| Pandas       | Data processing      |
| NumPy        | Numerical processing |

---

# 🔄 End-to-End Pipeline

```text
┌──────────────────────────────────────────────────────────────┐
│                         RAW EMAIL                            │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │   PREPROCESSING   │
                    └─────────┬─────────┘
                              │
             ┌────────────────┼─────────────────┐
             │                │                 │
             ▼                ▼                 ▼
        ┌─────────┐      ┌──────────┐      ┌──────────┐
        │   ML    │      │  Rules   │      │ Language │
        └────┬────┘      └─────┬────┘      └────┬─────┘
             │                 │                │
             └─────────────────┼────────────────┘
                               │
                               ▼
                    ┌───────────────────┐
                    │ Emotion Analysis  │
                    └─────────┬─────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │ Header Forensics  │
                    └─────────┬─────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │   URL Analysis    │
                    └─────────┬─────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │ Threat Intelligence│
                    └─────────┬─────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │    RISK ENGINE    │
                    └─────────┬─────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │ Threat Classifier │
                    └─────────┬─────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │    EXPLANATION    │
                    └─────────┬─────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │ Structured Result │
                    └───────────────────┘
```

---

# 💡 Design Principle

> **Detection tells you what happened.
> Correlation tells you how significant it is.
> Explainability tells you why.**

BodWid brings these three concepts together into a single email-security analysis pipeline.

---

# 📜 License

This project is licensed under the MIT License.

See the `LICENSE` file for details.

---

# 👤 Author

Loga Mithra R

Cybersecurity • Machine Learning • Threat Detection

---

<p align="center">

### 🛡️ BodWid — Detect. Correlate. Explain.

</p>
