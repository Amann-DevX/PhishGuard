                    ┌──────────────────────┐
                    │       User           │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   PhishGuard Web UI  │
                    │   HTML/CSS/JavaScript│
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │       Flask          │
                    │    Web Application   │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
       ┌─────────────┐  ┌─────────────┐  ┌──────────────┐
       │ ML Model    │  │ URL Analysis│  │   Domain     │
       │ Prediction  │  │ & Rules     │  │ Intelligence │
       └──────┬──────┘  └──────┬──────┘  └──────┬───────┘
              │                │                │
              └────────────────┼────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │    Risk Engine       │
                    └──────────┬───────────┘
                               │
                 ┌─────────────┼─────────────┐
                 ▼             ▼             ▼
              SAFE        SUSPICIOUS      PHISHING


# 🛡️ PhishGuard – AI-Powered URL Phishing Detector

PhishGuard is a web-based cybersecurity application that analyzes URLs and detects potential phishing threats using Machine Learning and rule-based security analysis.

The system provides a risk score, phishing probability, URL security analysis, domain intelligence, and advanced security indicators to help users identify potentially malicious URLs.

---

## 🌐 Live Website

🔗 **PhishGuard:**  
https://phishguard-1-p4no.onrender.com/

---

## 📌 Project Overview

Phishing attacks are one of the most common cybersecurity threats. Attackers often create fake websites that imitate legitimate services to steal passwords, banking information, and other sensitive data.

PhishGuard provides an automated way to analyze a URL before visiting it.

The application combines:

- 🤖 Machine Learning
- 🔍 URL Feature Analysis
- 🛡️ Rule-Based Security Analysis
- 🌐 Domain Intelligence
- 🔐 SSL/TLS Information
- 📊 Risk Scoring
- 📜 Scan History
- 📈 ML Analytics

---

## ✨ Features

### 🔐 User Authentication

- User registration
- Secure login
- Logout functionality
- Session-based authentication

### 🔎 URL Phishing Detection

Users can enter a URL and scan it for potential phishing indicators.

The system analyzes:

- URL length
- HTTPS usage
- IP address usage
- Number of subdomains
- Suspicious keywords
- Special characters
- URL entropy
- Path depth
- TLD
- URL encoding
- Hyphens
- Digits
- `@` symbol
- Other suspicious patterns

### 🤖 Machine Learning Detection

PhishGuard uses a trained Machine Learning model to estimate the probability that a URL is phishing.

The model uses extracted URL characteristics as input.

### 🛡️ Risk Scoring

The system combines Machine Learning predictions with rule-based security indicators to generate an overall risk score.

Example:

```text
Risk Score: 75 / 100

Phishing Probability: 82%
