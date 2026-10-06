# Phishing Email Detection & Awareness Dashboard

> This project is designed for cybersecurity education and defensive analysis using synthetic or authorized data.

## Overview
A local web app where you paste (or upload a safe `.txt`/`.eml`) email, and get an **explainable phishing risk score**: sender, content, URL and attachment-filename analysis, an optional ML model, a hybrid score, recommended actions, stored history, analytics, and a phishing-awareness module.

## Problem Statement
Email is a top initial-access vector. Users and SOC analysts need fast triage that says *why* an email looks risky, not just "phishing / not phishing".

## Objectives
Detect social-engineering indicators; analyse URLs/attachments **statically and safely**; score and classify risk; explain decisions; store privacy-friendly history; teach users to spot phish.

## Features
Email analyzer (paste/upload) · sender / content / URL / attachment analyzers · rule score (0-100) · optional ML (TF-IDF + indicators) · hybrid score · "WHY?" + recommendations · history with search/filter/sort · dashboard (6 charts + KPI cards + model metrics) · awareness tips + "Before You Click" checklist · optional register/login · rate limiting, CSP, XSS-safe rendering.

## Cybersecurity Relevance
Mirrors secure-email-gateway and SOC phishing-triage workflows (sender checks, URL inspection, attachment analysis, risk scoring, analyst-readable evidence).

## Architecture
```
User → Web Dashboard → Backend API (Flask)
        → Preprocessing (normalise, extract URLs/attachments, parse .eml safely)
        → ┌ Sender Analyzer ┐
          │ Content Analyzer │
          │ URL Analyzer     │ → Feature extraction → Rule engine ┐
          │ Attachment Anlzr │                                    ├→ Hybrid risk score → Classification
          └ (optional) ML ───────────────────────────────────────┘     → Explanation + Recommendations
        → SQLite (metadata only) → Dashboard analytics
```

## Technology Stack
Python 3.10+, Flask, SQLite, scikit-learn, pandas, matplotlib; vanilla JavaScript + SVG charts (no Node build, no CDN).

## Dataset
`data/generate_dataset.py` builds **628 synthetic emails** (314 legitimate / 314 phishing; seed 42) → `data/phishing_email_dataset.csv`. Legitimate: university, HR, project, meeting, shopping, newsletter, password-change, bank-style (fictional). Phishing: fake verification, invoice, prize, password expiry, delivery, HR request, executive request. Only `example.*`, `invalid.test` and `198.51.100.0/24` are used. It includes hard negatives (genuine "urgent" HR mail) and a subtle phish with no links/urgency.

## Phishing Indicators
Sender (domain keywords, reserved TLD, lookalike, display-name mismatch, subdomains…), subject/body (urgency, fear, financial, credential, reward, personal-info, generic greeting, formatting), URL (raw IP, non-HTTPS, shorteners, keywords, `@` tricks, link-text mismatch…), attachment (executable/script/macro/archive/HTML, double extension). **No single indicator proves phishing.**

## Sender / Content / URL / Attachment Analysis
See `backend/services/*_analyzer.py`. URL analysis is **string-only**: URLs are never opened or resolved, and are displayed defanged (`hxxp://198[.]51[.]100[.]10/…`). HTTPS never implies trust. Attachments are judged by **filename only** and never opened.

## Risk Scoring
Rule weights (project assumptions): sender +15, urgency +10, credential +20, suspicious URL +20, attachment +25, generic greeting +5, threat +10, financial +10, reward +10, personal-info +15; cap 100.
Bands: 0-20 LOW RISK · 21-40 MODERATE · 41-70 SUSPICIOUS · 71-100 HIGH RISK / LIKELY PHISHING. Thresholds must be calibrated on your own data. (A "SAFE" class is deliberately not used: no tool can prove an email is safe.)

## Machine Learning
Models: Naive Bayes, Logistic Regression, Random Forest on TF-IDF and/or the structured indicators. Split 70/15/15 (439/94/95); model selected on **validation** F1, test used once. Hybrid = 0.6·rule + 0.4·ML probability (configurable).

## Explainable Detection
Every result lists triggered rules with points, per-finding explanations, and recommended actions.

## Dashboard / Security Awareness
Analyzer, Dashboard, History, Awareness tabs. Awareness covers the 10 checks and the "Before You Click" checklist.

## Installation
```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage
```bash
python data/generate_dataset.py       # 1. synthetic dataset
python -m ml.train_model              # 2. optional ML (writes models/ and reports/)
python -m scripts.seed_history        # 3. optional: fill the dashboard with synthetic history
python -m backend.app                 # 4. open http://127.0.0.1:5000
```
In the app: **Load safe sample** → Analyze (expect LOW RISK) → **Load synthetic phishing sample** → Analyze (expect HIGH RISK) → compare → open **Dashboard** and **History**.

## API Documentation
JSON only (`Content-Type: application/json`). Errors: `{"error": "..."}`.

| Method & path | Purpose | Auth | Main codes |
|---|---|---|---|
| `POST /api/analyze` `{sender, subject, body, attachment_name, save?}` | Full analysis (saved unless `save:false`) | none (rate-limited) | 200, 400, 413, 415, 429 |
| `POST /api/analyze/url` `{url}` | Static URL analysis | none | 200, 400 |
| `POST /api/parse-eml` `{filename, content}` | Parse a `.txt`/`.eml` sample (never executed) | none | 200, 400 |
| `GET /api/analyses?classification=&q=&sort=risk\|date&order=&limit=&offset=` | History | none | 200, 400 |
| `GET /api/analyses/<id>` | One analysis | none | 200, 404 |
| `DELETE /api/analyses/<id>` | Delete | **login** | 200, 401, 404 |
| `GET /api/dashboard/stats?days=` · `GET /api/dashboard/indicators?days=` | Analytics | none | 200 |
| `POST /api/register` · `/api/login` · `/api/logout` · `GET /api/me` | Optional accounts (10+ char passwords, hashed) | – | 201/200, 400, 401, 409 |
| `GET /api/ml/metrics` · `GET /api/health` | Model report / status | none | 200, 404 |

## Testing
```bash
python -m unittest discover -s tests -v      # 34 tests (or: pytest)
python tests/generate_test_report.py         # writes docs/TEST_REPORT.md
```

## Security & Privacy
Attachments never opened; URLs never visited; email bodies **not stored** (`STORE_EMAIL_BODY=false`); all dynamic UI text uses `textContent` (no raw HTML rendering → no XSS); upload type/size limits; 300 KB request cap; per-IP rate limit; CSP + security headers; JSON-only writes (blocks cross-site form posts); hashed passwords; secrets via environment variables. Use HTTPS (reverse proxy) in production. Rendering raw HTML email is itself risky (scripts, tracking pixels, hidden links), so this app only shows escaped text.

## Results
Measured by running the code (`reports/ml_metrics.json`, seed 42, **95-email test set**):

| Detector | Accuracy | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|---|
| Rule engine only | 0.832 | 1.000 | 0.660 | 0.795 | 0 | 16 |
| Naive Bayes / LogReg / Random Forest (all variants) | 1.000 | 1.000 | 1.000 | 1.000 | 0 | 0 |
| Hybrid (rules + LogReg TF-IDF+indicators) | 1.000 | 1.000 | 1.000 | 1.000 | 0 | 0 |

**Read this honestly:** the ML scores are perfect because the data is synthetic and template-based, so train and test share templates. This does *not* predict real-world performance. A harder check hides one phishing category from training (leave-one-category-out):

| Hidden category | n | Rules recall | ML recall | Hybrid recall |
|---|---|---|---|---|
| fake delivery | 46 | 0.00 | 1.00 | 1.00 |
| fake HR request | 44 | 0.55 | 0.00 | 0.45 |
| fake executive request | 45 | 0.00 | 0.00 | 0.00 |
| account verification / invoice / password expiry / prize | 43-46 | 1.00 | 1.00 | 1.00 |

Takeaways: rules are precise but miss subtle lures; ML helps with wording but fails on unseen patterns; low-signal impersonation (executive/BEC) is missed by everything here - it needs headers (SPF/DKIM/DMARC), reply-to checks and context.

## False Positives & False Negatives
FP example: a genuine HR mail "Urgent: Submit your documents today" triggers the urgency rule (it stays LOW RISK because one weak signal is not enough - see test T23). FN example: a polished phish with no links, urgency or attachment (the executive-request category). Multiple signals, calibrated thresholds, context and analyst review reduce both.

## Limitations
Synthetic data; keyword rules are English-only; no header/SPF/DKIM/DMARC analysis; no live reputation lookups; thresholds are assumptions; one-process in-memory rate limiter; not a production gateway.

## Future Improvements
Header analysis and SPF/DKIM/DMARC ingestion, domain/URL reputation (authorized APIs), attachment hash reputation, better NLP models, explainable-AI (feature attributions), user report button + SOC ticket/SIEM integration, awareness quizzes, feedback-based retraining.

## Screenshots
Save under `screenshots/` using the names in `docs/PROJECT_GUIDE.md` (section "Screenshot checklist").

## Learning Outcomes
Phishing indicators & social engineering · safe static URL/attachment analysis · feature engineering · rule vs ML vs hybrid detection · precision/recall/F1 and honest evaluation · secure coding (XSS, validation, rate limits) · SOC triage thinking.

## Disclaimer
This project is designed for cybersecurity education and defensive analysis using synthetic or authorized data. It does not send emails, collect credentials, open links, or run attachments.

## Author
Your Name · GitHub: `<your-username>` · LinkedIn: `<your-link>`
