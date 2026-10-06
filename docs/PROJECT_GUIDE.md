# Project Guide (concepts, workflow, GitHub, proof, interview)

## 1. Concepts in plain words
**Phishing** = tricking a person into giving up credentials, money or access, usually by pretending to be someone trusted. **Email phishing** does this through messages that create urgency, fear, greed or authority. It is dangerous because it targets people, not software, and one click can start a breach.
**Indicators** are clues (urgent wording, odd sender domain, raw-IP link, `invoice.pdf.exe`). **No single indicator proves phishing** - genuine mail can be urgent, and polished phishing can look clean. So the tool *combines* clues into a score and shows its evidence. **Explainability** matters because analysts must justify decisions and users learn from the "why".
**Workflow:** input → preprocessing → sender / subject / content / URL / attachment analysis → feature extraction → rules (+ optional ML) → risk score → classification → explanation → recommendations → dashboard + history.

## 2. Industry relevance
Secure email gateways, anti-spam systems, SOC phishing-triage queues, security-awareness teams and managed security providers all score mail by sender reputation, content, URLs and attachments, then route it to users or analysts. Roles: **SOC analyst** (triage reported mail), **Email security analyst** (tune filters), **Cybersecurity analyst** (monitor and report), **Threat-intel analyst** (track campaigns/infrastructure), **Incident responder** (contain after a click). This project shows: indicator analysis, safe URL/attachment handling, scoring and explainable reporting, metrics, and secure coding.

## 3. Folder guide
`backend/` Flask app; `services/` analyzers + risk engine; `database.py` SQLite; `security.py` rate limit/headers · `frontend/` dashboard (HTML/CSS/JS) · `ml/` train, predict, evaluation · `data/` dataset generator + CSV · `models/` saved model · `tests/` 34 tests · `docs/` guides + test report · `reports/` metrics + confusion matrices · `scripts/` history seeding · `screenshots/` your proof images. (The brief's `routes/`, `models/`, `src/`, `components/`, `pages/` folders exist as empty placeholders: routes live in `backend/app.py` and the UI is a single-page vanilla JS app, which is simpler for beginners.)

## 4. Database
`analyses` (one row per analysis: sender_domain, subject, scores, classification, created_at, optional body) 1—* `indicators` (type, description, severity), 1—* `url_analyses` (defanged URL, risk, findings), 1—* `keywords`; `users` (hashed passwords) optionally owns analyses. Child rows use `ON DELETE CASCADE`; indexes on created_at, classification, risk_score.

## 5. Data flow & API
See README. Validation: strings only, size limits (sender 320, subject 500, body 50,000), JSON content-type, ≤300 KB requests. Auth is optional; only DELETE needs login. Errors return JSON with 400/401/404/409/413/415/429.

## 6. Security & privacy checklist
Never execute attachments · never visit URLs (static string analysis, defanged output) · don't store bodies by default · sanitize/limit input · escape rendered content (`textContent`) · validate upload type/size · authenticate protected endpoints · rate limit · secrets in environment variables · HTTPS in production · log security events (add a logger/SIEM feed as an extension).

## 7. False positives, false negatives, confusion matrix
TP = phishing caught; TN = legitimate passed; **FP** = legitimate flagged (alert fatigue, lost trust); **FN** = phishing missed (the dangerous one - a user may act on it). Precision = TP/(TP+FP); Recall = TP/(TP+FN); F1 balances them. Accuracy alone misleads when classes are imbalanced or when the data is easy. Confusion matrices are generated in `reports/confusion_matrices.png`.

## 8. SOC analyst workflow
Email reported → initial triage → sender analysis → URL analysis → attachment metadata → content analysis → risk score → **analyst review** → classification → response (block sender, purge mail, reset credentials if clicked, notify user). The score supports judgement; it never replaces it.

## 9. MITRE ATT&CK (high level)
Phishing maps to the *Initial Access* tactic, technique **Phishing (T1566)**, with sub-techniques **Spearphishing Attachment (T1566.001)**, **Spearphishing Link (T1566.002)** and **Spearphishing via Service (T1566.003)**. Attachment findings suggest .001-style activity, link findings .002-style, but a statistical score alone doesn't prove a technique - map only when evidence supports it. Mapping standardises detection documentation, helps threat hunting and makes reports comparable. (Verify IDs against attack.mitre.org before publishing.)

## 10. GitHub strategy
Repo: `Phishing-Email-Detection-Awareness-Dashboard`
Description: *Defensive cybersecurity dashboard for analyzing synthetic email content, sender patterns, URLs, attachments, and social-engineering indicators to generate explainable phishing risk assessments.*
Topics: cybersecurity, phishing-detection, email-security, soc, python, machine-learning, nlp, threat-detection, security-awareness, url-analysis, defensive-security
```bash
cd Phishing-Email-Detection-Dashboard
git init && git branch -M main
git add .gitignore requirements.txt .env.example && git commit -m "Initialize phishing detection project"
git add data/generate_dataset.py data/phishing_email_dataset.csv && git commit -m "Add synthetic email dataset generator"
git add backend/services/preprocessing.py && git commit -m "Implement email preprocessing"
git add backend/services/sender_analyzer.py && git commit -m "Add sender analysis module"
git add backend/services/content_analyzer.py && git commit -m "Implement phishing content analyzer"
git add backend/services/url_analyzer.py && git commit -m "Add static URL risk analysis"
git add backend/services/attachment_analyzer.py && git commit -m "Implement attachment filename analysis"
git add backend/services/feature_extractor.py backend/services/risk_engine.py backend/services/analyzer.py && git commit -m "Build phishing risk scoring engine"
git add ml/train_model.py ml/predict.py && git commit -m "Add optional ML detection model"
git add ml/evaluation.py reports && git commit -m "Implement model evaluation"
git add backend frontend/index.html frontend/app.js frontend/styles.css && git commit -m "Build cybersecurity dashboard"
git commit --allow-empty -m "Add phishing awareness module"   # awareness lives in frontend/app.js: split your commits as you like
git add scripts && git commit -m "Implement analysis history"
git add tests && git commit -m "Add automated security tests"
git add README.md docs screenshots && git commit -m "Complete README and documentation"
git remote add origin https://github.com/<you>/Phishing-Email-Detection-Awareness-Dashboard.git
git push -u origin main
```
(Tip: for an honest history, commit as you actually build each part over the days below.)

## 11. 13-day proof plan
| Day | Do | Commit | Screenshot (proves) |
|---|---|---|---|
| 1 | Repo + architecture | Initialize… | folder tree + diagram (planning) |
| 2 | Dataset generator | Add synthetic dataset… | CSV + `value_counts` (safe, balanced data) |
| 3 | Preprocessing | Implement email preprocessing | parsed URLs/attachments (evidence kept) |
| 4 | Sender + content | sender / content commits | findings output (indicator logic) |
| 5 | URL analysis | Add static URL… | defanged URL result (safe analysis) |
| 6 | Attachment analysis | Implement attachment… | `invoice.pdf.exe` flagged (filename-only) |
| 7 | Risk engine | Build risk scoring… | score 79/100 with WHY (explainability) |
| 8 | ML | Add optional ML… + evaluation | metrics + confusion matrix (honest evaluation) |
| 9 | Dashboard | Build dashboard | analyzer + charts (end-to-end) |
| 10 | Awareness | Add awareness module | tips + checklist (user education) |
| 11 | History | Implement analysis history | filtered history (storage/privacy) |
| 12 | Tests | Add automated tests | 34 passing (quality) |
| 13 | Docs | Complete README… | README preview (communication) |

## 12. Screenshot checklist (suggested filenames)
`01_project_structure.png` · `02_architecture.png` · `03_dataset_preview.png` · `04_dataset_stats.png` · `05_analyzer_page.png` · `06_legit_analysis.png` · `07_phishing_analysis.png` · `08_sender_findings.png` · `09_url_findings.png` · `10_attachment_analysis.png` · `11_risk_score.png` · `12_explainable_indicators.png` · `13_recommended_actions.png` · `14_dashboard.png` · `15_classification_chart.png` · `16_risk_distribution.png` · `17_top_indicators.png` · `18_ml_metrics.png` · `19_confusion_matrix.png` · `20_history.png` · `21_awareness.png` · `22_tests_passing.png` · `23_api_response.png` · `24_github_commits.png` · `25_github_repo.png` · `26_readme_preview.png`

## 13. Resume / LinkedIn
**Bullets**
- Built a phishing detection and awareness dashboard (Python, Flask, scikit-learn) that scores emails 0-100 from sender, content, static URL and attachment-filename indicators with fully explainable findings.
- Trained and compared Naive Bayes, Logistic Regression and Random Forest on a 628-email synthetic dataset; reported precision/recall/F1 and a leave-one-category-out test that exposed a 0% recall gap on executive-impersonation lures.
- Wrote 34 automated tests and applied secure-coding controls (XSS-safe rendering, input/upload limits, rate limiting, CSP, no body storage, never visiting URLs or opening attachments).

**2-line description:** Defensive phishing-triage dashboard combining rule-based indicators and ML into an explainable risk score. Includes safe URL/attachment analysis, history analytics and a user-awareness module.

**LinkedIn:** "I built an end-to-end phishing detection and awareness dashboard to understand how email-security tools and SOC analysts triage suspicious mail. It analyses senders, language, URLs and attachment names (statically and safely), blends a rule engine with an optional ML model, explains every decision, and tracks analytics. I evaluated it honestly - including where it fails - and documented the false-positive/false-negative trade-offs. Stack: Python, Flask, SQLite, scikit-learn, JavaScript."
**Skills:** Phishing analysis, email security, URL analysis, threat scoring, feature engineering, NLP/TF-IDF, scikit-learn, Flask/REST, SQLite, secure coding, SOC concepts, security analytics.

## 14. Future improvements
Header analysis, SPF/DKIM/DMARC results, domain/URL reputation, attachment hash reputation, better NLP, explainable AI, user reporting, SOC ticket + SIEM integration, awareness quizzes, feedback-based retraining. All defensive and authorized-data only.

## 15. Interview preparation (10 Q&A)
1. **Explain your project.** I built a phishing-triage dashboard. You paste an email; it analyses the sender, subject/body language, URLs and attachment filenames without opening anything, scores risk 0-100, classifies it, and explains why with recommended actions. A rule engine does the scoring, an optional ML model adds a probability, and the two are blended. History and analytics are stored without email bodies, and an awareness tab teaches users what to look for.
2. **How does phishing work and why does it succeed?** It uses social engineering - urgency, fear, authority, rewards - to make someone click, log in or pay before thinking. It succeeds because it targets human trust, and attackers can cheaply copy branding.
3. **How do you analyse a URL safely?** Only by parsing the string: scheme, host, raw IP, subdomains, shorteners, keywords, `@` tricks, link-text mismatch. I never request it, and I show it defanged (`hxxp://…[.]…`). HTTPS isn't trust - it only encrypts the connection.
4. **Which features did you engineer and why?** Keyword counts per category, URL counts and suspicious-URL counts, raw-IP/shortener flags, sender-domain length and subdomain count, attachment risk, generic greeting, password/personal-info request flags, exclamation count and uppercase ratio. Each maps to a known manipulation or evasion pattern.
5. **How does your risk score work?** Triggered rules add weights (credential +20, URL +20, attachment +25, sender +15, urgency +10…) capped at 100, then bands give the class. The weights and thresholds are my assumptions and would need calibration on validation data.
6. **Why combine rules and ML?** Rules are transparent and precise but miss unseen wording; ML generalises on text but is harder to explain and can fail on new patterns. My leave-one-category-out test showed rules alone caught 0% of delivery lures where ML caught them, while ML missed HR lures that rules partly caught.
7. **Why not trust 100% accuracy?** The dataset is synthetic and template-based, so train and test share patterns. I treat it as a sanity check, not a real-world estimate, and I report precision, recall, F1, confusion matrices and the harder hidden-category test.
8. **Precision vs recall for phishing?** Low precision means false alarms and alert fatigue; low recall means missed phishing, which is the costlier error. Security teams usually push recall up while keeping false positives manageable; F1 balances them.
9. **Give a false positive and a false negative.** FP: a genuine HR mail saying "Urgent: submit your documents today" triggers the urgency rule - my engine keeps it LOW RISK because one weak signal isn't enough. FN: a polite executive-impersonation message with no links or urgency - my system missed this category entirely, which shows why headers (SPF/DKIM/DMARC) and context are needed.
10. **How is it secured, and how would a SOC use it?** It never opens links/attachments, doesn't store bodies, renders all text via `textContent` to prevent XSS, limits input/uploads, rate-limits, sets CSP headers, hashes passwords and keeps secrets in env vars. A SOC analyst would use the score and evidence for triage, then make the final call and respond - block, purge, reset credentials, notify users.
