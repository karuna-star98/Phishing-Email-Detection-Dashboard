# Project Report - Phishing Email Detection & Awareness Dashboard

**Abstract.** This project implements a defensive, explainable phishing-triage system. It analyses sender, language, URLs and attachment filenames of synthetic emails, scores them with a rule engine and an optional machine-learning model, stores privacy-preserving history, and teaches users to recognise phishing.

**1. Introduction & Problem Statement.** Email is a leading initial-access path; users and analysts need quick, understandable triage rather than opaque verdicts.
**2. Objectives.** Detect indicators; analyse URLs/attachments safely; score and classify; explain; store metadata; visualise; educate.
**3. Phishing Background & Social Engineering.** Attackers impersonate trusted parties and exploit urgency, fear, authority and reward to obtain credentials, payments or execution of malware.
**4. Existing Approaches.** Blocklists/reputation, header authentication (SPF/DKIM/DMARC), keyword/heuristic filters, ML/NLP classifiers, and awareness training. Each alone has gaps.
**5. Proposed System & Cybersecurity Relevance.** A hybrid heuristic + ML pipeline with explainable output, aligned with secure-email-gateway and SOC workflows.
**6. Architecture.** Flask API → preprocessing → four analyzers → features → rule engine / ML → hybrid score → classification → explanation → SQLite → dashboard (see README).
**7. Dataset.** 628 synthetic emails, balanced, 8 legitimate and 7 phishing categories, fictional domains only, with hard negatives.
**8. Preprocessing.** Control-character removal, length limits, HTML-to-text with link capture, URL/attachment extraction, defanged-URL refanging, de-duplication. Aggressive cleaning is avoided for rules because punctuation, capitals and URLs are evidence; ML text only lower-cases and tokenises URLs/numbers.
**9. Feature Engineering.** 22 numeric features (keyword counts per category, URL stats, sender stats, attachment flag, greeting, exclamations, uppercase ratio, lengths).
**10-12. Sender / URL / Attachment Analysis.** Weighted static checks described in the README; nothing is fetched, opened or executed.
**13. Rule-Based Detection.** Weighted sum capped at 100; bands LOW/MODERATE/SUSPICIOUS/HIGH.
**14. Machine Learning.** Naive Bayes, Logistic Regression, Random Forest; TF-IDF and/or indicators; 70/15/15 split; selection on validation F1.
**15. Hybrid Detection.** 0.6·rule + 0.4·ML probability; probabilities are not certainty.
**16-17. Risk Scoring & Explainability.** Each result lists triggered rules, points, per-finding reasons and recommended actions.
**18-19. Dashboard & Awareness Module.** KPI cards, six charts, history with search/filter/sort, ML metrics, tips and the Before-You-Click checklist.
**20. Testing.** 34 automated tests, all passing (see `docs/TEST_REPORT.md`).
**21. Security & Privacy.** See README.
**22. Results.** Rule engine: precision 1.00, recall 0.66, F1 0.79 on the 95-email test set. All ML variants and the hybrid scored 1.00 on that set, which reflects the template-based synthetic data rather than real-world ability. Leave-one-category-out recall for the selected model: 1.00 on most categories but 0.00 on HR requests and executive requests (hybrid 0.45 / 0.00).
**23. False Positives / False Negatives.** FP: genuine urgent HR mail (kept LOW RISK by multi-signal scoring). FN: subtle executive impersonation with no links or urgency.
**24. Limitations.** Synthetic data, English keywords, no header authentication or reputation data, assumed thresholds.
**25. Future Scope.** Header/SPF/DKIM/DMARC, reputation feeds, better NLP, explainable AI, reporting workflow, SOC/SIEM integration, retraining from analyst feedback.
**26. Conclusion.** Combining interpretable rules with ML gives better coverage than either alone, and evaluating on held-out categories reveals weaknesses that headline accuracy hides.
