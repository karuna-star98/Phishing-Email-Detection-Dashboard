"""Orchestrator: Email input -> preprocess -> sender/content/URL/attachment analysis ->
features -> rule score (+ optional ML) -> classification -> explanation -> recommendations."""
from backend.services import risk_engine
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.content_analyzer import analyze_email_content
from backend.services.feature_extractor import extract_email_features
from backend.services.preprocessing import clean_text_for_ml, prepare_email
from backend.services.sender_analyzer import analyze_sender
from backend.services.url_analyzer import analyze_url

MAX_URLS = 25


def run_detectors(sender, subject, body, attachments=None):
    """Everything except ML. Used by the API and by ML training."""
    prep = prepare_email(sender, subject, body, attachments)
    snd = analyze_sender(prep["sender"])
    content = analyze_email_content(prep["subject"], prep["body"])
    link_text = {l["href"]: l["text"] for l in prep["links"]}
    urls = [analyze_url(u, link_text.get(u)) for u in prep["urls"][:MAX_URLS]]
    atts = [analyze_attachment(a) for a in prep["attachments"]]
    feats = extract_email_features(prep, snd, content, urls, atts)
    return prep, snd, content, urls, atts, feats


def _explain(snd, content, urls, atts, rules):
    """Human-readable 'WHY?' lines + a detailed indicator list for storage/analytics."""
    why, indicators = [], []
    for r in rules:
        why.append(risk_engine.LABELS[r])
    for f in snd["sender_findings"]:
        indicators.append({"indicator_type": f["code"], "description": f["description"], "severity": f["severity"]})
    for f in content["findings"]:
        indicators.append({"indicator_type": f["category"], "description": f["description"], "severity": f["severity"]})
    for u in urls:
        for f in u["findings"]:
            if f["points"] > 0:
                indicators.append({"indicator_type": f["code"], "description": f"{u['safe_representation']}: {f['description']}", "severity": f["severity"]})
    for a in atts:
        for f in a["findings"]:
            if f["points"] > 0:
                indicators.append({"indicator_type": f["code"], "description": f"{a['filename']}: {f['description']}", "severity": f["severity"]})
    return why, indicators


def analyze_email(sender="", subject="", body="", attachments=None, ml_model=None) -> dict:
    prep, snd, content, urls, atts, feats = run_detectors(sender, subject, body, attachments)
    rule = risk_engine.calculate_phishing_score(feats)
    ml_prob = None
    if ml_model is not None and getattr(ml_model, "available", False):
        ml_prob = ml_model.predict_proba(clean_text_for_ml(prep["subject"], prep["body"]), feats)
    final = risk_engine.hybrid_score(rule["rule_score"], ml_prob)
    cls = risk_engine.classify(final)
    why, indicators = _explain(snd, content, urls, atts, rule["triggered_rules"])
    keywords = [{"keyword": p, "category": f["category"]} for f in content["findings"] for p in f["phrases"]
                if f["category"] not in ("FORMATTING_ANOMALY",)]
    return {
        "risk_score": final, "rule_score": rule["rule_score"], "ml_probability": ml_prob,
        "classification": cls, "why": why, "contributions": rule["contributions"],
        "indicators": indicators, "keywords": keywords,
        "sender_analysis": snd, "content_analysis": {k: v for k, v in content.items() if k != "categories"} | {
            "categories": {k: v for k, v in content["categories"].items() if v["count"]}},
        "url_analyses": urls, "attachment_analyses": atts, "features": feats,
        "recommended_actions": risk_engine.recommended_actions(cls),
        "note": "Automated scoring supports analyst judgement; it does not replace it. "
                "No single indicator proves phishing, and no tool can prove an email is safe.",
        "sender_domain": snd["sender_domain"], "subject": prep["subject"],
    }
