"""Rule-based phishing score + optional hybrid with ML, plus explanations and recommendations.

The weights and thresholds are PROJECT ASSUMPTIONS. In real use they should be calibrated on
labelled validation data from your own mail flow.
"""
import os

WEIGHTS = {"SUSPICIOUS_SENDER": 15, "URGENCY": 10, "CREDENTIAL_REQUEST": 20, "SUSPICIOUS_URL": 20,
           "SUSPICIOUS_ATTACHMENT": 25, "GENERIC_GREETING": 5, "THREAT_FEAR_LANGUAGE": 10,
           "FINANCIAL_PRESSURE": 10, "REWARD_CLAIM": 10, "PERSONAL_INFO_REQUEST": 15}
SENDER_FLAG_THRESHOLD = 25

LABELS = {
    "SUSPICIOUS_SENDER": "Suspicious sender pattern",
    "URGENCY": "Urgent language detected",
    "CREDENTIAL_REQUEST": "Credential / verification request detected",
    "SUSPICIOUS_URL": "Suspicious URL structure",
    "SUSPICIOUS_ATTACHMENT": "Attachment requires caution",
    "GENERIC_GREETING": "Generic greeting",
    "THREAT_FEAR_LANGUAGE": "Threat / fear language detected",
    "FINANCIAL_PRESSURE": "Financial pressure detected",
    "REWARD_CLAIM": "Reward / prize claim detected",
    "PERSONAL_INFO_REQUEST": "Personal-information request detected",
}


def classify(score: float) -> str:
    return ("LOW RISK" if score <= 20 else "MODERATE RISK" if score <= 40
            else "SUSPICIOUS" if score <= 70 else "HIGH RISK / LIKELY PHISHING")


def triggered_rules(features: dict) -> list:
    f = features
    t = {"SUSPICIOUS_SENDER": f["sender_risk_score"] >= SENDER_FLAG_THRESHOLD,
         "URGENCY": f["urgent_keyword_count"] > 0,
         "CREDENTIAL_REQUEST": f["credential_keyword_count"] > 0 or f["contains_password_request"],
         "SUSPICIOUS_URL": f["suspicious_url_count"] > 0,
         "SUSPICIOUS_ATTACHMENT": bool(f["suspicious_attachment"]),
         "GENERIC_GREETING": bool(f["generic_greeting"]),
         "THREAT_FEAR_LANGUAGE": f["threat_keyword_count"] > 0,
         "FINANCIAL_PRESSURE": f["financial_keyword_count"] > 0,
         "REWARD_CLAIM": f["reward_keyword_count"] > 0,
         "PERSONAL_INFO_REQUEST": f["personal_info_keyword_count"] > 0 or bool(f["contains_personal_info_request"])}
    return [k for k, v in t.items() if v]


def calculate_phishing_score(features: dict, weights=None) -> dict:
    """Sum the weights of triggered rules, cap at 100."""
    w = weights or WEIGHTS
    rules = triggered_rules(features)
    score = min(100, sum(w[r] for r in rules))
    return {"rule_score": score, "triggered_rules": rules,
            "contributions": [{"rule": r, "points": w[r], "label": LABELS[r]} for r in rules]}


def hybrid_score(rule_score, ml_probability=None):
    """Weighted blend of the rule score and the ML probability (a probability is NOT certainty)."""
    if ml_probability is None:
        return float(rule_score)
    wr, wm = float(os.getenv("HYBRID_WEIGHT_RULE", 0.6)), float(os.getenv("HYBRID_WEIGHT_ML", 0.4))
    return round((wr * rule_score + wm * ml_probability * 100) / (wr + wm), 1)


def recommended_actions(classification: str, has_attachment_risk=False, has_url=False) -> list:
    if classification.startswith("HIGH") or classification == "SUSPICIOUS":
        acts = ["Do not click any links in this email.",
                "Do not open unexpected attachments.",
                "Verify the sender through a trusted channel (phone number or website you already know).",
                "Report the email to your security team / use the 'Report phishing' button.",
                "Use the organisation's official website or app directly instead of the email's links."]
        if classification == "SUSPICIOUS":
            acts.insert(0, "Treat with caution until verified - the evidence is mixed.")
        return acts
    if classification == "MODERATE RISK":
        return ["Check the sender address and link destinations carefully before acting.",
                "If anything feels off, verify through an official channel.",
                "When unsure, report it to your security team."]
    return ["No strong phishing indicators were found - but no tool can prove an email is safe.",
            "Stay alert to unexpected requests, even from known senders.",
            "Hover over links to check where they really go before clicking."]
