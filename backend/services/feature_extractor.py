"""Turns analyzer outputs into one flat, numeric feature dictionary (used by rules AND the ML model)."""
from backend.services.url_analyzer import SHORTENERS

SUSPICIOUS_URL_THRESHOLD = 30
SUSPICIOUS_ATTACHMENT_THRESHOLD = 40

ML_FEATURE_COLS = [
    "urgent_keyword_count", "credential_keyword_count", "financial_keyword_count",
    "threat_keyword_count", "reward_keyword_count", "personal_info_keyword_count", "url_count",
    "suspicious_url_count", "has_ip_url", "has_shortened_url_pattern", "has_non_https_url",
    "sender_domain_length", "subdomain_count", "sender_risk_score", "suspicious_attachment",
    "generic_greeting", "contains_password_request", "contains_personal_info_request",
    "exclamation_count", "uppercase_ratio", "body_length", "subject_length",
]


def extract_email_features(prepared, sender, content, urls, attachments) -> dict:
    cats = content["categories"]
    codes = {f["code"] for u in urls for f in u["findings"]}
    return {
        "urgent_keyword_count": cats["URGENCY"]["count"],            # pressure to act fast
        "credential_keyword_count": cats["CREDENTIAL_REQUEST"]["count"],  # asks for login/verification
        "financial_keyword_count": cats["FINANCIAL_PRESSURE"]["count"],   # payment pressure
        "threat_keyword_count": cats["FEAR_THREAT"]["count"],        # fear / consequences
        "reward_keyword_count": cats["REWARD_CLAIM"]["count"],       # bait
        "personal_info_keyword_count": cats["PERSONAL_INFO_REQUEST"]["count"],
        "url_count": len(urls),
        "suspicious_url_count": sum(u["url_risk_score"] >= SUSPICIOUS_URL_THRESHOLD for u in urls),
        "has_ip_url": int("RAW_IP_URL" in codes),
        "has_shortened_url_pattern": int("URL_SHORTENER" in codes),
        "has_non_https_url": int("NON_HTTPS_URL" in codes),
        "sender_domain_length": sender["domain_length"],
        "subdomain_count": sender["subdomain_count"],
        "sender_risk_score": sender["sender_risk_score"],
        "suspicious_attachment": int(any(a["attachment_risk_score"] >= SUSPICIOUS_ATTACHMENT_THRESHOLD for a in attachments)),
        "generic_greeting": int(content["generic_greeting"]),
        "contains_password_request": int(content["contains_password_request"]),
        "contains_personal_info_request": int(content["contains_personal_info_request"]),
        "exclamation_count": content["exclamation_count"],
        "uppercase_ratio": content["uppercase_ratio"],
        "body_length": content["body_length"],
        "subject_length": content["subject_length"],
    }
