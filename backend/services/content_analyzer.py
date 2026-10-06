"""Content analysis: finds social-engineering language. Matching words is a CLUE, not proof -
a genuine HR email can say 'urgent' too (that is a classic false positive)."""
import re

LEXICONS = {
    "URGENCY": (r"urgent(?:ly)?|immediately|immediate action|act now|right away|as soon as possible|asap|"
                r"within (?:24|48|12) hours|expires? (?:today|soon|in)|final notice|last chance|"
                r"time[- ]sensitive|deadline|today only",
                "Urgent wording pressures you to act before thinking.", "MEDIUM"),
    "FEAR_THREAT": (r"suspended|suspension|terminated|locked|will be closed|closed permanently|"
                    r"unauthori[sz]ed|legal action|will be deleted|compromised|failure to comply|"
                    r"restricted|deactivated",
                    "Threats about losing access or legal consequences create fear.", "MEDIUM"),
    "FINANCIAL_PRESSURE": (r"outstanding payment|payment overdue|overdue invoice|invoice (?:is )?(?:due|overdue)|"
                           r"unpaid invoice|wire transfer|gift cards?|payment failed|update your payment|"
                           r"payment details|refund|balance due|bank transfer",
                           "Payment pressure or unusual payment requests are common lures.", "MEDIUM"),
    "CREDENTIAL_REQUEST": (r"verify your (?:account|password|identity|login)|confirm your (?:identity|account|password)|"
                           r"(?:enter|provide|send|update|re-?enter) your (?:password|credentials|login)|"
                           r"login credentials|security code|one[- ]time password|\botp\b|password (?:will )?expires?|"
                           r"sign in to (?:verify|confirm)",
                           "The email asks for credentials or account verification.", "HIGH"),
    "REWARD_CLAIM": (r"you(?:'ve| have) won|winner|prize|claim your (?:reward|prize|gift)|congratulations|"
                     r"free gift|lottery|selected to receive",
                     "Unexpected rewards are used as bait.", "MEDIUM"),
    "PERSONAL_INFO_REQUEST": (r"(?:confirm|provide|verify|update|send|enter) (?:your )?(?:personal (?:details|information|data)|"
                              r"date of birth|social security(?: number)?|ssn|card number|bank account(?: number)?|passport|home address)",
                              "The email asks for personal or financial information.", "HIGH"),
    "CALL_TO_ACTION": (r"click here|click the link|click below|follow the link|open the attachment|"
                       r"log ?in now|sign in now|download now|update now|verify now",
                       "A pushy call-to-action tries to get you to click or open something.", "LOW"),
}
COMPILED = {k: re.compile(r"(?i)(?:%s)" % v[0]) for k, v in LEXICONS.items()}
GENERIC_GREETING = re.compile(r"(?i)^\W*(dear|hello|hi)\s+(valued\s+)?(customer|user|member|client|account holder|"
                              r"sir|madam|sir/madam|friend|email user)\b")
MISSPELLINGS = re.compile(r"(?i)\b(verfiy|acount|pasword|recieve|securty|immediatly|kindly|costumer|"
                          r"do the needful|your account have been)\b")
URL_STRIP = re.compile(r"(?i)\b(?:https?://|www\.)\S+")


def analyze_email_content(subject: str, body: str) -> dict:
    cats, findings = {}, []
    for cat, rx in COMPILED.items():
        in_subj = [m.group(0).lower() for m in rx.finditer(subject or "")]
        in_body = [m.group(0).lower() for m in rx.finditer(body or "")]
        phrases = in_subj + in_body
        cats[cat] = {"count": len(phrases), "phrases": sorted(set(phrases)),
                     "in_subject": bool(in_subj)}
        if phrases:
            _, explanation, sev = LEXICONS[cat]
            where = "subject and body" if in_subj and in_body else "subject" if in_subj else "body"
            findings.append({"category": cat, "severity": sev, "count": len(phrases),
                             "phrases": cats[cat]["phrases"][:6],
                             "description": f"{explanation} Found in {where}: " + ", ".join(f"'{p}'" for p in cats[cat]["phrases"][:4])})
    greeting = bool(GENERIC_GREETING.search((body or "")[:150]))
    if greeting:
        findings.append({"category": "GENERIC_GREETING", "severity": "LOW", "count": 1, "phrases": [],
                         "description": "Generic greeting (e.g. 'Dear customer') - real organisations usually use your name."})
    text = URL_STRIP.sub(" ", f"{subject} {body}")
    letters = [c for c in text if c.isalpha()]
    upper = sum(c.isupper() for c in letters) / len(letters) if letters else 0.0
    grammar = sorted({m.group(0).lower() for m in MISSPELLINGS.finditer(text)})
    if re.search(r"[!?]{2,}", text) or grammar:
        findings.append({"category": "FORMATTING_ANOMALY", "severity": "LOW", "count": len(grammar),
                         "phrases": grammar,
                         "description": "Odd wording/punctuation (weak signal - well-written phishing exists)."})
    return {"categories": cats, "generic_greeting": greeting, "grammar_flags": grammar,
            "exclamation_count": (subject or "").count("!") + (body or "").count("!"),
            "uppercase_ratio": round(upper, 3), "body_length": len(body or ""),
            "subject_length": len(subject or ""),
            "contains_password_request": bool(re.search(
                r"(?i)(verify|confirm|enter|provide|send|reply with|share|update)\W+(?:\w+\W+){0,4}(password|passcode|pin|otp|credentials)|password\W+(?:\w+\W+){0,3}expire", text)),
            "contains_personal_info_request": cats["PERSONAL_INFO_REQUEST"]["count"] > 0,
            "findings": findings}
