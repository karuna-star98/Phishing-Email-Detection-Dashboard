"""Sender analysis. Unfamiliar domains are NOT automatically malicious - each finding adds
modest points and the final decision combines many signals."""
import os
import re
from difflib import SequenceMatcher
from email.utils import parseaddr

ADDR_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
TWO_PART_TLDS = {"co.uk", "org.uk", "ac.uk", "com.au", "co.in", "ac.in", "co.jp", "com.br"}
RESERVED_TLDS = {"invalid", "test", "example", "localhost"}
DOMAIN_KEYWORDS = {"secure", "verify", "verification", "account", "login", "signin", "update",
                   "support", "alert", "billing", "password", "helpdesk", "confirm", "security",
                   "check", "auth", "portal", "wallet", "service"}
BRANDS = {"bluebird", "bluebirdbank", "northfield", "skyshop", "parcelgo", "orbitpay", "cloudnest",
          "examplebank", "paypal", "microsoft", "amazon", "apple", "google", "netflix", "dhl",
          "fedex", "docusign"}
AUTHORITY = re.compile(r"(?i)\b(ceo|cfo|chief|director|president|hr|human resources|payroll|"
                       r"it support|help ?desk|administrator|security team)\b")
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})


def trusted_domains():
    return {d.strip().lower() for d in os.getenv("TRUSTED_DOMAINS", "example.com,example.org").split(",") if d.strip()}


def registrable_len(labels):
    return 3 if ".".join(labels[-2:]) in TWO_PART_TLDS else 2


def _f(code, desc, severity, points):
    return {"code": code, "description": desc, "severity": severity, "points": points}


def analyze_sender(sender: str, display_name: str = None, trusted=None) -> dict:
    trusted = trusted or trusted_domains()
    name, addr = parseaddr(sender or "")
    display = (display_name if display_name is not None else name).strip()
    res = {"sender_address": addr, "display_name": display, "sender_domain": "",
           "domain_length": 0, "subdomain_count": 0, "sender_risk_score": 0, "sender_findings": []}
    F = res["sender_findings"]
    if not addr or not ADDR_RE.match(addr):
        F.append(_f("INVALID_SENDER", "Sender address is missing or not a valid email format.", "HIGH", 40))
        res["sender_domain"] = addr.split("@")[-1].lower() if "@" in addr else ""
        res["sender_risk_score"] = 40
        return res
    domain = addr.rsplit("@", 1)[1].lower()
    labels = domain.split(".")
    sub = max(0, len(labels) - registrable_len(labels))
    res.update(sender_domain=domain, domain_length=len(domain), subdomain_count=sub)
    reg = ".".join(labels[-registrable_len(labels):])
    core = labels[-registrable_len(labels)]
    tokens = set(re.split(r"[-.]", domain))
    kw = tokens & DOMAIN_KEYWORDS
    if kw:
        F.append(_f("DOMAIN_KEYWORDS", f"Domain contains account/security-style words ({', '.join(sorted(kw))}).",
                    "MEDIUM", 10 if len(kw) == 1 else 20))
    if labels[-1] in RESERVED_TLDS:
        F.append(_f("RESERVED_TLD", f"Domain uses reserved/non-routable ending '.{labels[-1]}', unusual for a real sender.",
                    "LOW", 10))
    if sub >= 3:
        F.append(_f("EXCESSIVE_SUBDOMAINS", f"Domain has {sub} subdomain levels, which can hide the real domain.", "MEDIUM", 15))
    if core.count("-") >= 2 or domain.count("-") >= 3:
        F.append(_f("MANY_HYPHENS", "Domain contains many hyphens, a common pattern in made-up lookalike domains.", "LOW", 10))
    if sum(c.isdigit() for c in core) >= 2:
        F.append(_f("DIGITS_IN_DOMAIN", "Domain name contains several digits.", "LOW", 10))
    if len(domain) > 30:
        F.append(_f("LONG_DOMAIN", f"Domain is unusually long ({len(domain)} characters).", "LOW", 10))
    if any(ord(c) > 127 for c in domain) or "xn--" in domain:
        F.append(_f("UNUSUAL_CHARACTERS", "Domain uses non-ASCII or punycode characters (possible homograph trick).", "HIGH", 25))
    # lookalike: leet-speak substitution of a known brand, or a near-miss spelling
    for label in labels:
        raw = label.replace("-", "")
        leet = raw.translate(LEET)
        hit = None
        if leet != raw and any(b in leet for b in BRANDS) and not any(b in raw for b in BRANDS):
            hit = "character substitution"
        else:
            for b in BRANDS:
                r = SequenceMatcher(None, raw, b).ratio()
                if 0.8 <= r < 1.0 and abs(len(raw) - len(b)) <= 2 and b not in raw:
                    hit = "near-miss spelling"
        if hit:
            F.append(_f("LOOKALIKE_DOMAIN", f"Domain label '{label}' resembles a known organisation name ({hit}).", "HIGH", 35))
            break
    # display-name checks
    dn_norm, dom_norm = re.sub(r"[^a-z0-9]", "", display.lower()), re.sub(r"[^a-z0-9]", "", domain)
    brand_in_name = [b for b in BRANDS if b in dn_norm]
    if brand_in_name and not any(b in dom_norm for b in brand_in_name):
        F.append(_f("DISPLAY_NAME_MISMATCH", f"Display name mentions '{brand_in_name[0]}' but the sending domain does not.", "HIGH", 30))
    elif AUTHORITY.search(display) and reg not in trusted and not any(b in dom_norm for b in BRANDS):
        F.append(_f("AUTHORITY_FROM_EXTERNAL", "Display name claims an authority role (e.g. HR/CEO/IT) but the domain is not a trusted organisation domain.", "MEDIUM", 20))
    res["sender_risk_score"] = min(100, sum(f["points"] for f in F))
    return res
