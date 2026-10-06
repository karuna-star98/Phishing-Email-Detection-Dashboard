"""Static URL analysis. We only PARSE strings - we never connect to, resolve or open a URL.
HTTPS only means the connection is encrypted; criminals use HTTPS too, so it never proves trust."""
import ipaddress
import re
from urllib.parse import urlparse, unquote

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rb.gy", "cutt.ly",
              "shrt.example.net", "tiny.example.org"}   # last two are fictional lab shorteners
URL_KEYWORDS = {"verify", "login", "signin", "secure", "account", "update", "confirm", "password",
                "wallet", "invoice", "billing", "validate", "unlock", "recover"}
SHORT_PATH_HINT = re.compile(r"^/[A-Za-z0-9]{4,8}$")


def _f(code, desc, severity, points):
    return {"code": code, "description": desc, "severity": severity, "points": points}


def defang(url: str) -> str:
    """Safe display form: hxxp://example[.]com/path - cannot be clicked by accident."""
    url = re.sub(r"(?i)^http", "hxxp", url)
    m = re.match(r"^(\w+://)([^/?#]*)(.*)$", url)
    return f"{m.group(1)}{m.group(2).replace('.', '[.]')}{m.group(3)}" if m else url.replace(".", "[.]")


def _is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host, re.I))   # hex / decimal-encoded IPs


def analyze_url(url: str, display_text: str = None) -> dict:
    url = (url or "").strip()
    res = {"url": url, "safe_representation": defang(url), "scheme": "", "hostname": "", "path": "",
           "query": "", "url_length": len(url), "hostname_length": 0, "subdomain_count": 0,
           "is_ip": False, "uses_https": False, "url_risk_score": 0, "findings": []}
    F = res["findings"]
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
    except ValueError:
        F.append(_f("MALFORMED_URL", "URL could not be parsed (malformed).", "MEDIUM", 20))
        res["url_risk_score"] = 20
        return res
    scheme = p.scheme.lower()
    res.update(scheme=scheme, hostname=host, path=p.path, query=p.query, hostname_length=len(host),
               uses_https=scheme == "https")
    if scheme not in ("http", "https"):
        F.append(_f("SUSPICIOUS_SCHEME", f"Unusual URL scheme '{scheme or 'none'}'.", "HIGH", 40))
    elif scheme == "http":
        F.append(_f("NON_HTTPS_URL", "Link is not HTTPS (unencrypted).", "MEDIUM", 15))
    else:
        F.append(_f("HTTPS_NOTE", "HTTPS present - this does NOT mean the site is trustworthy.", "INFO", 0))
    if _is_ip(host):
        res["is_ip"] = True
        F.append(_f("RAW_IP_URL", "Link points to a raw IP address instead of a domain name.", "HIGH", 30))
    else:
        labels = host.split(".") if host else []
        res["subdomain_count"] = max(0, len(labels) - 2)
        if res["subdomain_count"] >= 3:
            F.append(_f("EXCESSIVE_SUBDOMAINS", f"Hostname has {res['subdomain_count']} subdomain levels.", "MEDIUM", 15))
        if host.count("-") >= 3:
            F.append(_f("MANY_HYPHENS", "Hostname contains many hyphens.", "LOW", 10))
        if host in SHORTENERS or (host.split(".")[0] in {"shrt", "tiny"} and SHORT_PATH_HINT.match(p.path or "")):
            F.append(_f("URL_SHORTENER", "URL shortener hides the real destination.", "MEDIUM", 20))
        if "xn--" in host or any(ord(c) > 127 for c in host):
            F.append(_f("PUNYCODE_HOST", "Hostname uses punycode/non-ASCII characters (possible lookalike).", "HIGH", 20))
    if "@" in (p.netloc or ""):
        F.append(_f("USERINFO_IN_URL", "URL contains '@' - text before it can disguise the real host.", "HIGH", 25))
    haystack = unquote(f"{host}{p.path}").lower()
    kws = sorted({k for k in URL_KEYWORDS if k in haystack})
    if kws:
        F.append(_f("URL_KEYWORDS", f"Credential/account-related keyword(s) in URL: {', '.join(kws)}.",
                    "MEDIUM", 15 if len(kws) == 1 else 20))
    if len(url) > 100:
        F.append(_f("LONG_URL", f"Very long URL ({len(url)} characters).", "LOW", 10))
    if url.count("%") >= 5 or re.search(r"[^\x20-\x7e]", url):
        F.append(_f("ENCODED_CHARACTERS", "URL has heavy encoding or unusual characters.", "LOW", 10))
    if display_text:
        m = re.search(r"(?i)(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})", display_text)
        if m and host and m.group(1).lower().lstrip("www.") != host.lstrip("www."):
            F.append(_f("LINK_TEXT_MISMATCH", f"Link text shows '{m.group(1)}' but goes to '{host}'.", "HIGH", 30))
    res["url_risk_score"] = min(100, sum(f["points"] for f in F))
    return res
