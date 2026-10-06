"""Preprocessing: safe normalisation + extraction. Nothing here opens links or attachments.

IMPORTANT: we do NOT clean aggressively for the rule engine. Lower-casing is fine, but removing
punctuation, URLs or capital letters would destroy evidence (e.g. '!!!', 'URGENT', raw-IP links).
Only the ML text (clean_text_for_ml) is simplified - and even there URLs become a token so the
"contains a link" signal survives.
"""
import os
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser

MAX_BODY, MAX_SUBJECT, MAX_SENDER, MAX_ATTACH = 50_000, 500, 320, 20
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
URL_RE = re.compile(r"(?i)\b(?:https?://|hxxps?://|www\.)[^\s<>\"'`]+")


def normalize_text(value, limit) -> str:
    """None -> '', strip control chars, trim, enforce a length limit."""
    if value is None:
        return ""
    return CTRL_RE.sub("", str(value)).strip()[:limit]


def refang(url: str) -> str:
    """Turn defanged text (hxxp://x[.]y) back into analysable form (still never visited)."""
    return re.sub(r"(?i)^hxxp", "http", url).replace("[.]", ".").replace("(.)", ".")


def extract_urls(text: str) -> list:
    seen, out = set(), []
    for m in URL_RE.findall(text or ""):
        u = refang(m.rstrip(".,;:!?)]}>"))
        if u.lower().startswith("www."):
            u = "http://" + u
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


class _HTMLText(HTMLParser):
    """Strips tags but remembers <a href> links and their visible text."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.links, self._href, self._txt, self._skip = [], [], None, [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            self._href, self._txt = dict(attrs).get("href"), []
        if tag in ("br", "p", "div", "li", "tr"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append({"href": self._href, "text": "".join(self._txt).strip()})
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.parts.append(data)
        if self._href is not None:
            self._txt.append(data)


def html_to_text(html_str: str):
    p = _HTMLText()
    try:
        p.feed(html_str)
    except Exception:  # malformed HTML must never crash analysis
        pass
    return re.sub(r"\n{3,}", "\n\n", "".join(p.parts)).strip(), p.links


def safe_filename(name) -> str:
    """Drop any path part and control characters (RTL-override chars are kept so they can be flagged)."""
    name = CTRL_RE.sub("", str(name or "")).replace("\\", "/").split("/")[-1].strip()
    return name[:255]


def prepare_email(sender, subject, body, attachments=None) -> dict:
    sender = normalize_text(sender, MAX_SENDER)
    subject = normalize_text(subject, MAX_SUBJECT)
    body = normalize_text(body, MAX_BODY)
    links, was_html = [], False
    if re.search(r"(?i)<(html|body|a\s|p>|div|br)", body):
        body, links = html_to_text(body)
        was_html = True
    urls = extract_urls(body)
    for l in links:
        href = refang(l["href"] or "")
        if re.match(r"(?i)^(https?:|javascript:|data:|ftp:)", href) and href not in urls:
            urls.append(href)
    if isinstance(attachments, str):
        attachments = [a for a in re.split(r"[,;\n]", attachments)]
    atts = [safe_filename(a) for a in (attachments or [])][:MAX_ATTACH]
    return {"sender": sender, "subject": subject, "body": body, "urls": urls,
            "links": links, "attachments": [a for a in atts if a], "was_html": was_html}


def clean_text_for_ml(subject: str, body: str) -> str:
    """Light cleaning for TF-IDF: lowercase, URLs->token, numbers->token, keep '!' and '$' as tokens."""
    t = f"{subject} {body}"
    t = URL_RE.sub(" urltoken ", t)
    t = re.sub(r"\d+", " numtoken ", t.lower())
    t = t.replace("!", " exclam ").replace("$", " dollar ")
    return re.sub(r"\s+", " ", t).strip()


# ---------- safe sample-file parsing (.txt / .eml). Payloads are never decoded or executed ----------
def parse_eml_bytes(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    part = msg.get_body(preferencelist=("plain", "html"))
    body = part.get_content() if part else ""
    atts = [p.get_filename() for p in msg.iter_attachments() if p.get_filename()]
    return {"sender": str(msg.get("From", "")), "subject": str(msg.get("Subject", "")),
            "body": body, "attachment_name": ", ".join(atts)}


def parse_text_email(text: str) -> dict:
    """Plain text with optional 'From:/Subject:/Attachment:' header lines, blank line, then body."""
    out, lines, i = {"sender": "", "subject": "", "attachment_name": ""}, text.splitlines(), 0
    keys = {"from": "sender", "subject": "subject", "attachment": "attachment_name",
            "attachments": "attachment_name"}
    while i < len(lines) and ":" in lines[i] and lines[i].split(":", 1)[0].strip().lower() in keys:
        k, v = lines[i].split(":", 1)
        out[keys[k.strip().lower()]] = v.strip()
        i += 1
    out["body"] = "\n".join(lines[i:]).strip()
    return out


def parse_sample_file(filename: str, content: str) -> dict:
    ext = os.path.splitext(filename or "")[1].lower()
    if ext not in (".txt", ".eml"):
        raise ValueError("Only .txt and .eml sample files are accepted")
    if len(content) > 200_000:
        raise ValueError("File too large (max 200 KB)")
    return parse_eml_bytes(content.encode("utf-8", "replace")) if ext == ".eml" else parse_text_email(content)
