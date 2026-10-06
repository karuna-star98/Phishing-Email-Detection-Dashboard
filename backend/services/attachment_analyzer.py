"""Attachment FILENAME analysis only. Files are never opened, decoded or executed."""
import os
import re

EXECUTABLE = {".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".dll", ".jar"}
SCRIPT = {".js", ".jse", ".vbs", ".vbe", ".ps1", ".wsf", ".hta", ".sh"}
MACRO = {".docm", ".xlsm", ".pptm"}
ARCHIVE = {".zip", ".rar", ".7z", ".iso", ".img", ".gz", ".tar"}
WEB = {".html", ".htm"}
DOC_LOOKING = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".txt", ".csv"}
RTL = "\u202e"


def analyze_attachment(filename: str) -> dict:
    name = (filename or "").strip()
    low = name.lower()
    ext = os.path.splitext(low)[1]
    findings, score = [], 0

    def add(code, desc, sev, pts):
        nonlocal score
        findings.append({"code": code, "description": desc, "severity": sev, "points": pts})
        score = max(score, pts)

    inner = os.path.splitext(os.path.splitext(low)[0])[1]
    risky = EXECUTABLE | SCRIPT | ARCHIVE | MACRO | WEB
    if RTL in name:
        add("RTL_OVERRIDE", "Filename contains a right-to-left override character that can disguise the real extension.", "HIGH", 95)
    if inner in DOC_LOOKING and ext in EXECUTABLE | SCRIPT | {".zip"}:
        add("DOUBLE_EXTENSION", f"Double extension '{inner}{ext}': looks like a document but ends in '{ext}'.", "HIGH", 95)
    elif re.search(r"\s{3,}\.", name):
        add("PADDED_FILENAME", "Filename is padded with spaces to hide its real extension.", "HIGH", 85)
    if ext in EXECUTABLE:
        add("EXECUTABLE_ATTACHMENT", f"'{ext}' files are programs that can run code.", "HIGH", 90)
    elif ext in SCRIPT:
        add("SCRIPT_ATTACHMENT", f"'{ext}' files are scripts that can run code.", "HIGH", 80)
    elif ext in MACRO:
        add("MACRO_DOCUMENT", f"'{ext}' documents can contain macros.", "MEDIUM", 50)
    elif ext in WEB:
        add("HTML_ATTACHMENT", "HTML attachments can display fake login forms.", "MEDIUM", 45)
    elif ext in ARCHIVE:
        add("ARCHIVE_ATTACHMENT", f"'{ext}' archives can hide other files from scanners.", "MEDIUM", 35)
    if not findings:
        findings.append({"code": "NO_RISKY_PATTERN", "severity": "INFO", "points": 0,
                         "description": "No risky pattern in the filename (an unexpected attachment still deserves caution)."})
    return {"filename": name, "extension": ext, "attachment_risk_score": score, "findings": findings}
