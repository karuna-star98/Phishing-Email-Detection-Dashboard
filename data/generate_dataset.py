"""Generate a SYNTHETIC email dataset (data/phishing_email_dataset.csv).

All organisations are fictional and all domains/IPs are reserved for documentation
(example.com/.org/.net, invalid.test, 198.51.100.0/24). No real URLs, no real brands' infrastructure.
Run:  python data/generate_dataset.py
"""
import argparse
import os
import random

import pandas as pd

FIRST = ["Priya", "Alex", "Sam", "Maria", "Chen", "Omar", "Lena", "Ravi", "Nina", "Tom"]
LAST = ["Sharma", "Lee", "Garcia", "Khan", "Novak", "Patel", "Brown", "Rossi"]
ORGS = {"bluebird": ("Bluebird Bank", "bluebirdbank"), "skyshop": ("SkyShop", "skyshop"),
        "parcelgo": ("ParcelGo", "parcelgo"), "cloudnest": ("CloudNest", "cloudnest"),
        "orbitpay": ("OrbitPay", "orbitpay")}
IP = lambda r: f"198.51.100.{r.randint(2, 250)}"
def name(r): return f"{r.choice(FIRST)} {r.choice(LAST)}"
def tok(r, n=6): return "".join(r.choices("abcdefghjkmnpqrstuvwxyz23456789", k=n))
def pick(r, *xs): return r.choice(xs)

# ---------------- LEGITIMATE ----------------
def university(r):
    n = name(r)
    s = pick(r, "Registration for spring courses opens on Monday.", "The library will close early on Friday for maintenance.",
             "Please review the updated exam timetable on the student portal.")
    return (f"Registrar Office <registrar@university.example.org>", f"Notice: {pick(r, 'Course registration', 'Library hours', 'Exam timetable')} update",
            f"Dear {n.split()[0]},\n\n{s} Log in to the student portal as usual (https://portal.example.org/students) when convenient.\n\nRegards,\nRegistrar Office",
            f"https://portal.example.org/students", "", "university notice")

def hr_update(r):
    urgent = r.random() < 0.25   # hard negative: genuine mail that uses urgent wording
    subj = pick(r, "Urgent: Submit your documents today", "Reminder: benefits enrolment closes Friday") if urgent else pick(r, "Updated leave policy", "Holiday calendar 2026", "Team lunch Thursday")
    return (f"HR Team <hr@example.com>", subj,
            f"Hi {r.choice(FIRST)},\n\nPlease see the {pick(r, 'updated leave policy', 'holiday calendar', 'benefits guide')} on the intranet: https://intranet.example.com/hr/{tok(r,4)}.\nContact HR with any questions.\n\nThanks,\nHR",
            "https://intranet.example.com/hr/doc", pick(r, "", "policy.pdf", "calendar.xlsx"), "hr update")

def project_update(r):
    return (f"{name(r)} <{r.choice(FIRST).lower()}@example.com>", pick(r, "Sprint 14 status", "Project Atlas milestone", "Notes from design review"),
            f"Hi team,\n\nQuick update: {pick(r, 'the API tests are passing', 'the dashboard mockups are ready', 'we shipped the beta')}. Next steps are in the tracker.\n\nCheers,\n{r.choice(FIRST)}",
            "", pick(r, "", "status.pdf", "notes.docx"), "project update")

def meeting(r):
    return (f"Calendar <calendar@example.org>", f"Meeting reminder: {pick(r, 'Weekly sync', 'Thesis review', 'Club planning')} at {r.randint(9, 16)}:00",
            f"Hello {r.choice(FIRST)},\n\nThis is a reminder for your meeting tomorrow at {r.randint(9, 16)}:00 in room {r.randint(1, 40)}. Agenda attached.", "", "agenda.pdf", "meeting reminder")

def shopping(r):
    org = ORGS["skyshop"]
    return (f"SkyShop Orders <orders@skyshop.example.net>", f"Your SkyShop order #{r.randint(10000, 99999)} is confirmed",
            f"Hi {r.choice(FIRST)},\n\nThanks for your order! Total: ${r.randint(10, 300)}.00. Track it at https://skyshop.example.net/orders/{r.randint(1000, 9999)}.\n\nSkyShop", 
            "https://skyshop.example.net/orders/1", "", "shopping confirmation")

def newsletter(r):
    return (f"Orbit News <news@orbit.example.net>", pick(r, "This week in tech", "Your monthly digest", "New articles you may like"),
            f"Hello subscriber,\n\nIssue #{r.randint(100, 999)}: here are this week's top stories. Read more at https://orbit.example.net/weekly. You can unsubscribe in your settings at any time.", "https://orbit.example.net/weekly", "", "newsletter")

def password_change(r):
    return (f"CloudNest <no-reply@cloudnest.example.com>", "Your password was changed",
            f"Hi {r.choice(FIRST)},\n\nYour CloudNest password was changed on {r.randint(1, 28)}/{r.randint(1, 12)}. If this was you, no action is needed. If not, contact support through the official app.\n", "", "", "password-change confirmation")

def bank_notice(r):
    return (f"Bluebird Bank <alerts@bluebirdbank.example.com>", pick(r, "Your monthly statement is ready", "Card payment received", "Branch hours update"),
            f"Dear {r.choice(FIRST)},\n\nYour statement (ref {r.randint(10000, 99999)}) is now available in the Bluebird Bank app. We will never ask for your password by email.\n\nBluebird Bank (fictional)", "", "", "bank notification")

LEGIT = [university, hr_update, project_update, meeting, shopping, newsletter, password_change, bank_notice]

# ---------------- PHISHING (synthetic patterns) ----------------
BAD_DOMAINS = ["account-check.invalid.test", "secure-verify.invalid.test", "login-update.example.net.invalid.test",
               "support-desk.invalid.test", "examp1e-bank.invalid.test", "verify.account.secure.invalid.test"]
def bad_url(r, word):
    k = r.random()
    if k < .35: return f"http://{IP(r)}/{word}"
    if k < .6: return f"http://{r.choice(BAD_DOMAINS)}/{word}?id={tok(r,8)}"
    if k < .8: return f"https://{r.choice(BAD_DOMAINS)}/{word}"
    return f"http://shrt.example.net/{tok(r,5)}"

def p_verify(r):
    u = bad_url(r, "verify-account")
    org = r.choice(list(ORGS.values()))[0]
    return (f"{org} Security <security-alert@{r.choice(BAD_DOMAINS)}>", pick(r, "URGENT: Verify Your Account Immediately", "Action required: confirm your identity", "Your account will be suspended"),
            f"Dear customer,\n\nWe detected unusual activity. Your account will be suspended within 24 hours unless you verify your password and confirm your identity: {u}\n\n{org} Security Team", u, "", "fake account verification")

def p_invoice(r):
    u = bad_url(r, "invoice")
    return (f"Accounts <billing@{r.choice(BAD_DOMAINS)}>", pick(r, "Overdue invoice - payment details required", "Unpaid invoice #%d" % r.randint(1000, 9999)),
            f"Dear user,\n\nYour invoice is overdue. Outstanding payment must be settled today to avoid legal action. Review payment details: {u}", u,
            pick(r, "invoice.pdf.exe", "invoice_details.zip", "invoice.html", "invoice.docm", "invoice.pdf"), "fake invoice")

def p_prize(r):
    u = bad_url(r, "claim")
    return (f"Rewards <winner@{r.choice(BAD_DOMAINS)}>", "Congratulations! You have won a prize!!!",
            f"Dear member,\n\nYou have won a free gift card! Claim your prize now: {u}\nConfirm your personal details to receive it. Offer expires today!", u, "", "fake prize")

def p_password(r):
    u = bad_url(r, "reset-password")
    return (f"IT Help Desk <helpdesk@{r.choice(BAD_DOMAINS)}>", pick(r, "Password expires today", "Password expiration notice"),
            f"Dear user,\n\nYour password expires in 2 hours. Click here to enter your password and keep access: {u}", u, "", "fake password expiration")

def p_delivery(r):
    u = bad_url(r, "track")
    return (f"ParcelGo Delivery <parcel@{r.choice(BAD_DOMAINS)}>", pick(r, "Delivery failed - action required", "Your parcel is on hold"),
            f"Dear customer,\n\nWe could not deliver your parcel. Confirm your address and pay a small fee here: {u} Failure to respond will result in return to sender.", u,
            pick(r, "", "label.zip"), "fake delivery")

def p_hr(r):
    u = bad_url(r, "payroll-update")
    return (f"HR Payroll <hr-payroll@example.net>", pick(r, "Salary revision - confirm your details", "Updated payroll form"),
            f"Hello,\n\nPlease confirm your bank account number and personal details for the new payroll system: {u}", u, pick(r, "", "payroll_form.docm"), "fake HR request")

def p_exec(r):
    # subtle: short, polite, no links, no urgency words - relies on sender mismatch
    n = name(r)
    return (f"{n} (CEO) <ceo.{r.choice(LAST).lower()}@example.com.invalid.test>", pick(r, "Quick favor", "Are you available?"),
            f"Hi,\n\nI am in a meeting and need you to buy {r.randint(3, 8)} gift cards for a client. Reply here when ready and I will send the details.\n\n{n}", "", "", "fake executive request")

PHISH = [p_verify, p_invoice, p_prize, p_password, p_delivery, p_hr, p_exec]


def make_row(r, fn, label):
    sender, subject, body, urls, att, cat = fn(r)
    # light random noise so templates are not identical
    if r.random() < 0.3: body += pick(r, "\n\nThank you.", "\n\nRegards.", "\n\n--\nSent from my device")
    dom = sender.split("@")[-1].rstrip(">")
    return {"sender": sender, "sender_domain": dom, "subject": subject, "body": body, "urls": urls,
            "attachment_name": att, "label": label, "category": cat}


def generate(n_each=300, seed=42) -> pd.DataFrame:
    r = random.Random(seed)
    rows = [make_row(r, LEGIT[i % len(LEGIT)], "LEGITIMATE") for i in range(n_each)]
    rows += [make_row(r, PHISH[i % len(PHISH)], "PHISHING") for i in range(n_each)]
    r.shuffle(rows)
    df = pd.DataFrame(rows)
    df = df.drop_duplicates(subset=["sender", "subject", "body"]).reset_index(drop=True)
    df.insert(0, "email_id", [f"EML-{i + 1:04d}" for i in range(len(df))])
    return df


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-class", type=int, default=320)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/phishing_email_dataset.csv")
    a = ap.parse_args()
    d = generate(a.per_class, a.seed)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    d.to_csv(a.out, index=False)
    print(f"Wrote {len(d)} emails -> {a.out}")
    print(d["label"].value_counts().to_string())
    print(d["category"].value_counts().to_string())
