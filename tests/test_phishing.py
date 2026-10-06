"""Automated tests. Run:  python -m unittest discover -s tests -v   (or: pytest)
Docstring format:  Scenario | Input | Expected   (used by tests/generate_test_report.py)"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from backend.app import create_app
from backend.database import Database
from backend.services.analyzer import analyze_email, run_detectors
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.content_analyzer import analyze_email_content
from backend.services.risk_engine import calculate_phishing_score, classify
from backend.services.sender_analyzer import analyze_sender
from backend.services.url_analyzer import analyze_url
from ml.predict import PhishingMLModel

PHISH = dict(sender="security-alert@account-check.invalid.test", subject="URGENT: Verify Your Account Immediately",
             body="Dear customer,\nYour account will be suspended within 24 hours. Verify your password: http://198.51.100.10/verify-account")
LEGIT = dict(sender="Cyber Club <training@example.org>", subject="Cybersecurity Workshop Reminder",
             body="Hi team, the workshop is Friday at 3 PM in Room 12. See you there.")


def codes(analysis):
    return {f["code"] for f in analysis["findings"]}


class TestEmailLogic(unittest.TestCase):
    def test_t01_legit_email(self):
        """Legitimate email | workshop reminder from example.org | LOW RISK, score <= 20"""
        r = analyze_email(**LEGIT)
        self.assertEqual(r["classification"], "LOW RISK")
        self.assertLessEqual(r["rule_score"], 20)

    def test_t02_urgent_phishing(self):
        """Urgent phishing-style email | demo phishing sample | HIGH RISK"""
        r = analyze_email(**PHISH)
        self.assertEqual(r["classification"], "HIGH RISK / LIKELY PHISHING")
        self.assertGreaterEqual(r["rule_score"], 71)

    def test_t03_credential_request(self):
        """Credential request | 'verify your password' | CREDENTIAL_REQUEST rule + password flag"""
        c = analyze_email_content("", "Please verify your password to keep access.")
        self.assertGreater(c["categories"]["CREDENTIAL_REQUEST"]["count"], 0)
        self.assertTrue(c["contains_password_request"])

    def test_t04_financial_request(self):
        """Financial request | 'outstanding payment ... wire transfer' | FINANCIAL_PRESSURE found"""
        c = analyze_email_content("Overdue invoice", "Outstanding payment: send a wire transfer today.")
        self.assertGreater(c["categories"]["FINANCIAL_PRESSURE"]["count"], 0)

    def test_t05_generic_greeting(self):
        """Generic greeting | 'Dear customer,' | generic_greeting True"""
        self.assertTrue(analyze_email_content("x", "Dear customer,\nHello")["generic_greeting"])
        self.assertFalse(analyze_email_content("x", "Dear Priya,\nHello")["generic_greeting"])

    def test_t06_safe_url(self):
        """Safe-looking URL | https://portal.example.org/students | score 0 and HTTPS note only"""
        u = analyze_url("https://portal.example.org/students")
        self.assertEqual(u["url_risk_score"], 0)
        self.assertIn("HTTPS_NOTE", codes(u))

    def test_t07_raw_ip_url(self):
        """Raw IP URL | http://198.51.100.10/verify-account | RAW_IP_URL, score >= 30"""
        u = analyze_url("http://198.51.100.10/verify-account")
        self.assertIn("RAW_IP_URL", codes(u))
        self.assertGreaterEqual(u["url_risk_score"], 30)

    def test_t08_non_https_url(self):
        """Non-HTTPS URL | http://example.com/page | NON_HTTPS_URL"""
        self.assertIn("NON_HTTPS_URL", codes(analyze_url("http://example.com/page")))

    def test_t09_excessive_subdomains(self):
        """Excessive subdomains | a.b.c.d.example.net | EXCESSIVE_SUBDOMAINS"""
        self.assertIn("EXCESSIVE_SUBDOMAINS", codes(analyze_url("https://a.b.c.d.example.net/")))

    def test_t10_url_keyword(self):
        """Suspicious keyword in URL | /login/verify | URL_KEYWORDS"""
        self.assertIn("URL_KEYWORDS", codes(analyze_url("https://example.net/login/verify")))

    def test_t11_no_url(self):
        """No URL | plain text body | zero url analyses, url_count 0"""
        r = analyze_email(**LEGIT)
        self.assertEqual(r["url_analyses"], [])
        self.assertEqual(r["features"]["url_count"], 0)

    def test_t12_multiple_urls(self):
        """Multiple URLs | 3 links in body | 3 analyses, only the bad ones counted suspicious"""
        body = "See https://example.org/a and http://198.51.100.9/verify and https://example.com/b"
        r = analyze_email("a@example.org", "links", body)
        self.assertEqual(len(r["url_analyses"]), 3)
        self.assertEqual(r["features"]["suspicious_url_count"], 1)

    def test_t13_normal_attachment(self):
        """Normal attachment | report.pdf | risk 0"""
        self.assertEqual(analyze_attachment("report.pdf")["attachment_risk_score"], 0)

    def test_t14_executable_attachment(self):
        """Executable attachment | setup.exe | EXECUTABLE_ATTACHMENT, risk >= 80"""
        a = analyze_attachment("setup.exe")
        self.assertIn("EXECUTABLE_ATTACHMENT", codes(a))
        self.assertGreaterEqual(a["attachment_risk_score"], 80)

    def test_t15_double_extension(self):
        """Double extension | invoice.pdf.exe | DOUBLE_EXTENSION, risk >= 90"""
        a = analyze_attachment("invoice.pdf.exe")
        self.assertIn("DOUBLE_EXTENSION", codes(a))
        self.assertGreaterEqual(a["attachment_risk_score"], 90)

    def test_t16_empty_subject(self):
        """Empty subject | subject '' | no crash, subject_length 0"""
        r = analyze_email("a@example.org", "", "Hello there")
        self.assertEqual(r["features"]["subject_length"], 0)

    def test_t17_empty_body(self):
        """Empty body | body '' | no crash, body_length 0"""
        r = analyze_email("a@example.org", "Hi", "")
        self.assertEqual(r["features"]["body_length"], 0)

    def test_t18_invalid_sender(self):
        """Invalid sender | 'not-an-email' | INVALID_SENDER finding"""
        s = analyze_sender("not-an-email")
        self.assertIn("INVALID_SENDER", {f["code"] for f in s["sender_findings"]})

    def test_t19_high_uppercase_ratio(self):
        """High uppercase ratio | ALL-CAPS text | uppercase_ratio > 0.8"""
        c = analyze_email_content("URGENT NOTICE", "ACT NOW OR LOSE ACCESS")
        self.assertGreater(c["uppercase_ratio"], 0.8)

    def test_t20_exclamation_marks(self):
        """Multiple exclamation marks | 'Win!!! Now!!!' | exclamation_count 6"""
        self.assertEqual(analyze_email_content("Win!!!", "Now!!!")["exclamation_count"], 6)

    def test_t21_score_boundaries(self):
        """Rule-score boundary | 20/21/40/41/70/71 | LOW/MODERATE/MODERATE/SUSPICIOUS/SUSPICIOUS/HIGH"""
        self.assertEqual([classify(s) for s in (20, 21, 40, 41, 70, 71)],
                         ["LOW RISK", "MODERATE RISK", "MODERATE RISK", "SUSPICIOUS", "SUSPICIOUS", "HIGH RISK / LIKELY PHISHING"])

    def test_t22_score_cap(self):
        """Score cap | every rule triggered | rule_score capped at 100"""
        feats = {k: 1 for k in ("urgent_keyword_count", "credential_keyword_count", "financial_keyword_count",
                                "threat_keyword_count", "reward_keyword_count", "personal_info_keyword_count",
                                "suspicious_url_count", "suspicious_attachment", "generic_greeting",
                                "contains_password_request", "contains_personal_info_request")}
        feats["sender_risk_score"] = 90
        self.assertEqual(calculate_phishing_score(feats)["rule_score"], 100)

    def test_t23_false_positive_urgent_hr(self):
        """Known false positive | genuine HR 'Urgent: submit documents' | flagged for urgency only, stays LOW RISK"""
        r = analyze_email("HR <hr@example.com>", "Urgent: Submit your documents today", "Hi Sam, please upload them to the intranet.")
        self.assertIn("URGENCY", r["contributions"][0]["rule"])
        self.assertEqual(r["classification"], "LOW RISK")

    def test_t24_html_link_mismatch(self):
        """Link text mismatch | <a href=198.51.100.7>example.org</a> | LINK_TEXT_MISMATCH"""
        r = analyze_email("a@example.org", "x", '<p>Visit <a href="http://198.51.100.7/x">www.example.org</a></p>')
        self.assertIn("LINK_TEXT_MISMATCH", {f["code"] for u in r["url_analyses"] for f in u["findings"]})

    def test_t25_lookalike_domain(self):
        """Lookalike sender domain | support@examp1ebank.invalid.test | LOOKALIKE_DOMAIN or digits flag"""
        s = analyze_sender("Support <support@bluebirdbnk.example.net>")
        self.assertIn("LOOKALIKE_DOMAIN", {f["code"] for f in s["sender_findings"]})

    def test_t26_never_visits_url(self):
        """Static analysis only | URL on reserved TLD | returns instantly, defanged form shown"""
        u = analyze_url("http://never-resolves.invalid.test/verify")
        self.assertTrue(u["safe_representation"].startswith("hxxp://"))


class TestStorageAndApi(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "t.db")
        self.app = create_app(self.path, ml_enabled=True)
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_t27_database_save(self):
        """Database save | analysis saved | row + indicators stored, body NOT stored"""
        db = Database(self.path)
        res = analyze_email(**PHISH)
        aid = db.save_analysis(res, body=PHISH["body"], store_body=False)
        got = db.get_analysis(aid)
        self.assertEqual(got["classification"], res["classification"])
        self.assertFalse(got["body_stored"])
        self.assertGreater(len(got["result"]["indicators"]), 0)

    def test_t28_api_validation(self):
        """API validation | empty JSON / non-string / oversized | 400 responses"""
        self.assertEqual(self.client.post("/api/analyze", json={}).status_code, 400)
        self.assertEqual(self.client.post("/api/analyze", json={"sender": 5}).status_code, 400)
        self.assertEqual(self.client.post("/api/analyze", json={"body": "x" * 60000}).status_code, 400)
        self.assertEqual(self.client.post("/api/analyze/url", json={"url": ""}).status_code, 400)

    def test_t29_ml_prediction(self):
        """ML prediction | phishing vs legit sample | probability higher for phishing (skipped if model missing)"""
        m = PhishingMLModel()
        if not m.available:
            self.skipTest("run `python -m ml.train_model` first")
        p = analyze_email(**PHISH, ml_model=m)["ml_probability"]
        l = analyze_email(**LEGIT, ml_model=m)["ml_probability"]
        self.assertGreater(p, l)
        self.assertTrue(0 <= l <= 1 and 0 <= p <= 1)

    def test_t30_history_retrieval(self):
        """Analysis-history retrieval | save 2, filter + fetch by id | correct counts and detail"""
        a = self.client.post("/api/analyze", json=PHISH).json
        self.client.post("/api/analyze", json=LEGIT)
        listing = self.client.get("/api/analyses").json
        self.assertEqual(listing["total"], 2)
        high = self.client.get("/api/analyses?classification=HIGH RISK / LIKELY PHISHING").json
        self.assertEqual(high["total"], 1)
        self.assertEqual(self.client.get(f"/api/analyses/{a['analysis_id']}").status_code, 200)
        self.assertEqual(self.client.get("/api/analyses/9999").status_code, 404)

    def test_t31_delete_requires_login(self):
        """Authorization | DELETE without login, then with login | 401 then 200"""
        aid = self.client.post("/api/analyze", json=LEGIT).json["analysis_id"]
        self.assertEqual(self.client.delete(f"/api/analyses/{aid}").status_code, 401)
        self.client.post("/api/register", json={"username": "analyst1", "password": "a-long-password-1"})
        self.assertEqual(self.client.post("/api/login", json={"username": "analyst1", "password": "a-long-password-1"}).status_code, 200)
        self.assertEqual(self.client.delete(f"/api/analyses/{aid}").status_code, 200)

    def test_t32_dashboard_stats(self):
        """Dashboard statistics | 1 phish + 1 legit | totals and indicator counts"""
        self.client.post("/api/analyze", json=PHISH)
        self.client.post("/api/analyze", json=LEGIT)
        s = self.client.get("/api/dashboard/stats").json
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["likely_phishing"], 1)
        ind = self.client.get("/api/dashboard/indicators").json
        self.assertTrue(ind["top_indicators"])

    def test_t33_bad_login_and_save_false(self):
        """Auth + privacy | wrong password; save=false | 401; nothing stored"""
        self.assertEqual(self.client.post("/api/login", json={"username": "x", "password": "y"}).status_code, 401)
        self.client.post("/api/analyze", json={**LEGIT, "save": False})
        self.assertEqual(self.client.get("/api/analyses").json["total"], 0)

    def test_t34_upload_validation(self):
        """File validation | .exe upload rejected, .txt parsed | 400 then 200"""
        bad = self.client.post("/api/parse-eml", json={"filename": "x.exe", "content": "hi"})
        self.assertEqual(bad.status_code, 400)
        ok = self.client.post("/api/parse-eml", json={"filename": "s.txt", "content": "From: a@example.org\nSubject: Hi\n\nBody text"})
        self.assertEqual(ok.json["subject"], "Hi")


if __name__ == "__main__":
    unittest.main()
