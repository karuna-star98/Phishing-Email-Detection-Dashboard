"""Run the suite and write docs/TEST_REPORT.md (Test ID | Scenario | Input | Expected | Actual | Result).
Run:  python tests/generate_test_report.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
import test_phishing  # noqa: E402


class Collect(unittest.TextTestResult):
    rows = {}
    def _rec(self, test, status, actual):
        doc = (test._testMethodDoc or "").split("|")
        doc = [d.strip() for d in doc] + ["", "", ""]
        tid = test._testMethodName.split("_")[1].upper()
        self.rows[tid] = (tid, doc[0], doc[1], doc[2], actual, status)
    def addSuccess(self, t): super().addSuccess(t); self._rec(t, "PASS", "Matched expected result")
    def addFailure(self, t, e): super().addFailure(t, e); self._rec(t, "FAIL", str(e[1]).splitlines()[0][:120])
    def addError(self, t, e): super().addError(t, e); self._rec(t, "FAIL", "Error: " + str(e[1])[:120])
    def addSkip(self, t, r): super().addSkip(t, r); self._rec(t, "SKIP", r)


suite = unittest.defaultTestLoader.loadTestsFromModule(test_phishing)
result = unittest.TextTestRunner(resultclass=Collect, verbosity=0).run(suite)
os.makedirs("docs", exist_ok=True)
with open("docs/TEST_REPORT.md", "w") as fh:
    fh.write("# Test Report (auto-generated)\n\n| Test ID | Scenario | Input | Expected result | Actual result | Pass/Fail |\n|---|---|---|---|---|---|\n")
    for r in sorted(Collect.rows.values()):
        fh.write("| " + " | ".join(c.replace("|", "/") for c in r) + " |\n")
    fh.write(f"\n**{result.testsRun} tests, {len(result.failures)} failures, {len(result.errors)} errors, {len(result.skipped)} skipped.**\n")
print("Wrote docs/TEST_REPORT.md")
