# Test Report (auto-generated)

| Test ID | Scenario | Input | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| T01 | Legitimate email | workshop reminder from example.org | LOW RISK, score <= 20 | Matched expected result | PASS |
| T02 | Urgent phishing-style email | demo phishing sample | HIGH RISK | Matched expected result | PASS |
| T03 | Credential request | 'verify your password' | CREDENTIAL_REQUEST rule + password flag | Matched expected result | PASS |
| T04 | Financial request | 'outstanding payment ... wire transfer' | FINANCIAL_PRESSURE found | Matched expected result | PASS |
| T05 | Generic greeting | 'Dear customer,' | generic_greeting True | Matched expected result | PASS |
| T06 | Safe-looking URL | https://portal.example.org/students | score 0 and HTTPS note only | Matched expected result | PASS |
| T07 | Raw IP URL | http://198.51.100.10/verify-account | RAW_IP_URL, score >= 30 | Matched expected result | PASS |
| T08 | Non-HTTPS URL | http://example.com/page | NON_HTTPS_URL | Matched expected result | PASS |
| T09 | Excessive subdomains | a.b.c.d.example.net | EXCESSIVE_SUBDOMAINS | Matched expected result | PASS |
| T10 | Suspicious keyword in URL | /login/verify | URL_KEYWORDS | Matched expected result | PASS |
| T11 | No URL | plain text body | zero url analyses, url_count 0 | Matched expected result | PASS |
| T12 | Multiple URLs | 3 links in body | 3 analyses, only the bad ones counted suspicious | Matched expected result | PASS |
| T13 | Normal attachment | report.pdf | risk 0 | Matched expected result | PASS |
| T14 | Executable attachment | setup.exe | EXECUTABLE_ATTACHMENT, risk >= 80 | Matched expected result | PASS |
| T15 | Double extension | invoice.pdf.exe | DOUBLE_EXTENSION, risk >= 90 | Matched expected result | PASS |
| T16 | Empty subject | subject '' | no crash, subject_length 0 | Matched expected result | PASS |
| T17 | Empty body | body '' | no crash, body_length 0 | Matched expected result | PASS |
| T18 | Invalid sender | 'not-an-email' | INVALID_SENDER finding | Matched expected result | PASS |
| T19 | High uppercase ratio | ALL-CAPS text | uppercase_ratio > 0.8 | Matched expected result | PASS |
| T20 | Multiple exclamation marks | 'Win!!! Now!!!' | exclamation_count 6 | Matched expected result | PASS |
| T21 | Rule-score boundary | 20/21/40/41/70/71 | LOW/MODERATE/MODERATE/SUSPICIOUS/SUSPICIOUS/HIGH | Matched expected result | PASS |
| T22 | Score cap | every rule triggered | rule_score capped at 100 | Matched expected result | PASS |
| T23 | Known false positive | genuine HR 'Urgent: submit documents' | flagged for urgency only, stays LOW RISK | Matched expected result | PASS |
| T24 | Link text mismatch | <a href=198.51.100.7>example.org</a> | LINK_TEXT_MISMATCH | Matched expected result | PASS |
| T25 | Lookalike sender domain | support@examp1ebank.invalid.test | LOOKALIKE_DOMAIN or digits flag | Matched expected result | PASS |
| T26 | Static analysis only | URL on reserved TLD | returns instantly, defanged form shown | Matched expected result | PASS |
| T27 | Database save | analysis saved | row + indicators stored, body NOT stored | Matched expected result | PASS |
| T28 | API validation | empty JSON / non-string / oversized | 400 responses | Matched expected result | PASS |
| T29 | ML prediction | phishing vs legit sample | probability higher for phishing (skipped if model missing) | Matched expected result | PASS |
| T30 | Analysis-history retrieval | save 2, filter + fetch by id | correct counts and detail | Matched expected result | PASS |
| T31 | Authorization | DELETE without login, then with login | 401 then 200 | Matched expected result | PASS |
| T32 | Dashboard statistics | 1 phish + 1 legit | totals and indicator counts | Matched expected result | PASS |
| T33 | Auth + privacy | wrong password; save=false | 401; nothing stored | Matched expected result | PASS |
| T34 | File validation | .exe upload rejected, .txt parsed | 400 then 200 | Matched expected result | PASS |

**34 tests, 0 failures, 0 errors, 0 skipped.**
