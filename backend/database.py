"""SQLite storage. Tables: users, analyses, indicators, url_analyses, keywords.
analyses 1--* indicators / url_analyses / keywords (ON DELETE CASCADE). Raw email bodies are NOT stored
unless STORE_EMAIL_BODY=true."""
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  user_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS analyses(
  analysis_id INTEGER PRIMARY KEY AUTOINCREMENT, sender_domain TEXT, subject TEXT,
  risk_score REAL NOT NULL, rule_score REAL, ml_probability REAL, classification TEXT NOT NULL,
  created_at TEXT NOT NULL, user_id INTEGER REFERENCES users(user_id),
  body_text TEXT, result_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS indicators(
  indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id) ON DELETE CASCADE,
  indicator_type TEXT NOT NULL, description TEXT, severity TEXT);
CREATE TABLE IF NOT EXISTS url_analyses(
  url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id) ON DELETE CASCADE,
  url_safe_representation TEXT, risk_score REAL, findings TEXT);
CREATE TABLE IF NOT EXISTS keywords(
  keyword_id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id) ON DELETE CASCADE,
  keyword TEXT, category TEXT);
CREATE INDEX IF NOT EXISTS idx_an_created ON analyses(created_at);
CREATE INDEX IF NOT EXISTS idx_an_class ON analyses(classification);
CREATE INDEX IF NOT EXISTS idx_an_score ON analyses(risk_score);
CREATE INDEX IF NOT EXISTS idx_ind_an ON indicators(analysis_id);
CREATE INDEX IF NOT EXISTS idx_kw_an ON keywords(analysis_id);
"""
SORTS = {"risk": "risk_score", "date": "created_at"}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


class Database:
    def __init__(self, path):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with closing(self._conn()) as c:
            c.executescript(SCHEMA)
            c.commit()

    def _conn(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        return c

    # ---- analyses ----
    def save_analysis(self, result, body=None, store_body=False, user_id=None, created_at=None) -> int:
        public = {k: v for k, v in result.items() if k not in ("keywords",)}
        with closing(self._conn()) as c:
            cur = c.execute(
                "INSERT INTO analyses(sender_domain,subject,risk_score,rule_score,ml_probability,classification,"
                "created_at,user_id,body_text,result_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (result["sender_domain"], result["subject"][:200], result["risk_score"], result["rule_score"],
                 result["ml_probability"], result["classification"], created_at or now_iso(), user_id,
                 body if store_body else None, json.dumps(public)))
            aid = cur.lastrowid
            c.executemany("INSERT INTO indicators(analysis_id,indicator_type,description,severity) VALUES(?,?,?,?)",
                          [(aid, i["indicator_type"], i["description"], i["severity"]) for i in result["indicators"]])
            c.executemany("INSERT INTO url_analyses(analysis_id,url_safe_representation,risk_score,findings) VALUES(?,?,?,?)",
                          [(aid, u["safe_representation"], u["url_risk_score"], json.dumps(u["findings"])) for u in result["url_analyses"]])
            c.executemany("INSERT INTO keywords(analysis_id,keyword,category) VALUES(?,?,?)",
                          [(aid, k["keyword"], k["category"]) for k in result["keywords"]])
            c.commit()
            return aid

    def list_analyses(self, classification=None, q=None, sort="date", order="desc", limit=50, offset=0):
        where, args = [], []
        if classification:
            where.append("classification = ?"); args.append(classification)
        if q:
            where.append("(subject LIKE ? OR sender_domain LIKE ?)"); args += [f"%{q}%"] * 2
        sql = "SELECT analysis_id,sender_domain,subject,risk_score,classification,created_at FROM analyses"
        if where:
            sql += " WHERE " + " AND ".join(where)
        col = SORTS.get(sort, "created_at")
        sql += f" ORDER BY {col} {'ASC' if order == 'asc' else 'DESC'}, analysis_id DESC LIMIT ? OFFSET ?"
        with closing(self._conn()) as c:
            total = c.execute("SELECT COUNT(*) FROM analyses" + (" WHERE " + " AND ".join(where) if where else ""), args).fetchone()[0]
            rows = [dict(r) for r in c.execute(sql, args + [limit, offset])]
        return rows, total

    def get_analysis(self, aid):
        with closing(self._conn()) as c:
            r = c.execute("SELECT * FROM analyses WHERE analysis_id=?", (aid,)).fetchone()
            if not r:
                return None
            d = dict(r)
            d["result"] = json.loads(d.pop("result_json"))
            d["body_stored"] = d["body_text"] is not None
            return d

    def delete_analysis(self, aid) -> bool:
        with closing(self._conn()) as c:
            n = c.execute("DELETE FROM analyses WHERE analysis_id=?", (aid,)).rowcount
            c.commit()
            return n > 0

    # ---- dashboard ----
    def _since(self, days):
        if not days:
            return "", []
        return " WHERE created_at >= datetime('now', ?)", [f"-{int(days)} days"]

    def stats(self, days=0):
        w, a = self._since(days)
        with closing(self._conn()) as c:
            tot, avg = c.execute(f"SELECT COUNT(*), AVG(risk_score) FROM analyses{w}", a).fetchone()
            by = {r[0]: r[1] for r in c.execute(f"SELECT classification, COUNT(*) FROM analyses{w} GROUP BY classification", a)}
            hist = [0] * 10
            for (s,) in c.execute(f"SELECT risk_score FROM analyses{w}", a):
                hist[min(9, int(s // 10))] += 1
            flagged = c.execute(f"SELECT COUNT(*) FROM analyses{w + (' AND' if w else ' WHERE')} risk_score >= 41", a).fetchone()[0]
        return {"total": tot, "average_risk": round(avg or 0, 1), "by_classification": by,
                "likely_phishing": by.get("HIGH RISK / LIKELY PHISHING", 0), "suspicious": by.get("SUSPICIOUS", 0),
                "moderate": by.get("MODERATE RISK", 0), "low_risk": by.get("LOW RISK", 0),
                "flagged": flagged, "not_flagged": tot - flagged,
                "risk_histogram": [{"range": f"{i * 10}-{i * 10 + 9 if i < 9 else 100}", "count": n} for i, n in enumerate(hist)]}

    def indicator_stats(self, days=0):
        w, a = self._since(days)
        sub = f"(SELECT analysis_id FROM analyses{w})"
        with closing(self._conn()) as c:
            ind = [dict(r) for r in c.execute(
                f"SELECT indicator_type AS type, COUNT(*) AS count FROM indicators WHERE analysis_id IN {sub} "
                "GROUP BY indicator_type ORDER BY count DESC LIMIT 10", a)]
            kw = [dict(r) for r in c.execute(
                f"SELECT keyword, category, COUNT(*) AS count FROM keywords WHERE analysis_id IN {sub} "
                "GROUP BY keyword ORDER BY count DESC LIMIT 10", a)]
            trend = [dict(r) for r in c.execute(
                f"SELECT substr(created_at,1,10) AS day, COUNT(*) AS total, "
                f"SUM(risk_score>=41) AS flagged FROM analyses{w} GROUP BY day ORDER BY day", a)]
        return {"top_indicators": ind, "top_keywords": kw, "trend": trend}

    # ---- users ----
    def create_user(self, username, pw_hash, role="analyst"):
        with closing(self._conn()) as c:
            try:
                cur = c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                                (username, pw_hash, role, now_iso()))
                c.commit()
                return cur.lastrowid
            except sqlite3.IntegrityError:
                return None

    def get_user(self, username=None, user_id=None):
        with closing(self._conn()) as c:
            r = c.execute("SELECT * FROM users WHERE username=?" if username else "SELECT * FROM users WHERE user_id=?",
                          (username or user_id,)).fetchone()
            return dict(r) if r else None
