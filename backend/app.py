"""Flask backend. Run:  python -m backend.app   (serves API + dashboard on http://127.0.0.1:5000)"""
import json
import os
import re

from flask import Flask, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

from backend.database import Database
from backend.security import RateLimiter, apply_headers, login_required
from backend.services.analyzer import analyze_email
from backend.services.preprocessing import parse_sample_file
from backend.services.url_analyzer import analyze_url
from ml.predict import PhishingMLModel

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLASSES = {"LOW RISK", "MODERATE RISK", "SUSPICIOUS", "HIGH RISK / LIKELY PHISHING"}


def create_app(db_path=None, ml_enabled=None):
    app = Flask(__name__, static_folder=None)
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY", "dev-only-change-me"),
        MAX_CONTENT_LENGTH=300 * 1024,                       # reject huge uploads
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
    app.db = Database(db_path or os.getenv("PHISH_DB_PATH", os.path.join(ROOT, "data", "phishing.db")))
    use_ml = (os.getenv("ML_ENABLED", "true").lower() == "true") if ml_enabled is None else ml_enabled
    app.ml = PhishingMLModel(os.path.join(ROOT, "models", "phishing_model.joblib")) if use_ml else None
    app.store_body = os.getenv("STORE_EMAIL_BODY", "false").lower() == "true"
    limiter = RateLimiter(int(os.getenv("RATE_LIMIT_PER_MIN", 120)))
    app.after_request(apply_headers)

    def err(msg, code):
        return jsonify(error=msg), code

    @app.before_request
    def guard():
        if request.path.startswith("/api/"):
            if not limiter.check(request.remote_addr or "local"):
                return err("Rate limit exceeded, slow down", 429)
            if request.method in ("POST", "PUT", "DELETE") and request.content_length and not request.is_json:
                return err("Content-Type must be application/json", 415)   # also blocks cross-site form posts

    @app.errorhandler(413)
    def too_big(_): return err("Request too large", 413)
    @app.errorhandler(404)
    def nf(_): return err("Not found", 404)
    @app.errorhandler(405)
    def na(_): return err("Method not allowed", 405)

    def body_json():
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else None

    # ---------------- analysis ----------------
    @app.post("/api/analyze")
    def api_analyze():
        d = body_json()
        if d is None:
            return err("JSON object expected", 400)
        for f, lim in (("sender", 320), ("subject", 500), ("body", 50_000)):
            if f in d and not isinstance(d[f], str):
                return err(f"'{f}' must be a string", 400)
            if len(d.get(f, "")) > lim:
                return err(f"'{f}' exceeds {lim} characters", 400)
        atts = d.get("attachments", d.get("attachment_name", ""))
        if not isinstance(atts, (str, list)) or (isinstance(atts, list) and not all(isinstance(a, str) for a in atts)):
            return err("'attachment_name' must be a string or list of strings", 400)
        if not (d.get("sender") or d.get("subject") or d.get("body")):
            return err("Provide at least one of sender, subject or body", 400)
        result = analyze_email(d.get("sender", ""), d.get("subject", ""), d.get("body", ""), atts, app.ml)
        if d.get("save", True):
            result["analysis_id"] = app.db.save_analysis(result, d.get("body", ""), app.store_body, session.get("user_id"))
        return jsonify(result), 200

    @app.post("/api/analyze/url")
    def api_analyze_url():
        d = body_json()
        url = (d or {}).get("url")
        if not isinstance(url, str) or not url.strip() or len(url) > 2048:
            return err("'url' (string, max 2048 chars) is required", 400)
        return jsonify(analyze_url(url)), 200      # static analysis only: the URL is never fetched

    @app.post("/api/parse-eml")
    def api_parse():
        d = body_json() or {}
        try:
            return jsonify(parse_sample_file(str(d.get("filename", "")), str(d.get("content", "")))), 200
        except ValueError as e:
            return err(str(e), 400)

    # ---------------- history ----------------
    @app.get("/api/analyses")
    def api_list():
        cls = request.args.get("classification")
        if cls and cls not in CLASSES:
            return err("Unknown classification", 400)
        try:
            limit = max(1, min(200, int(request.args.get("limit", 50))))
            offset = max(0, int(request.args.get("offset", 0)))
        except ValueError:
            return err("limit/offset must be integers", 400)
        rows, total = app.db.list_analyses(cls, (request.args.get("q") or "")[:100] or None,
                                           request.args.get("sort", "date"), request.args.get("order", "desc"), limit, offset)
        return jsonify(items=rows, total=total)

    @app.get("/api/analyses/<int:aid>")
    def api_get(aid):
        a = app.db.get_analysis(aid)
        return (jsonify(a), 200) if a else err("Analysis not found", 404)

    @app.delete("/api/analyses/<int:aid>")
    @login_required
    def api_delete(aid):
        return (jsonify(deleted=aid), 200) if app.db.delete_analysis(aid) else err("Analysis not found", 404)

    # ---------------- dashboard ----------------
    def days_arg():
        try:
            return max(0, min(3650, int(request.args.get("days", 0))))
        except ValueError:
            return 0

    @app.get("/api/dashboard/stats")
    def api_stats():
        return jsonify(app.db.stats(days_arg()))

    @app.get("/api/dashboard/indicators")
    def api_ind():
        return jsonify(app.db.indicator_stats(days_arg()))

    @app.get("/api/ml/metrics")
    def api_ml():
        p = os.path.join(ROOT, "reports", "ml_metrics.json")
        if not os.path.exists(p):
            return err("Run `python -m ml.train_model` first", 404)
        with open(p) as fh:
            return jsonify(json.load(fh))

    @app.get("/reports/<path:name>")
    def reports(name):
        if name not in ("confusion_matrices.png",):
            return err("Not found", 404)
        return send_from_directory(os.path.join(ROOT, "reports"), name)

    # ---------------- auth (optional) ----------------
    @app.post("/api/register")
    def api_register():
        d = body_json() or {}
        u, p = d.get("username", ""), d.get("password", "")
        if not (isinstance(u, str) and re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", u)):
            return err("Username must be 3-32 characters (letters, digits, _ . -)", 400)
        if not (isinstance(p, str) and 10 <= len(p) <= 128):
            return err("Password must be 10-128 characters", 400)
        uid = app.db.create_user(u, generate_password_hash(p))
        return (jsonify(user_id=uid, username=u), 201) if uid else err("Username already taken", 409)

    @app.post("/api/login")
    def api_login():
        d = body_json() or {}
        user = app.db.get_user(username=str(d.get("username", "")))
        if not user or not check_password_hash(user["password_hash"], str(d.get("password", ""))):
            return err("Invalid credentials", 401)          # same message for both cases
        session.clear()
        session["user_id"] = user["user_id"]
        return jsonify(username=user["username"], role=user["role"])

    @app.post("/api/logout")
    def api_logout():
        session.clear()
        return jsonify(ok=True)

    @app.get("/api/me")
    def api_me():
        uid = session.get("user_id")
        u = app.db.get_user(user_id=uid) if uid else None
        return jsonify(authenticated=bool(u), username=u["username"] if u else None)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", ml_enabled=bool(app.ml and app.ml.available),
                       ml_model=app.ml.name if app.ml and app.ml.available else None)

    # ---------------- static dashboard ----------------
    @app.get("/")
    def index():
        return send_from_directory(os.path.join(ROOT, "frontend"), "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(os.path.join(ROOT, "frontend"), name)

    return app


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    create_app().run(host="0.0.0.0", port=port, debug=False)
