"""Small security helpers: rate limiting, login decorator, security headers."""
import time
from collections import defaultdict, deque
from functools import wraps

from flask import jsonify, request, session


class RateLimiter:
    def __init__(self, max_calls, per_seconds=60):
        self.max, self.per, self.hits = max_calls, per_seconds, defaultdict(deque)

    def check(self, key) -> bool:
        now, dq = time.time(), self.hits[key]
        while dq and dq[0] < now - self.per:
            dq.popleft()
        if len(dq) >= self.max:
            return False
        dq.append(now)
        return True


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("user_id"):
            return jsonify(error="Authentication required"), 401
        return fn(*a, **kw)
    return wrapper


def apply_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; "
                                               "style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'")
    return resp
