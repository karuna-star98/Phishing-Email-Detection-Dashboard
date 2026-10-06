"""Fill the dashboard with analyses of SYNTHETIC dataset emails (spread over the last 7 days).
Run:  python -m scripts.seed_history [--n 150]"""
import argparse
import random
from datetime import datetime, timedelta, timezone

import pandas as pd

from backend.app import create_app


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=150)
    a = ap.parse_args()
    from backend.services.analyzer import analyze_email
    app = create_app()
    df = pd.read_csv("data/phishing_email_dataset.csv").fillna("").sample(a.n, random_state=1)
    rnd, now = random.Random(1), datetime.now(timezone.utc)
    for r in df.itertuples():
        res = analyze_email(r.sender, r.subject, r.body, r.attachment_name, app.ml)
        ts = (now - timedelta(minutes=rnd.randint(0, 7 * 24 * 60))).strftime("%Y-%m-%dT%H:%M:%S")
        app.db.save_analysis(res, created_at=ts)
    print(f"Seeded {a.n} synthetic analyses into {app.db.path}")


if __name__ == "__main__":
    main()
