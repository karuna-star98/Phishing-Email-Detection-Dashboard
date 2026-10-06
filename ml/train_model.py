"""Train + compare models on the synthetic dataset, then save the best one.

Run:  python -m ml.train_model
Outputs: models/phishing_model.joblib, reports/ml_metrics.json, reports/confusion_matrices.png
"""
import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from backend.services import risk_engine
from backend.services.analyzer import run_detectors
from backend.services.feature_extractor import ML_FEATURE_COLS
from backend.services.preprocessing import clean_text_for_ml
from ml.evaluation import compute_metrics, plot_confusion_matrices

DATA = "data/phishing_email_dataset.csv"
ALERT_THRESHOLD = 41      # rule/hybrid score >= 41 counts as "flagged"
SEED = 42
PREFERRED = "LogReg (TF-IDF + indicators)"


def build_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Run the SAME detectors used in the app, so training features == serving features."""
    rows = []
    for r in df.itertuples():
        prep, _, _, _, _, feats = run_detectors(r.sender, r.subject, r.body, r.attachment_name)
        row = {"text": clean_text_for_ml(prep["subject"], prep["body"]), **feats}
        row["rule_score"] = risk_engine.calculate_phishing_score(feats)["rule_score"]
        row["y"] = int(r.label == "PHISHING")
        row["category"] = r.category
        rows.append(row)
    return pd.DataFrame(rows)


def make_models():
    def text_tf():
        return TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)
    def struct():
        return StandardScaler()
    tfidf_only = ColumnTransformer([("t", text_tf(), "text")])
    combined = ColumnTransformer([("t", text_tf(), "text"), ("s", struct(), ML_FEATURE_COLS)])
    struct_only = ColumnTransformer([("s", struct(), ML_FEATURE_COLS)])
    return {
        "NaiveBayes (TF-IDF)": Pipeline([("f", tfidf_only), ("m", MultinomialNB())]),
        "LogReg (TF-IDF)": Pipeline([("f", tfidf_only), ("m", LogisticRegression(max_iter=1000, class_weight="balanced"))]),
        "LogReg (TF-IDF + indicators)": Pipeline([("f", combined), ("m", LogisticRegression(max_iter=1000, class_weight="balanced"))]),
        "RandomForest (indicators only)": Pipeline([("f", struct_only), ("m", RandomForestClassifier(n_estimators=200, random_state=SEED, class_weight="balanced"))]),
        "RandomForest (TF-IDF + indicators)": Pipeline([("f", combined), ("m", RandomForestClassifier(n_estimators=200, random_state=SEED, class_weight="balanced"))]),
    }


def main():
    os.makedirs("models", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    raw = pd.read_csv(DATA).fillna("").drop_duplicates(subset=["sender", "subject", "body"])
    df = build_frame(raw)
    X, y = df.drop(columns=["y"]), df["y"]
    X_tr, X_tmp, y_tr, y_tmp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=SEED)
    X_val, X_te, y_val, y_te = train_test_split(X_tmp, y_tmp, test_size=0.50, stratify=y_tmp, random_state=SEED)
    print(f"train={len(X_tr)} validation={len(X_val)} test={len(X_te)}")

    models, val_f1, test_res, fitted = make_models(), {}, {}, {}
    for name, pipe in models.items():
        pipe.fit(X_tr, y_tr)
        fitted[name] = pipe
        val_f1[name] = compute_metrics(y_val, pipe.predict(X_val))["f1"]
        test_res[name] = compute_metrics(y_te, pipe.predict(X_te))
    # Chosen on VALIDATION F1 only. Ties (common on synthetic data) go to Logistic Regression with
    # indicators: it is explainable and gives better-calibrated probabilities than Naive Bayes.
    best = max(val_f1, key=lambda k: (val_f1[k], k == PREFERRED))
    print("validation F1:", val_f1, "\nselected:", best)

    rules_pred = (X_te["rule_score"] >= ALERT_THRESHOLD).astype(int)
    test_res["Rule engine only"] = compute_metrics(y_te, rules_pred)
    proba = fitted[best].predict_proba(X_te)[:, 1]
    hyb = [risk_engine.hybrid_score(rs, p) for rs, p in zip(X_te["rule_score"], proba)]
    test_res[f"Hybrid (rules + {best})"] = compute_metrics(y_te, (np.array(hyb) >= ALERT_THRESHOLD).astype(int))

    # Harder test: hide ONE phishing category from training, see if it is still caught.
    loco = {}
    for cat in sorted(df.loc[df.y == 1, "category"].unique()):
        mask = df["category"] == cat
        pipe = make_models()[best]
        pipe.fit(X[~mask], y[~mask])
        p = pipe.predict_proba(X[mask])[:, 1]
        hy = np.array([risk_engine.hybrid_score(rs, q) for rs, q in zip(X[mask]["rule_score"], p)])
        loco[cat] = {"n": int(mask.sum()),
                     "ml_recall": round(float((p >= 0.5).mean()), 3),
                     "rules_recall": round(float((X[mask]["rule_score"] >= ALERT_THRESHOLD).mean()), 3),
                     "hybrid_recall": round(float((hy >= ALERT_THRESHOLD).mean()), 3)}

    joblib.dump({"pipeline": fitted[best], "name": best, "features": ML_FEATURE_COLS}, "models/phishing_model.joblib")
    report = {"dataset_rows": len(df), "split": {"train": len(X_tr), "validation": len(X_val), "test": len(X_te)},
              "selected_model": best, "validation_f1": val_f1, "test_metrics": test_res,
              "leave_one_phishing_category_out": loco,
              "notes": ["Data is SYNTHETIC and template-based: scores are optimistic compared with real mail.",
                        "Model selected on validation F1; test set used once for reporting."]}
    with open("reports/ml_metrics.json", "w") as fh:
        json.dump(report, fh, indent=2)
    plot_confusion_matrices(test_res, "reports/confusion_matrices.png")
    print(json.dumps({k: v for k, v in test_res.items()}, indent=1))
    print("leave-one-category-out:", json.dumps(loco, indent=1))


if __name__ == "__main__":
    main()
