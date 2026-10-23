"""Random Forest training and prediction for CyberSentinel AI.

Leakage controls:
  * identifiers (timestamp, source_ip, destination_ip, source_port) are NOT features;
  * exact duplicate feature rows are dropped BEFORE the split, so no row can be in both sets;
  * the stratified split happens before any fitting, and every reported metric
    comes from the held-out test set.
"""
import json, time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             precision_recall_fscore_support)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from dataset import CLASSES, COLUMNS

NUMERIC = ["destination_port", "duration", "packet_count", "bytes_sent", "bytes_received",
           "failed_login_count", "unique_destination_ports", "outbound_inbound_ratio"]
CATEGORICAL = ["protocol"]
FEATURES = NUMERIC + CATEGORICAL
ART = Path(__file__).parent / "artifacts"
INCONCLUSIVE = "Suspicious — Further Investigation Required"
CONF_THRESHOLD = 0.5


def validate(df):
    missing = [c for c in COLUMNS if c not in df.columns]
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    if len(df) < 100:
        raise ValueError("At least 100 records are required for training.")
    bad = sorted(set(df["label"]) - set(CLASSES))
    if bad:
        raise ValueError("Unknown labels: " + ", ".join(map(str, bad)))
    for c in NUMERIC:
        df[c] = pd.to_numeric(df[c], errors="raise")
        if (df[c] < 0).any() or not np.isfinite(df[c]).all():
            raise ValueError(f"Column {c} must be finite and non-negative.")
    df["protocol"] = df["protocol"].astype(str).str.upper()
    if not df["protocol"].isin(["TCP", "UDP", "ICMP"]).all():
        raise ValueError("protocol must be TCP, UDP or ICMP.")
    counts = df["label"].value_counts()
    if len(counts) < 2 or counts.min() < 10:
        raise ValueError("Each present class needs at least 10 records and at least 2 classes are required.")
    return df


def build_pipeline(seed=42):
    pre = ColumnTransformer([("num", "passthrough", NUMERIC),
                             ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL)])
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=seed, n_jobs=-1)
    return Pipeline([("pre", pre), ("rf", rf)])


def train(df, seed=42):
    df = validate(df.copy())
    n0 = len(df)
    df = df.drop_duplicates(subset=FEATURES + ["label"]).reset_index(drop=True)
    X, y = df[FEATURES], df["label"]
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=seed)
    pipe = build_pipeline(seed)
    cv = cross_val_score(build_pipeline(seed), Xtr, ytr, cv=StratifiedKFold(5, shuffle=True, random_state=seed))
    pipe.fit(Xtr, ytr)
    pred = pipe.predict(Xte)
    labels = [c for c in CLASSES if c in set(y)]
    p, r, f, _ = precision_recall_fscore_support(yte, pred, labels=labels, average="macro", zero_division=0)
    rep = classification_report(yte, pred, labels=labels, output_dict=True, zero_division=0)
    names = pipe.named_steps["pre"].get_feature_names_out()
    imp = sorted(({"feature": n.split("__")[1], "importance": round(float(v), 4)}
                  for n, v in zip(names, pipe.named_steps["rf"].feature_importances_)),
                 key=lambda d: -d["importance"])
    metrics = {
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "model": "RandomForestClassifier(n_estimators=200, class_weight=balanced)",
        "evaluated_on": "held-out stratified test set (25%)",
        "n_records": n0, "duplicates_removed": n0 - len(df),
        "n_train": len(Xtr), "n_test": len(Xte),
        "accuracy": round(float(accuracy_score(yte, pred)), 4),
        "macro": {"precision": round(float(p), 4), "recall": round(float(r), 4), "f1": round(float(f), 4)},
        "cv_accuracy_train_mean": round(float(cv.mean()), 4), "cv_accuracy_train_std": round(float(cv.std()), 4),
        "labels": labels,
        "per_class": [{"label": l, **{k: round(float(rep[l][k]), 4) for k in ("precision", "recall", "f1-score")},
                       "support": int(rep[l]["support"])} for l in labels],
        "confusion_matrix": confusion_matrix(yte, pred, labels=labels).tolist(),
        "feature_importance": imp,
    }
    ART.mkdir(exist_ok=True)
    joblib.dump(pipe, ART / "model.joblib")
    (ART / "metrics.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    return pipe, metrics


def load():
    mp, jp = ART / "model.joblib", ART / "metrics.json"
    if mp.exists() and jp.exists():
        return joblib.load(mp), json.loads(jp.read_text(encoding="utf-8"))
    return None, None


def predict(pipe, event):
    row = {}
    for c in NUMERIC:
        v = float(event[c])
        if not np.isfinite(v) or v < 0:
            raise ValueError(f"{c} must be a finite, non-negative number")
        row[c] = v
    proto = str(event.get("protocol", "")).upper()
    if proto not in ("TCP", "UDP", "ICMP"):
        raise ValueError("protocol must be TCP, UDP or ICMP")
    row["protocol"] = proto
    proba = pipe.predict_proba(pd.DataFrame([row])[FEATURES])[0]
    order = np.argsort(proba)[::-1]
    classes = pipe.named_steps["rf"].classes_
    top, conf = classes[order[0]], float(proba[order[0]])
    return {"label": top if conf >= CONF_THRESHOLD else INCONCLUSIVE, "top_class": top,
            "confidence": round(conf, 4),
            "note": "Confidence is the Random Forest vote share, not a calibrated probability.",
            "probabilities": {classes[i]: round(float(proba[i]), 4) for i in order[:3]}}
