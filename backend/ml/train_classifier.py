"""Train a char-ngram LogReg classifier for Cowrie command intents.

Training signal: the rule-labeled rows currently in the DB (weak supervision).
The model learns to generalize the regex rules — it should match them on the
hold-out and can also classify commands the rules miss (the ``unknown`` bucket).

Run from backend/:

    python -m ml.train_classifier

Outputs:
    data/models/command_classifier.joblib   (pipeline + label mapping)
    data/models/metrics.json                (hold-out metrics)
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sqlalchemy import select

from app.config import settings
from app.database import SessionLocal
from app.models import Attempt

BACKEND_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BACKEND_DIR / "data" / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = MODELS_DIR / "command_classifier.joblib"
METRICS_PATH = MODELS_DIR / "metrics.json"

# Floor below which rare classes are pooled — LogReg won't generalize from < ~20 samples
MIN_SAMPLES_PER_CLASS = 20


def load_dataset() -> tuple[list[str], list[str], list[str]]:
    """Pull (command, intent) pairs from DB, splitting labeled vs unknown."""
    db = SessionLocal()
    try:
        stmt = select(Attempt.command, Attempt.intent).where(
            Attempt.event_id == "cowrie.command.input",
            Attempt.command.isnot(None),
            Attempt.command != "",
        )
        rows = db.execute(stmt).all()
    finally:
        db.close()

    labeled_cmds: list[str] = []
    labeled_intents: list[str] = []
    unknown_cmds: list[str] = []
    for cmd, intent in rows:
        if intent and intent != "unknown":
            labeled_cmds.append(cmd)
            labeled_intents.append(intent)
        else:
            unknown_cmds.append(cmd)
    return labeled_cmds, labeled_intents, unknown_cmds


def drop_rare_classes(cmds: list[str], labels: list[str], floor: int) -> tuple[list[str], list[str]]:
    counts = Counter(labels)
    keep = {k for k, v in counts.items() if v >= floor}
    dropped = {k: v for k, v in counts.items() if v < floor}
    if dropped:
        print(f"  Dropping under-represented classes (< {floor} samples): {dropped}")
    filtered = [(c, l) for c, l in zip(cmds, labels) if l in keep]
    return [c for c, _ in filtered], [l for _, l in filtered]


def build_pipeline() -> Pipeline:
    """Char n-grams + LogReg. Handles obfuscation (base64, hex escapes) far better than word tokens."""
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            min_df=2,
            max_df=0.95,
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            C=4.0,
            max_iter=2000,
            class_weight="balanced",
            n_jobs=1,  # single-threaded is faster on the Pi for this size
        )),
    ])


def predict_with_confidence(pipe: Pipeline, texts: list[str]) -> list[tuple[str, float]]:
    probs = pipe.predict_proba(texts)
    classes = pipe.classes_
    out = []
    for p in probs:
        idx = int(p.argmax())
        out.append((classes[idx], float(p[idx])))
    return out


def main() -> None:
    print(f"[1/4] Loading data from {settings.database_url}")
    cmds, labels, unknown_cmds = load_dataset()
    print(f"  Labeled commands: {len(cmds):>6}  across {len(set(labels))} classes")
    print(f"  Unknown commands: {len(unknown_cmds):>6}  (unseen by training)")

    cmds, labels = drop_rare_classes(cmds, labels, MIN_SAMPLES_PER_CLASS)
    dist = Counter(labels)
    print("  Class distribution:")
    for k, v in dist.most_common():
        print(f"    {k:<22} {v:>6}")

    print("\n[2/4] Stratified 80/20 split")
    X_train, X_test, y_train, y_test = train_test_split(
        cmds, labels, test_size=0.20, stratify=labels, random_state=42
    )
    print(f"  Train: {len(X_train)}  Test: {len(X_test)}")

    print("\n[3/4] Training char-ngram TF-IDF + LogisticRegression")
    pipe = build_pipeline()
    t0 = time.perf_counter()
    pipe.fit(X_train, y_train)
    train_secs = time.perf_counter() - t0
    print(f"  Trained in {train_secs:.2f}s")

    t0 = time.perf_counter()
    y_pred = pipe.predict(X_test)
    infer_secs = time.perf_counter() - t0
    print(f"  Inference on {len(X_test)} samples: {infer_secs*1000:.1f}ms  "
          f"({infer_secs/len(X_test)*1e6:.1f}µs per command)")

    accuracy = (y_pred == y_test).mean() if hasattr(y_pred, "mean") else sum(
        a == b for a, b in zip(y_pred, y_test)
    ) / len(y_test)
    report_dict = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    report_text = classification_report(y_test, y_pred, zero_division=0)
    labels_sorted = sorted(set(y_test))
    cm = confusion_matrix(y_test, y_pred, labels=labels_sorted)

    print("\n=== Hold-out metrics ===")
    print(f"Overall accuracy: {accuracy:.4f}")
    print()
    print(report_text)
    print("Confusion matrix (rows = true, cols = predicted):")
    header = " " * 22 + "  ".join(f"{c[:10]:>10}" for c in labels_sorted)
    print(header)
    for lbl, row in zip(labels_sorted, cm):
        print(f"{lbl:<22}" + "  ".join(f"{v:>10}" for v in row))

    print("\n[4/4] Sampling the 'unknown' bucket — what does the model find?")
    sample = unknown_cmds[: min(5000, len(unknown_cmds))]
    if sample:
        preds = predict_with_confidence(pipe, sample)
        # High-confidence recoveries
        by_class: dict[str, list[tuple[str, float]]] = {}
        for cmd, (cls, conf) in zip(sample, preds):
            if conf >= 0.70:
                by_class.setdefault(cls, []).append((cmd, conf))
        recovered = sum(len(v) for v in by_class.values())
        print(f"  Classified {recovered}/{len(sample)} "
              f"({recovered/len(sample)*100:.1f}%) of sampled unknowns at confidence >= 0.70")
        for cls, items in sorted(by_class.items(), key=lambda kv: -len(kv[1])):
            print(f"  → {cls} ({len(items)} recovered). Examples:")
            for cmd, conf in items[:3]:
                print(f"      [{conf:.2f}] {cmd[:110]}")

    # Persist artifacts
    joblib.dump({"pipeline": pipe, "classes": list(pipe.classes_)}, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps({
        "accuracy": accuracy,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "train_seconds": train_secs,
        "inference_us_per_command": infer_secs / len(X_test) * 1e6,
        "model_path": str(MODEL_PATH),
        "per_class": report_dict,
        "confusion_matrix": {"labels": labels_sorted, "matrix": cm.tolist()},
    }, indent=2))

    print(f"\nArtifacts:")
    print(f"  Model:   {MODEL_PATH}   ({MODEL_PATH.stat().st_size/1024:.0f} KB)")
    print(f"  Metrics: {METRICS_PATH}")


if __name__ == "__main__":
    main()
