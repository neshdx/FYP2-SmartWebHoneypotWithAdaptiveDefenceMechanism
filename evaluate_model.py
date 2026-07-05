"""
evaluate_model.py — Cross-Validation & Confusion Matrix Evaluation
Smart Web Honeypot | FYP01-CS-2530-0463

WHY THIS EXISTS:
A single 80/20 train/test split (as used by trainer.py for the live model)
gives one accuracy number that can be misleadingly high or low depending on
which samples happened to land in the test set. This script runs proper
k-fold stratified cross-validation instead, and produces a confusion matrix
so you can see WHICH classes get confused with which - not just an overall
percentage. This is the evidence base for the Testing & Evaluation chapter.

Usage:
  python3 evaluate_model.py
"""

import json
import numpy as np
from collections import defaultdict

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.preprocessing import LabelEncoder

from dataset_generator import DatasetGenerator
from feature_extractor import FeatureExtractor


def run_evaluation(samples_per_class=150, n_folds=5):
    print("=" * 70)
    print("  Smart Honeypot — Cross-Validation & Confusion Matrix Evaluation")
    print("=" * 70)

    # ── Build dataset (same combined real+synthetic source as trainer.py) ──
    generator = DatasetGenerator()
    X, y = generator.generate(samples_per_class=samples_per_class)
    X = np.array(X)

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    classes = list(le.classes_)

    print(f"\n[*] Total samples: {len(X)}")
    print(f"[*] Classes: {classes}")

    # ── Model: same hyperparameters as trainer.py, for a fair comparison ───
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    # ── 5-fold stratified cross-validation ──────────────────────────────────
    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
    scores = cross_val_score(model, X, y_encoded, cv=skf, scoring="accuracy")

    print(f"\n[*] {n_folds}-Fold Stratified Cross-Validation Results")
    print("-" * 70)
    for i, s in enumerate(scores, 1):
        print(f"    Fold {i}: {s*100:.2f}%")
    print(f"    Mean:   {scores.mean()*100:.2f}%  (+/- {scores.std()*100:.2f}%)")
    print("\n    Report this as: \"{:.1f}% ± {:.1f}% across {}-fold cross-validation\"".format(
        scores.mean() * 100, scores.std() * 100, n_folds
    ))

    # ── Confusion matrix from a single held-out fold (for per-class detail) ─
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    cm = confusion_matrix(y_test, y_pred)
    print("\n[*] Confusion Matrix (rows = actual, columns = predicted)")
    print("-" * 70)
    header = "".join(f"{c[:10]:>12s}" for c in classes)
    print(f"{'':22s}{header}")
    for i, row in enumerate(cm):
        row_str = "".join(f"{v:12d}" for v in row)
        print(f"{classes[i]:22s}{row_str}")

    # ── Per-class precision/recall/f1 ───────────────────────────────────────
    print("\n[*] Classification Report")
    print("-" * 70)
    print(classification_report(y_test, y_pred, target_names=classes, digits=3))

    # ── Identify the most confused class pairs ──────────────────────────────
    print("[*] Most Confused Class Pairs (off-diagonal confusion matrix entries)")
    print("-" * 70)
    confusions = []
    for i in range(len(classes)):
        for j in range(len(classes)):
            if i != j and cm[i][j] > 0:
                confusions.append((cm[i][j], classes[i], classes[j]))
    confusions.sort(reverse=True)
    if confusions:
        for count, actual, predicted in confusions[:8]:
            print(f"    {count:3d}x  actual={actual:22s} predicted as {predicted}")
    else:
        print("    No confusion - all test samples classified correctly.")

    # ── Save results for inclusion in report ────────────────────────────────
    results = {
        "n_folds": n_folds,
        "samples_total": len(X),
        "cv_scores": [float(s) for s in scores],
        "cv_mean_accuracy": float(scores.mean()),
        "cv_std": float(scores.std()),
        "classes": classes,
        "confusion_matrix": cm.tolist(),
        "classification_report": classification_report(
            y_test, y_pred, target_names=classes, output_dict=True
        ),
        "top_confusions": [
            {"count": int(c), "actual": a, "predicted_as": p}
            for c, a, p in confusions[:10]
        ],
    }

    with open("logs/cross_validation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\n[*] Full results saved to: logs/cross_validation_results.json")

    return results


if __name__ == "__main__":
    run_evaluation(samples_per_class=150, n_folds=5)
