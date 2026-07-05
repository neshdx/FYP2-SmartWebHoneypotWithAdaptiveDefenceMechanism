"""
trainer.py — ML Model Trainer
Smart Web Honeypot | FYP01-CS-2530-0463

Trains Random Forest classifier on combined real + synthetic attack data.
Outputs: rf_model.pkl, metrics, and feature importance.
"""

import os
import sys
import json
import csv
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

from dataset_generator import DatasetGenerator
from feature_extractor import FeatureExtractor

MODEL_FILE = os.path.join(
    os.path.dirname(__file__),
    "rf_model.pkl"
)

METRICS_FILE = os.path.join(
    os.path.dirname(__file__),
    "logs",
    "ml_metrics.json"
)


def train_model(test_size=0.2, n_trees=100):
    """
    Generate dataset and train Random Forest classifier.
    
    Args:
        test_size: Fraction for train/test split (default 0.2 = 80/20)
        n_trees: Number of trees in forest (default 100)
    
    Returns:
        (model, metrics_dict)
    """
    
    print("=" * 70)
    print("  ML Model Trainer — Random Forest Classifier")
    print("=" * 70)
    
    # Step 1: Generate dataset
    print("\n[Step 1] Generating dataset...")
    print("-" * 70)
    
    generator = DatasetGenerator()
    X, y = generator.generate(samples_per_class=200)
    
    print(f"\nTotal samples: {len(X)}")
    print(f"Feature dimension: {len(X[0])}")
    
    # Step 2: Train/test split
    print("\n[Step 2] Splitting data (80% train, 20% test)...")
    print("-" * 70)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=42,
        stratify=y  # Maintain class distribution
    )
    
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    
    # Step 3: Train model
    print("\n[Step 3] Training Random Forest ({} trees)...".format(n_trees))
    print("-" * 70)
    
    model = RandomForestClassifier(
        n_estimators=n_trees,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1,  # Use all CPU cores
        verbose=1
    )
    
    model.fit(X_train, y_train)
    
    print("\n✓ Model trained successfully")
    
    # Step 4: Evaluate model
    print("\n[Step 4] Evaluating model...")
    print("-" * 70)
    
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    
    # Step 5: Feature importance
    print("\n[Step 5] Feature Importance:")
    print("-" * 70)
    
    extractor = FeatureExtractor()
    feature_names = extractor.get_feature_names()
    
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    for i in range(min(12, len(feature_names))):
        idx = indices[i]
        importance = importances[idx]
        print(f"  {i+1}. {feature_names[idx]:25s} : {importance:.4f}")
    
    # Step 6: Save model
    print("\n[Step 6] Saving model...")
    print("-" * 70)
    
    os.makedirs(os.path.dirname(MODEL_FILE), exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    
    print(f"✓ Model saved to: {MODEL_FILE}")
    
    # Step 7: Save metrics
    print("\n[Step 7] Saving metrics...")
    print("-" * 70)
    
    metrics = {
        "accuracy": float(accuracy),
        "n_samples": len(X),
        "n_features": len(X[0]),
        "n_trees": n_trees,
        "test_size": test_size,
        "classes": list(model.classes_),
        "class_counts": {
            label: int(np.sum(np.array(y) == label))
            for label in model.classes_
        },
        "feature_importance": {
            feature_names[idx]: float(importances[idx])
            for idx in range(len(feature_names))
        }
    }
    
    os.makedirs(os.path.dirname(METRICS_FILE), exist_ok=True)
    with open(METRICS_FILE, "w") as f:
        json.dump(metrics, f, indent=2)
    
    print(f"✓ Metrics saved to: {METRICS_FILE}")
    
    print("\n" + "=" * 70)
    print(f"  Training Complete! Accuracy: {accuracy*100:.2f}%")
    print("=" * 70)
    
    return model, metrics


if __name__ == "__main__":
    try:
        model, metrics = train_model()
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Training failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
