"""
validate_ml_setup.py — ML Setup Validation
Smart Web Honeypot | FYP01-CS-2530-0463

Validates that all ML components are properly installed and working.
Run this before deploying the honeypot.
"""

import sys
import os

print("=" * 70)
print("  ML Setup Validation")
print("=" * 70)

checks = {
    "Dependencies": [],
    "Modules": [],
    "Data Files": [],
    "Configuration": []
}

# ── Check 1: Dependencies ──
print("\n[1] Checking dependencies...")
print("-" * 70)

deps = [
    ("flask", "Flask"),
    ("sklearn", "scikit-learn"),
    ("joblib", "joblib"),
    ("numpy", "numpy"),
    ("pandas", "pandas"),
]

for import_name, display_name in deps:
    try:
        __import__(import_name)
        print(f"✓ {display_name}")
        checks["Dependencies"].append((display_name, True))
    except ImportError:
        print(f"✗ {display_name} — NOT INSTALLED")
        checks["Dependencies"].append((display_name, False))

# ── Check 2: Modules ──
print("\n[2] Checking honeypot modules...")
print("-" * 70)

modules = [
    "feature_extractor",
    "ml_model",
    "detection_engine",
    "dataset_generator",
    "trainer",
    "logger",
]

for module in modules:
    try:
        __import__(module)
        print(f"✓ {module}.py")
        checks["Modules"].append((module, True))
    except Exception as e:
        print(f"✗ {module}.py — ERROR: {e}")
        checks["Modules"].append((module, False))

# ── Check 3: Data Files ──
print("\n[3] Checking data files...")
print("-" * 70)

files = [
    ("logs/", "logs directory"),
    ("ml_dataset.csv", "training dataset"),
    ("rf_model.pkl", "trained model"),
]

for path, display_name in files:
    exists = os.path.exists(path)
    status = "✓" if exists else "⚠"
    print(f"{status} {display_name}: {path}")
    checks["Data Files"].append((display_name, exists))

# ── Check 4: ML Model Status ──
print("\n[4] Checking ML model...")
print("-" * 70)

try:
    from ml_model import MLModel
    from feature_extractor import FeatureExtractor
    
    ml = MLModel()
    extractor = FeatureExtractor()
    
    print(f"Model trained: {ml.is_trained}")
    print(f"Model classes: {list(ml.model.classes_) if ml.is_trained else 'N/A'}")
    
    # Test prediction
    test_entry = {
        "payload": "admin' OR '1'='1",
        "payload_len": 16,
        "user_agent": "sqlmap/1.7",
        "method": "POST",
        "path": "/login",
        "query_string": "",
        "matched_rules": ["SQLi: OR 1=1"]
    }
    
    features = extractor.extract(test_entry)
    print(f"Feature extraction: {len(features)} features extracted")
    
    if ml.is_trained:
        result = ml.predict(features)
        print(f"Test prediction: {result['attack_type']} (confidence: {result['confidence']:.4f})")
    
    checks["Configuration"].append(("ML Model", ml.is_trained))
    
except Exception as e:
    print(f"✗ ML model check failed: {e}")
    checks["Configuration"].append(("ML Model", False))

# ── Check 5: Detection Engine ──
print("\n[5] Checking detection engine...")
print("-" * 70)

try:
    from detection_engine import DetectionEngine
    
    engine = DetectionEngine()
    print(f"Rule patterns loaded:")
    print(f"  - SQL injection: {len(engine._sqli_re)} patterns")
    print(f"  - XSS: {len(engine._xss_re)} patterns")
    print(f"  - Traversal: {len(engine._traversal_re)} patterns")
    print(f"  - Scanner: {len(engine._scanner_re)} patterns")
    print(f"ML enabled: {engine.ml_enabled}")
    
    checks["Configuration"].append(("Detection Engine", True))
    
except Exception as e:
    print(f"✗ Detection engine check failed: {e}")
    checks["Configuration"].append(("Detection Engine", False))

# ── Summary ──
print("\n" + "=" * 70)
print("  Validation Summary")
print("=" * 70)

all_pass = True

for category, items in checks.items():
    if not items:
        continue
    
    passed = sum(1 for _, status in items if status)
    total = len(items)
    
    status_icon = "✓" if passed == total else "⚠" if passed > 0 else "✗"
    print(f"\n{status_icon} {category}: {passed}/{total}")
    
    for name, status in items:
        if not status:
            print(f"    ⚠ {name}")
            all_pass = False

print("\n" + "=" * 70)

if all_pass:
    print("✓ ALL CHECKS PASSED!")
    print("\nYou can now run:")
    print("  1. python trainer.py      (train/retrain ML model)")
    print("  2. python app.py          (start honeypot)")
    print("  3. python test_ml_complete.py (verify everything works)")
    sys.exit(0)
else:
    print("⚠ Some checks failed!")
    print("\nTo fix:")
    print("  1. Install missing dependencies: pip install -r requirements.txt")
    print("  2. Train ML model: python trainer.py")
    print("\nThen run this validation again.")
    sys.exit(1)
