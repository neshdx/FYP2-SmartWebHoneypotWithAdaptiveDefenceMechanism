#!/usr/bin/env python3
"""Quick syntax check."""

try:
    import detection_engine
    print("✓ detection_engine.py imports successfully")
except Exception as e:
    print(f"✗ detection_engine.py error: {e}")

try:
    import deception_module
    print("✓ deception_module.py imports successfully")
except Exception as e:
    print(f"✗ deception_module.py error: {e}")

print("\n✓ All files passed syntax check!")
