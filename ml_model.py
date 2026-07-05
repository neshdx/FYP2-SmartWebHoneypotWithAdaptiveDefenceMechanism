import joblib
import os

MODEL_FILE = os.path.join(
    os.path.dirname(__file__),
    "rf_model.pkl"
)

class MLModel:

    def __init__(self):

        self.model = None
        self.is_trained = False

        try:

            self.model = joblib.load(
                MODEL_FILE
            )

            self.is_trained = True

            print(
                "[*] Random Forest model loaded."
            )

        except Exception as e:

            print(
                "[!] Model load failed:",
                e
            )
            import traceback
            traceback.print_exc()
            print(f"[!] Attempted path: {MODEL_FILE}")
            print(f"[!] File exists: {os.path.exists(MODEL_FILE)}")

    def predict(self, features):
        """
        Predict attack type from feature vector.
        
        Args:
            features: List of 12 numeric features
            
        Returns:
            {
                "attack_type": str or None,
                "confidence": float (0-1),
                "ml_used": bool,
                "classes": list of possible classes
            }
        """

        if not self.is_trained:

            return {
                "attack_type": None,
                "confidence": 0.0,
                "ml_used": False,
                "error": "Model not trained"
            }

        try:

            # Get prediction probabilities
            probs = self.model.predict_proba(
                [features]
            )[0]

            # Get top prediction
            pred_index = probs.argmax()
            confidence = float(probs[pred_index])
            attack_type = self.model.classes_[pred_index]

            return {
                "attack_type": attack_type,
                "confidence": round(confidence, 4),
                "ml_used": True,
                "classes": list(self.model.classes_),
                "probabilities": {
                    cls: round(float(prob), 4)
                    for cls, prob in zip(
                        self.model.classes_,
                        probs
                    )
                }
            }
            
        except Exception as e:
            
            return {
                "attack_type": None,
                "confidence": 0.0,
                "ml_used": False,
                "error": str(e)
            }