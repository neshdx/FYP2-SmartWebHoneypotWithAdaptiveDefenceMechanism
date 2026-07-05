"""
ML Model Evaluation & Comparison
Smart Web Honeypot | FYP02-CS-2610-0463

Models selected based on Literature Review:
- Random Forest
- XGBoost
- Gradient Boosting
- Neural Network (MLP)
- Logistic Regression

Uses the same dataset generation pipeline as trainer.py:
Real honeypot logs + Synthetic attack dataset
"""

import numpy as np
import pandas as pd

from dataset_generator import DatasetGenerator

from sklearn.model_selection import (
    train_test_split,
    cross_val_score
)

from sklearn.preprocessing import StandardScaler

from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier
)

from sklearn.linear_model import LogisticRegression

from sklearn.neural_network import MLPClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder


class MLEvaluator:

    def __init__(self):

        self.X = None
        self.y = None

        self.X_train = None
        self.X_test = None

        self.y_train = None
        self.y_test = None

        self.scaler = StandardScaler()

        self.results = {}

        self.encoder = LabelEncoder()


    def load_dataset(self):

        print("=" * 70)
        print("Loading Honeypot Dataset")
        print("=" * 70)


        generator = DatasetGenerator()


        # SAME AS trainer.py
        X, y = generator.generate(
            samples_per_class=200
        )


        self.X = np.array(X)


        # Encode labels for XGBoost compatibility
        self.y = self.encoder.fit_transform(
            np.array(y)
        )


        print(
            f"\nTotal samples: {len(self.X)}"
        )


        print(
            f"Feature dimension: {len(self.X[0])}"
        )


        self.X_train, self.X_test, \
        self.y_train, self.y_test = train_test_split(

            self.X,
            self.y,

            test_size=0.2,

            random_state=42,

            stratify=self.y

        )


        print(
            f"Training samples: {len(self.X_train)}"
        )

        print(
            f"Testing samples: {len(self.X_test)}"
        )


    def train_models(self):


        models = {


            # YOUR DEPLOYED MODEL
            "Random Forest (Selected)":


                RandomForestClassifier(

                    n_estimators=100,

                    max_depth=15,

                    min_samples_split=5,

                    min_samples_leaf=2,

                    class_weight="balanced",

                    random_state=42,

                    n_jobs=-1
                ),



            # Ensemble ML comparison
            "Gradient Boosting":


                GradientBoostingClassifier(

                    n_estimators=100,

                    random_state=42

                ),



            # Literature: Kumar et al.
            "XGBoost":


                XGBClassifier(

                    n_estimators=100,

                    learning_rate=0.1,

                    max_depth=6,

                    eval_metric="mlogloss",

                    random_state=42

                ),



            # Deep Learning comparison
            "MLP Neural Network":


                MLPClassifier(

                    hidden_layer_sizes=(64,32),

                    activation="relu",

                    max_iter=1000,

                    random_state=42

                ),



            # Baseline
            "Logistic Regression":


                LogisticRegression(

                    max_iter=2000,

                    class_weight="balanced",

                    random_state=42

                )
        }


        print("\n")
        print("=" * 70)
        print("Training Literature-Based ML Models")
        print("=" * 70)



        X_train_scaled = self.scaler.fit_transform(

            self.X_train

        )


        X_test_scaled = self.scaler.transform(

            self.X_test

        )



        for name, model in models.items():


            print(
                f"\nTraining {name}..."
            )


            if name in [
                "MLP Neural Network",
                "Logistic Regression"
            ]:


                model.fit(
                    X_train_scaled,
                    self.y_train
                )


                prediction = model.predict(
                    X_test_scaled
                )


                cv = cross_val_score(

                    model,

                    self.scaler.fit_transform(self.X),

                    self.y,

                    cv=5

                )



            else:


                model.fit(

                    self.X_train,

                    self.y_train

                )


                prediction = model.predict(

                    self.X_test

                )


                cv = cross_val_score(

                    model,

                    self.X,

                    self.y,

                    cv=5

                )



            accuracy = accuracy_score(

                self.y_test,

                prediction

            )


            precision = precision_score(

                self.y_test,

                prediction,

                average="weighted"

            )


            recall = recall_score(

                self.y_test,

                prediction,

                average="weighted"

            )


            f1 = f1_score(

                self.y_test,

                prediction,

                average="weighted"

            )



            self.results[name] = {


                "accuracy":accuracy,

                "precision":precision,

                "recall":recall,

                "f1":f1,

                "cv":cv.mean(),

                "prediction":prediction

            }



            print(

                f"Accuracy={accuracy:.4f} | "
                f"F1={f1:.4f} | "
                f"CV={cv.mean():.4f}"

            )



    def show_results(self):


        print("\n")
        print("="*100)

        print("MODEL COMPARISON RESULTS")

        print("="*100)


        table=[]


        for name,result in self.results.items():


            table.append({

                "Model":name,

                "Accuracy":round(result["accuracy"],4),

                "Precision":round(result["precision"],4),

                "Recall":round(result["recall"],4),

                "F1 Score":round(result["f1"],4),

                "Cross Validation":round(result["cv"],4)

            })


        df=pd.DataFrame(table)


        print(
            df.to_string(index=False)
        )



        print("\n")


        print(
            "="*100
        )


        print(
            "FINAL SELECTED MODEL : RANDOM FOREST"
        )


        print(
            "="*100
        )



        rf=self.results["Random Forest (Selected)"]



        print(

            f"""
Accuracy : {rf['accuracy']:.4f}
Precision: {rf['precision']:.4f}
Recall   : {rf['recall']:.4f}
F1 Score : {rf['f1']:.4f}

Reason:
Random Forest was selected because it provides high accuracy,
better generalisation through ensemble learning,
low computational overhead,
and suitability for real-time honeypot deployment.
"""

        )



        print(
            classification_report(

                self.y_test,

                rf["prediction"],

                target_names=self.encoder.classes_

            )

        )


        print(

            confusion_matrix(

                self.y_test,

                rf["prediction"]

            )

        )




def main():


    evaluator = MLEvaluator()


    evaluator.load_dataset()


    evaluator.train_models()


    evaluator.show_results()




if __name__ == "__main__":

    main()