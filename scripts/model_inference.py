
from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd

BASE = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE / "models/typosquatshield_baseline.joblib"
METADATA_PATH = BASE / "models/typosquatshield_model_metadata.json"


class TyposquatShieldModel:
    def __init__(self):
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Model not found: {MODEL_PATH}"
            )

        if not METADATA_PATH.exists():
            raise FileNotFoundError(
                f"Model metadata not found: {METADATA_PATH}"
            )

        self.model = joblib.load(MODEL_PATH)

        self.metadata = json.loads(
            METADATA_PATH.read_text(encoding="utf-8")
        )

        self.features = self.metadata["features"]
        self.preprocessing = self.metadata["preprocessing"]

    def predict(self, feature_values):
        missing = [
            feature
            for feature in self.features
            if feature not in feature_values
        ]

        if missing:
            raise ValueError(
                f"Missing required features: {missing}"
            )

        row = {
            feature: feature_values[feature]
            for feature in self.features
        }

        X = pd.DataFrame([row])

        for feature in self.features:
            X[feature] = pd.to_numeric(
                X[feature],
                errors="raise",
            )

        # Reproduce the D2 age treatment.
        age_column = "observed_package_age_days"
        threshold = self.preprocessing[
            "age_threshold_days"
        ]

        if age_column in X.columns:
            age = X[age_column].iloc[0]

            if pd.notna(age) and age < threshold:
                X.loc[0, age_column] = np.nan

        # Reproduce log1p transformations.
        for feature in self.preprocessing["log1p_features"]:
            if feature in X.columns:
                values = X[feature].dropna()

                if (values < 0).any():
                    raise ValueError(
                        f"Negative values in {feature}"
                    )

                X[feature] = np.log1p(X[feature])

        if np.isinf(X.to_numpy(dtype=float)).any():
            raise ValueError(
                "Infinite feature values are not allowed."
            )

        prediction = int(self.model.predict(X)[0])

        probabilities = self.model.predict_proba(X)[0]

        class_probabilities = dict(
            zip(
                self.model.classes_.tolist(),
                probabilities.tolist(),
            )
        )

        return {
            "predicted_candidate_group": (
                "openssf_exact_version_candidate"
                if prediction == 1
                else "presumed_legitimate"
            ),
            "provisional_group_score": round(
                float(class_probabilities[prediction]),
                4,
            ),
            "openssf_association_score": round(
                float(class_probabilities.get(1, 0.0)),
                4,
            ),
            "model_experiment": self.metadata["experiment"],
            "interpretation": (
                "Experimental candidate-group classification. "
                "Not a verified malware probability or "
                "final installation-risk advisory."
            ),
        }


if __name__ == "__main__":
    print(
        "TYPOSQUATSHIELD - MODEL INFERENCE MODULE"
    )

    predictor = TyposquatShieldModel()

    print("Model loaded successfully.")
    print("Experiment:", predictor.metadata["experiment"])
    print("Required features:", len(predictor.features))
    print("Model classes:", predictor.model.classes_.tolist())
