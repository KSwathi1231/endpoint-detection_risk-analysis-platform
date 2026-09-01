import os
import joblib
import pandas as pd
import numpy as np


class MLService:

    def __init__(self):

        # Get backend directory
        BASE_DIR = os.path.dirname(
            os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            )
        )

        MODEL_DIR = os.path.join(BASE_DIR, "trained_models")

        # Load models
        self.threat_classifier = joblib.load(
            os.path.join(MODEL_DIR, "threat_classifier.pkl")
        )

        self.preprocessor = joblib.load(
            os.path.join(MODEL_DIR, "preprocessor.pkl")
        )

        self.anomaly_detector = joblib.load(
            os.path.join(MODEL_DIR, "anomaly_detector.pkl")
        )

        self.anomaly_config = joblib.load(
            os.path.join(MODEL_DIR, "anomaly_config.pkl")
        )

        print("ML models loaded successfully!")


    def analyze(self, event: dict):

        # Convert incoming event to DataFrame
        event_df = pd.DataFrame([event])

        # Preprocess event
        processed_event = self.preprocessor.transform(event_df)

        # Random Forest prediction
        threat_probability = self.threat_classifier.predict_proba(
            processed_event
        )[0][1]

        prediction = self.threat_classifier.predict(
            processed_event
        )[0]

        # Isolation Forest decision score
        raw_anomaly_score = self.anomaly_detector.decision_function(
            processed_event
        )[0]

        # Normalize anomaly score
        score_min = self.anomaly_config["score_min"]
        score_max = self.anomaly_config["score_max"]

        anomaly_score = 1 - (
            (raw_anomaly_score - score_min)
            / (score_max - score_min)
        )

        # Keep score between 0 and 1
        anomaly_score = max(0, min(1, anomaly_score))

        # Isolation Forest anomaly prediction
        anomaly_prediction = self.anomaly_detector.predict(
            processed_event
        )[0]

        return {

            "threat_prediction": int(prediction),

            "threat_probability": round(
                float(threat_probability), 4
            ),

            "anomaly_score": round(
                float(anomaly_score), 4
            ),

            "is_anomalous": bool(
                anomaly_prediction == -1
            )
        }


# Create singleton instance
ml_service = MLService()