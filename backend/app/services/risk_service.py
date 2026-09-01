class RiskService:

    def calculate_risk(
        self,
        threat_probability: float,
        anomaly_score: float,
        behaviour_score: float = 0.0,
        ioc_score: float = 0.0,
        temporal_score: float = 0.0,
        correlation_score: float = 0.0
    ):
        """
        Calculate the final context-aware risk score.

        All input scores must be between 0 and 1.
        """

        # Weighted risk calculation
        risk_score = (
            threat_probability * 35
            + anomaly_score * 20
            + behaviour_score * 15
            + ioc_score * 15
            + temporal_score * 10
            + correlation_score * 5
        )

        # Determine severity
        if risk_score >= 80:
            severity = "CRITICAL"
        elif risk_score >= 60:
            severity = "HIGH"
        elif risk_score >= 35:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "risk_score": round(risk_score, 2),
            "severity": severity,
            "risk_factors": {
                "threat_probability": round(threat_probability, 4),
                "anomaly_score": round(anomaly_score, 4),
                "behaviour_score": round(behaviour_score, 4),
                "ioc_score": round(ioc_score, 4),
                "temporal_score": round(temporal_score, 4),
                "correlation_score": round(correlation_score, 4)
            }
        }


# Singleton instance
risk_service = RiskService()