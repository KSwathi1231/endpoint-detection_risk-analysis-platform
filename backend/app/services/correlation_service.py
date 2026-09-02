class CorrelationService:

    def correlate_events(
        self,
        ml_result: dict,
        behaviour_result: dict,
        ioc_result: dict,
        temporal_result: dict
    ):
        """
        Correlate multiple security analysis results
        to identify combined threat patterns.
        """

        correlation_score = 0.0
        correlated_indicators = []

        threat_probability = ml_result.get(
            "threat_probability", 0
        )

        anomaly_score = ml_result.get(
            "anomaly_score", 0
        )

        behaviour_score = behaviour_result.get(
            "behaviour_score", 0
        )

        ioc_score = ioc_result.get(
            "ioc_score", 0
        )

        temporal_score = temporal_result.get(
            "temporal_score", 0
        )

        # Rule 1: ML threat + anomaly
        if threat_probability >= 0.7 and anomaly_score >= 0.5:
            correlation_score += 0.30
            correlated_indicators.append(
                "High threat probability correlated with anomalous activity"
            )

        # Rule 2: Suspicious behaviour + anomaly
        if behaviour_score >= 0.4 and anomaly_score >= 0.5:
            correlation_score += 0.25
            correlated_indicators.append(
                "Suspicious behaviour correlated with anomaly detection"
            )

        # Rule 3: IOC + ML threat
        if ioc_score > 0 and threat_probability >= 0.6:
            correlation_score += 0.25
            correlated_indicators.append(
                "IOC indicators correlated with ML threat detection"
            )

        # Rule 4: Temporal pattern + threat
        if temporal_score >= 0.3 and threat_probability >= 0.6:
            correlation_score += 0.20
            correlated_indicators.append(
                "Repeated suspicious activity correlated with threat detection"
            )

        correlation_score = min(correlation_score, 1.0)

        if correlation_score >= 0.6:
            correlation_status = "STRONG_CORRELATION"
        elif correlation_score > 0:
            correlation_status = "PARTIAL_CORRELATION"
        else:
            correlation_status = "NO_SIGNIFICANT_CORRELATION"

        return {
            "correlation_score": round(correlation_score, 4),
            "correlation_status": correlation_status,
            "correlated_indicators": correlated_indicators
        }


# Singleton instance
correlation_service = CorrelationService()