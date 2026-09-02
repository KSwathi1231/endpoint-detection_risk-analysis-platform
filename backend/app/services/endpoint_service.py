class EndpointService:

    def analyze_telemetry(self, telemetry: dict):
        """
        Analyze telemetry received from the Endpoint Agent.
        """

        process_data = telemetry.get(
            "process_monitor", {}
        )

        network_data = telemetry.get(
            "network_monitor", {}
        )

        system_data = telemetry.get(
            "system_monitor", {}
        )

        file_data = telemetry.get(
            "file_monitor", {}
        )

        # Extract suspicious activity counts
        suspicious_processes = process_data.get(
            "suspicious_processes", {}
        ).get(
            "total_suspicious_processes", 0
        )

        suspicious_connections = network_data.get(
            "suspicious_connections", {}
        ).get(
            "total_suspicious_connections", 0
        )

        suspicious_file_events = file_data.get(
            "total_suspicious_file_events", 0
        )

        system_anomaly_score = system_data.get(
            "anomaly_score", 0
        )

        # Initial endpoint risk scoring
        risk_score = 0
        risk_reasons = []

        if suspicious_processes > 0:
            risk_score += min(
                suspicious_processes * 15,
                30
            )
            risk_reasons.append(
                f"{suspicious_processes} suspicious process(es) detected"
            )

        if suspicious_connections > 0:
            risk_score += min(
                suspicious_connections * 20,
                30
            )
            risk_reasons.append(
                f"{suspicious_connections} suspicious network connection(s) detected"
            )

        if suspicious_file_events > 0:
            risk_score += min(
                suspicious_file_events * 10,
                25
            )
            risk_reasons.append(
                f"{suspicious_file_events} suspicious file event(s) detected"
            )

        if system_anomaly_score > 0:
            risk_score += system_anomaly_score * 15
            risk_reasons.append(
                "System resource anomaly detected"
            )

        risk_score = round(
            min(risk_score, 100),
            2
        )

        # Determine severity
        if risk_score >= 70:
            severity = "CRITICAL"
        elif risk_score >= 50:
            severity = "HIGH"
        elif risk_score >= 25:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "risk_score": risk_score,
            "severity": severity,
            "risk_reasons": risk_reasons,
            "telemetry_timestamp": telemetry.get(
                "timestamp"
            )
        }


endpoint_service = EndpointService()