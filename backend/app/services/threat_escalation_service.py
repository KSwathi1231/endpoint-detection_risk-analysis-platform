class ThreatEscalationService:

    # High-confidence threshold for a suspicious process
    HIGH_CONFIDENCE_THRESHOLD = 0.9

    def escalate_threat(
        self,
        risk_score,
        severity,
        suspicious_processes,
        suspicious_connections,
        suspicious_file_events,
        system_anomaly_score=0
    ):
        """
        Escalate endpoint risk based on:

        HIGH:
        - High-confidence threat detected

        CRITICAL:
        - High-confidence threat
          +
          evidence of harmful endpoint behavior/impact
        """

        escalation_reasons = []

        # =======================================
        # FIND HIGH-CONFIDENCE PROCESSES
        # =======================================

        high_confidence_processes = [

            process
            for process in suspicious_processes

            if process.get(
                "suspicion_score", 0
            ) >= self.HIGH_CONFIDENCE_THRESHOLD
        ]

        high_confidence_count = len(
            high_confidence_processes
        )
        # =======================================
        # CHECK CONTROLLED CRITICAL TEST
        # =======================================

        controlled_critical_processes = [
            process
            for process in suspicious_processes
            if process.get("controlled_critical_test", False)
        ]

        controlled_critical_detected = (
            len(controlled_critical_processes) > 0
        )


        # =======================================
        # CHECK ENDPOINT IMPACT INDICATORS
        # =======================================

        impact_indicators = []

        # Suspicious network activity
        if suspicious_connections > 0:

            impact_indicators.append(
                "Suspicious network activity detected"
            )


        # Suspicious file modifications
        if suspicious_file_events > 0:

            impact_indicators.append(
                "Suspicious file activity detected"
            )


        # Significant system anomaly
        if system_anomaly_score >= 0.7:

            impact_indicators.append(
                "Significant system behavior anomaly detected"
            )


        impact_detected = len(
            impact_indicators
        ) > 0
        


        # =======================================
        # CRITICAL ESCALATION
        #
        # High-confidence threat
        # +
        # Endpoint impact
        # =======================================

        if (
            controlled_critical_detected
            or (
                high_confidence_count >= 1
                and impact_detected
            )
        ):

            risk_score = max(
                risk_score,
                85
            )

            severity = "CRITICAL"

            if controlled_critical_detected:

                escalation_reasons.append(
                    "Controlled critical threat scenario detected "
                    "for automated response testing"
            )

            else:

                escalation_reasons.append(
                    "High-confidence threat correlated "
                    "with harmful endpoint behavior"
            )
            escalation_reasons.extend(
                impact_indicators
            )


        # =======================================
        # HIGH ESCALATION
        #
        # Strong threat evidence but
        # endpoint impact not confirmed
        # =======================================

        elif high_confidence_count >= 1:

            risk_score = max(
                risk_score,
                60
            )

            severity = "HIGH"

            escalation_reasons.append(
                "High-confidence threat indicator detected"
            )


        # =======================================
        # RETURN ESCALATION RESULT
        # =======================================

        return {

            "risk_score": round(
                risk_score,
                2
            ),

            "severity": severity,

            "escalated": len(
                escalation_reasons
            ) > 0,

            "escalation_reasons":
                escalation_reasons,

            "high_confidence_process_count":
                high_confidence_count,

            "endpoint_impact_detected":
                impact_detected,

            "impact_indicators":
                impact_indicators,
            "controlled_critical_test_detected":
                controlled_critical_detected,
        }


# Singleton instance

threat_escalation_service = ThreatEscalationService()