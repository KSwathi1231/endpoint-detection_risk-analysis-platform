class ResponseAgent:

    def determine_response(
        self,
        risk_result: dict,
        correlation_result: dict,
        ioc_result: dict
    ):
        """
        Determine the recommended security response
        based on the complete contextual analysis.
        """

        severity = risk_result.get("severity", "LOW")
        risk_score = risk_result.get("risk_score", 0)
        correlation_score = correlation_result.get(
            "correlation_score", 0
        )
        ioc_score = ioc_result.get("ioc_score", 0)

        recommended_actions = []
        response_priority = "LOW"

        # CRITICAL response
        if severity == "CRITICAL":
            response_priority = "CRITICAL"
            recommended_actions = [
                "Immediately isolate the affected endpoint",
                "Block suspicious network connections",
                "Create critical security incident",
                "Preserve forensic evidence",
                "Notify security administrator"
            ]

        # HIGH response
        elif severity == "HIGH":
            response_priority = "HIGH"
            recommended_actions = [
                "Generate high-priority security alert",
                "Investigate affected endpoint",
                "Monitor related network activity",
                "Check for additional indicators of compromise"
            ]

        # MEDIUM response
        elif severity == "MEDIUM":
            response_priority = "MEDIUM"
            recommended_actions = [
                "Flag event for investigation",
                "Increase monitoring of related activity",
                "Collect additional contextual information"
            ]

        # LOW response
        else:
            response_priority = "LOW"
            recommended_actions = [
                "Continue normal monitoring",
                "Store event for future correlation"
            ]

        # Additional context-based actions
        if ioc_score >= 0.5:
            recommended_actions.append(
                "Investigate detected Indicators of Compromise"
            )

        if correlation_score >= 0.6:
            recommended_actions.append(
                "Investigate potentially coordinated attack activity"
            )

        return {
            "response_priority": response_priority,
            "risk_score": risk_score,
            "recommended_actions": recommended_actions,
            "automation_status": self._get_automation_status(
                severity
            )
        }

    def _get_automation_status(self, severity):

        if severity == "CRITICAL":
            return "AUTOMATED_CONTAINMENT_RECOMMENDED"

        elif severity == "HIGH":
            return "AUTOMATED_ALERT_RECOMMENDED"

        elif severity == "MEDIUM":
            return "HUMAN_REVIEW_RECOMMENDED"

        return "MONITORING_ONLY"


# Singleton instance
response_agent = ResponseAgent()