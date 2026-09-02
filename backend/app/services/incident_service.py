from datetime import datetime
from uuid import uuid4


class IncidentService:

    def __init__(self):
        # Temporary in-memory incident storage
        self.incidents = []

    def create_incident(
        self,
        risk_result: dict,
        response_result: dict,
        analysis_result: dict
    ):
        """
        Create a security incident for HIGH or CRITICAL threats.
        """

        severity = risk_result.get("severity", "LOW")

        # Create incidents only for HIGH and CRITICAL events
        if severity not in ["HIGH", "CRITICAL"]:
            return {
                "incident_created": False,
                "message": "Risk level does not require incident creation"
            }

        incident = {
            "incident_id": str(uuid4()),
            "created_at": datetime.now().isoformat(),
            "status": "OPEN",
            "severity": severity,
            "risk_score": risk_result.get("risk_score", 0),
            "threat_probability": analysis_result.get(
                "threat_probability", 0
            ),
            "anomaly_score": analysis_result.get(
                "anomaly_score", 0
            ),
            "response_priority": response_result.get(
                "response_priority", "LOW"
            ),
            "recommended_actions": response_result.get(
                "recommended_actions", []
            )
        }

        self.incidents.append(incident)

        return {
            "incident_created": True,
            "incident": incident
        }

    def get_all_incidents(self):
        return self.incidents

    def get_incident_by_id(self, incident_id: str):
        for incident in self.incidents:
            if incident["incident_id"] == incident_id:
                return incident

        return None


# Singleton instance
incident_service = IncidentService()