from collections import deque
from datetime import datetime, timedelta


class TemporalService:

    def __init__(self):
        # Store recent events in memory
        self.event_history = deque(maxlen=1000)

    def analyze_temporal_pattern(
        self,
        event: dict,
        ml_result: dict
    ):
        """
        Analyze event patterns over time.
        """

        current_time = datetime.now()

        # Store current event
        current_event = {
            "timestamp": current_time,
            "threat_prediction": ml_result.get(
                "threat_prediction", 0
            ),
            "is_anomalous": ml_result.get(
                "is_anomalous", False
            )
        }

        self.event_history.append(current_event)

        # Define time window
        time_window = current_time - timedelta(minutes=1)

        # Get recent events
        recent_events = [
            event
            for event in self.event_history
            if event["timestamp"] >= time_window
        ]

        total_recent_events = len(recent_events)

        # Count suspicious events
        suspicious_events = [
            event
            for event in recent_events
            if event["threat_prediction"] == 1
            or event["is_anomalous"]
        ]

        suspicious_count = len(suspicious_events)

        score = 0.0
        temporal_indicators = []

        # Rule 1: High event frequency
        if total_recent_events >= 10:
            score += 0.30
            temporal_indicators.append(
                f"High event frequency: {total_recent_events} events in 1 minute"
            )

        # Rule 2: Repeated suspicious events
        if suspicious_count >= 5:
            score += 0.40
            temporal_indicators.append(
                f"Repeated suspicious activity: {suspicious_count} suspicious events"
            )

        # Rule 3: Suspicious event burst
        if total_recent_events >= 20 and suspicious_count >= 10:
            score += 0.30
            temporal_indicators.append(
                "Burst of suspicious activity detected"
            )

        score = min(score, 1.0)

        # Determine status
        if score >= 0.6:
            temporal_status = "HIGH_TEMPORAL_RISK"
        elif score > 0:
            temporal_status = "TEMPORAL_PATTERN_DETECTED"
        else:
            temporal_status = "NO_TEMPORAL_ANOMALY"

        return {
            "temporal_score": round(score, 4),
            "temporal_status": temporal_status,
            "recent_event_count": total_recent_events,
            "suspicious_event_count": suspicious_count,
            "temporal_indicators": temporal_indicators
        }


# Singleton instance
temporal_service = TemporalService()