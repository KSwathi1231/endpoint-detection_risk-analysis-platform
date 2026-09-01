class BehaviourService:

    def analyze_behaviour(self, event: dict):
        """
        Analyze network behaviour and return:
        - behaviour_score (0 to 1)
        - suspicious_behaviours list
        """

        score = 0.0
        suspicious_behaviours = []

        # 1. High connection rate
        if event.get("rate", 0) > 10000:
            score += 0.20
            suspicious_behaviours.append(
                "Unusually high connection rate"
            )

        # 2. High packet activity
        total_packets = (
            event.get("spkts", 0)
            + event.get("dpkts", 0)
        )

        if total_packets > 100:
            score += 0.15
            suspicious_behaviours.append(
                "High packet volume detected"
            )

        # 3. High data transfer
        total_bytes = (
            event.get("sbytes", 0)
            + event.get("dbytes", 0)
        )

        if total_bytes > 100000:
            score += 0.15
            suspicious_behaviours.append(
                "High data transfer volume"
            )

        # 4. Repeated destination/source connections
        if event.get("ct_dst_src_ltm", 0) > 10:
            score += 0.15
            suspicious_behaviours.append(
                "Repeated connections between source and destination"
            )

        # 5. High connections to same service
        if event.get("ct_srv_dst", 0) > 20:
            score += 0.15
            suspicious_behaviours.append(
                "High number of connections to same service"
            )

        # 6. High source activity
        if event.get("ct_src_ltm", 0) > 20:
            score += 0.10
            suspicious_behaviours.append(
                "Unusually high source connection activity"
            )

        # 7. Multiple destination interactions
        if event.get("ct_dst_ltm", 0) > 20:
            score += 0.10
            suspicious_behaviours.append(
                "High number of destination interactions"
            )

        # Ensure score remains between 0 and 1
        score = min(score, 1.0)

        return {
            "behaviour_score": round(score, 4),
            "suspicious_behaviours": suspicious_behaviours,
            "behaviour_status": (
                "SUSPICIOUS"
                if score >= 0.3
                else "NORMAL"
            )
        }


# Singleton instance
behaviour_service = BehaviourService()