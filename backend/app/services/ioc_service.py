class IOCService:

    def analyze_iocs(self, event: dict):
        """
        Analyze Indicators of Compromise (IOCs)
        available in the network event.

        Returns:
        - ioc_score (0 to 1)
        - detected_iocs
        """

        score = 0.0
        detected_iocs = []

        # Suspicious ports commonly associated with attacks/services
        suspicious_ports = [
            23,     # Telnet
            445,    # SMB
            3389,   # RDP
            4444,   # Common reverse shell port
            6667    # IRC
        ]

        # Check destination port if available
        dst_port = event.get("dst_port")

        if dst_port is not None and dst_port in suspicious_ports:
            score += 0.30
            detected_iocs.append(
                f"Connection to suspicious port: {dst_port}"
            )

        # Check suspicious service
        suspicious_services = [
            "telnet",
            "irc"
        ]

        service = str(event.get("service", "")).lower()

        if service in suspicious_services:
            score += 0.25
            detected_iocs.append(
                f"Suspicious network service detected: {service}"
            )

        # Check unusual protocol
        suspicious_protocols = [
            "icmp"
        ]

        protocol = str(event.get("proto", "")).lower()

        if protocol in suspicious_protocols:
            score += 0.15
            detected_iocs.append(
                f"Potentially suspicious protocol activity: {protocol}"
            )

        # Check FTP login attempts
        if event.get("is_ftp_login", 0) == 1:
            score += 0.15
            detected_iocs.append(
                "FTP login activity detected"
            )

        # Check excessive FTP commands
        if event.get("ct_ftp_cmd", 0) > 5:
            score += 0.15
            detected_iocs.append(
                "High number of FTP commands detected"
            )

        # Ensure score stays between 0 and 1
        score = min(score, 1.0)

        # Determine IOC status
        if score >= 0.5:
            ioc_status = "HIGH_IOC_MATCH"
        elif score > 0:
            ioc_status = "IOC_INDICATOR_FOUND"
        else:
            ioc_status = "NO_IOC_FOUND"

        return {
            "ioc_score": round(score, 4),
            "ioc_status": ioc_status,
            "detected_iocs": detected_iocs
        }


# Singleton instance
ioc_service = IOCService()