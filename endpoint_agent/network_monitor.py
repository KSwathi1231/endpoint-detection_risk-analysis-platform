import psutil
import socket
from datetime import datetime


class NetworkMonitor:

    def get_network_connections(self):
        """
        Collect active network connections from the endpoint.
        """

        connections = []

        try:
            active_connections = psutil.net_connections(kind="inet")

            for connection in active_connections:

                try:
                    local_address = (
                        f"{connection.laddr.ip}:{connection.laddr.port}"
                        if connection.laddr
                        else None
                    )

                    remote_address = (
                        f"{connection.raddr.ip}:{connection.raddr.port}"
                        if connection.raddr
                        else None
                    )

                    process_name = None

                    if connection.pid:
                        try:
                            process = psutil.Process(connection.pid)
                            process_name = process.name()
                        except (
                            psutil.NoSuchProcess,
                            psutil.AccessDenied
                        ):
                            process_name = "Unknown"

                    connections.append({
                        "pid": connection.pid,
                        "process_name": process_name,
                        "local_address": local_address,
                        "remote_address": remote_address,
                        "status": connection.status,
                        "family": (
                            "IPv4"
                            if connection.family == socket.AF_INET
                            else "IPv6"
                        ),
                        "type": (
                            "TCP"
                            if connection.type == socket.SOCK_STREAM
                            else "UDP"
                        )
                    })

                except Exception:
                    continue

        except psutil.AccessDenied:
            print(
                "Access denied. Run terminal as Administrator "
                "to see all network connections."
            )

        return connections

    def get_network_summary(self):
        """
        Generate a summary of endpoint network activity.
        """

        connections = self.get_network_connections()

        active_remote_connections = [
            connection
            for connection in connections
            if connection["remote_address"] is not None
        ]

        return {
            "timestamp": datetime.now().isoformat(),
            "total_connections": len(connections),
            "active_remote_connections": len(
                active_remote_connections
            ),
            "connections": connections
        }
    def detect_suspicious_connections(self):
    
        suspicious_connections = []

        # Ports sometimes associated with remote access,
        # command/control, or commonly abused services.
        suspicious_ports = [
            4444,   # Often used by testing/backdoor tools
            5555,
            6667,
            1337,
            31337
        ]

        connections = self.get_network_connections()

        for connection in connections:

            suspicion_score = 0
            suspicion_reasons = []

            remote_address = connection["remote_address"]
            process_name = (
                connection["process_name"] or ""
            ).lower()

            # Ignore connections without remote endpoints
            if not remote_address:
                continue

            try:
                # Extract remote port from address
                remote_port = int(
                    remote_address.rsplit(":", 1)[1]
                )
            except (ValueError, IndexError):
                remote_port = None

            # Suspicious remote ports
            if remote_port in suspicious_ports:
                suspicion_score += 0.4
                suspicion_reasons.append(
                    f"Connection to unusual remote port: {remote_port}"
                )

            # Suspicious process indicators
            suspicious_processes = [
                "mimikatz.exe",
                "meterpreter.exe",
                "nc.exe",
                "netcat.exe"
            ]

            if process_name in suspicious_processes:
                suspicion_score += 0.5
                suspicion_reasons.append(
                    "Network activity from suspicious process"
                )

            # High suspicion threshold
            if suspicion_score > 0:
                suspicious_connections.append({
                    "pid": connection["pid"],
                    "process_name": connection["process_name"],
                    "local_address": connection["local_address"],
                    "remote_address": remote_address,
                    "status": connection["status"],
                    "suspicion_score": round(
                        min(suspicion_score, 1.0), 2
                    ),
                    "reasons": suspicion_reasons
                })

        return {
            "total_suspicious_connections": len(
                suspicious_connections
            ),
            "suspicious_connections": suspicious_connections
        }


# Singleton instance
network_monitor = NetworkMonitor()