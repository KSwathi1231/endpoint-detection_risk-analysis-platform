import time
import json
import requests
from datetime import datetime

from process_monitor import process_monitor
from network_monitor import network_monitor
from system_monitor import system_monitor
from file_monitor import file_monitor


class EndpointAgent:

    def collect_endpoint_telemetry(self):
        """
        Collect and combine telemetry from all endpoint monitors.
        """

        # Process analysis
        process_summary = process_monitor.get_process_summary()
        suspicious_processes = (
            process_monitor.detect_suspicious_processes()
        )

        # Network analysis
        network_summary = network_monitor.get_network_summary()
        suspicious_connections = (
            network_monitor.detect_suspicious_connections()
        )

        # System analysis
        system_metrics = system_monitor.get_system_metrics()
        system_anomalies = (
            system_monitor.detect_system_anomalies()
        )

        # File analysis
        suspicious_file_events = (
            file_monitor.analyze_suspicious_file_events()
        )

        # Unified endpoint telemetry
        telemetry = {
            "timestamp": datetime.now().isoformat(),

            "process_monitor": {
                "total_processes": process_summary[
                    "total_processes"
                ],
                "suspicious_processes": suspicious_processes
            },

            "network_monitor": {
                "total_connections": network_summary[
                    "total_connections"
                ],
                "active_remote_connections": network_summary[
                    "active_remote_connections"
                ],
                "suspicious_connections": suspicious_connections
            },

            "system_monitor": system_anomalies,

            "file_monitor": suspicious_file_events
        }

        return telemetry
    def send_telemetry_to_backend(self, telemetry):
  
        backend_url = "http://127.0.0.1:8000/endpoint/telemetry"

        try:
            response = requests.post(
                backend_url,
                json=telemetry,
                timeout=10
            )

            response.raise_for_status()

            print("\nTelemetry successfully sent to backend.")

            backend_response = response.json()

            print("\nBACKEND SECURITY ANALYSIS:")
            print(json.dumps(backend_response, indent=4))

            return backend_response

        except requests.exceptions.ConnectionError:
            print(
                "\nERROR: Cannot connect to backend. "
                "Make sure FastAPI server is running."
            )

        except requests.exceptions.RequestException as error:
            print(
                f"\nERROR sending telemetry: {error}"
            )

        return None

    def start(self):
        """
        Start Endpoint Agent monitoring.
        """

        print("\nEndpoint Agent Started...")
        print("Collecting endpoint telemetry...\n")

        # Start real-time file monitoring
        file_monitor.start_monitoring()

        try:
            # Give file monitor a moment to initialize
            time.sleep(2)

            telemetry = self.collect_endpoint_telemetry()
            backend_response = self.send_telemetry_to_backend(telemetry)

            print("=" * 60)
            print("UNIFIED ENDPOINT TELEMETRY REPORT")
            print("=" * 60)

            print("\nTimestamp:")
            print(telemetry["timestamp"])

            print("\nPROCESS MONITOR")
            print(
                "Total Processes:",
                telemetry["process_monitor"]["total_processes"]
            )
            print(
                "Suspicious Processes:",
                telemetry["process_monitor"]
                ["suspicious_processes"]
                ["total_suspicious_processes"]
            )

            print("\nNETWORK MONITOR")
            print(
                "Total Connections:",
                telemetry["network_monitor"]["total_connections"]
            )
            print(
                "Active Remote Connections:",
                telemetry["network_monitor"]
                ["active_remote_connections"]
            )
            print(
                "Suspicious Connections:",
                telemetry["network_monitor"]
                ["suspicious_connections"]
                ["total_suspicious_connections"]
            )

            print("\nSYSTEM MONITOR")
            print(
                "System Anomaly Detected:",
                telemetry["system_monitor"]
                ["anomaly_detected"]
            )
            print(
                "System Anomaly Score:",
                telemetry["system_monitor"]
                ["anomaly_score"]
            )

            print("\nFILE MONITOR")
            print(
                "Suspicious File Events:",
                telemetry["file_monitor"]
                ["total_suspicious_file_events"]
            )

            print("\n" + "=" * 60)

            return telemetry

        finally:
            file_monitor.stop_monitoring()
            print("\nEndpoint Agent Stopped.")


if __name__ == "__main__":

    agent = EndpointAgent()
    agent.start()