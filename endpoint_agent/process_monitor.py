import psutil
from datetime import datetime


class ProcessMonitor:

    def get_running_processes(self):
        """
        Collect information about currently running processes.
        """

        processes = []

        for process in psutil.process_iter(
            [
                "pid",
                "name",
                "status",
                "cpu_percent",
                "memory_percent",
                "exe"
            ]
        ):
            try:
                process_info = process.info

                processes.append({
                    "pid": process_info["pid"],
                    "name": process_info["name"],
                    "status": process_info["status"],
                    "cpu_percent": process_info["cpu_percent"],
                    "memory_percent": round(
                        process_info["memory_percent"], 2
                    ),
                    "executable": process_info["exe"]
                })

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue

        return processes

    def get_process_summary(self):
        """
        Generate a summary of current process activity.
        """

        processes = self.get_running_processes()

        return {
            "timestamp": datetime.now().isoformat(),
            "total_processes": len(processes),
            "processes": processes
        }
    def detect_suspicious_processes(self):
        suspicious_processes = []

        suspicious_names = [
            "mimikatz.exe",
            "meterpreter.exe",
            "nc.exe",
            "netcat.exe"
        ]

        processes = self.get_running_processes()

        for process in processes:

            suspicion_reasons = []
            suspicion_score = 0

            process_name = (process["name"] or "").lower()
            cpu_usage = process["cpu_percent"] or 0
            memory_usage = process["memory_percent"] or 0
            executable = process["executable"] or ""

            # Ignore known system/idle processes
            safe_processes = [
                "system idle process",
                "system",
                "registry"
            ]

            if process_name in safe_processes:
                continue

            # High CPU usage
            if cpu_usage > 80:
                suspicion_reasons.append("Unusually high CPU usage")
                suspicion_score += 0.3

            # High memory usage
            if memory_usage > 30:
                suspicion_reasons.append("Unusually high memory usage")
                suspicion_score += 0.2

            # Known suspicious process names
            if process_name in suspicious_names:
                suspicion_reasons.append(
                    "Process name matches suspicious indicator"
                )
                suspicion_score += 0.3

            # Executable running from temporary directory
            if "\\temp\\" in executable.lower():
                suspicion_reasons.append(
                    "Process running from temporary directory"
                )
                suspicion_score += 0.3

            if suspicion_score > 0:
                suspicious_processes.append({
                    "pid": process["pid"],
                    "name": process["name"],
                    "executable": executable,
                    "suspicion_score": round(
                        min(suspicion_score, 1.0), 2
                    ),
                    "reasons": suspicion_reasons
                })

        return {
            "total_suspicious_processes": len(
                suspicious_processes
            ),
            "suspicious_processes": suspicious_processes
        }


# Create monitor instance
process_monitor = ProcessMonitor()