import psutil
import time
from datetime import datetime


class ProcessMonitor:

    def __init__(self):
        self.cpu_sample_interval = 1.0

    def get_running_processes(self):
        """
        Collect process information with stable CPU sampling.
        """

        processes = []

        # -------------------------------------------------
        # STEP 1: Prime CPU counters
        # -------------------------------------------------
        for process in psutil.process_iter(["pid"]):
            try:
                process.cpu_percent(None)
            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue

        # Wait before taking the actual CPU measurement
        time.sleep(self.cpu_sample_interval)

        # -------------------------------------------------
        # STEP 2: Collect process information
        # -------------------------------------------------
        for process in psutil.process_iter(
            [
                "pid",
                "name",
                "status",
                "memory_percent",
                "exe",
                "cmdline"
            ]
        ):
            try:
                process_info = process.info

                cpu_percent = process.cpu_percent(None)

                processes.append({
                    "pid": process_info["pid"],
                    "name": process_info["name"],
                    "status": process_info["status"],
                    "cpu_percent": round(cpu_percent, 2),
                    "memory_percent": round(
                        process_info["memory_percent"] or 0,
                        2
                    ),
                    "executable": process_info["exe"],
                    "command_line": " ".join(
                        process_info["cmdline"] or []
                    )
                })

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                continue

        return processes


    def get_process_summary(self,processes=None):
        """
        Generate a summary of current process activity.
        """

        if processes is None:
            processes = self.get_running_processes()
        return {
            "timestamp": datetime.now().isoformat(),
            "total_processes": len(processes),
            "processes": processes
        }


    def detect_suspicious_processes(self,processes=None):

        suspicious_processes = []

        # High-confidence malicious tool names
        high_risk_names = [
            "mimikatz.exe",
            "meterpreter.exe",
            "nc.exe",
            "netcat.exe"
        ]

        # Legitimate tools requiring behavioral/context analysis
        contextual_names = [
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "python.exe"
        ]

        # Core system processes to ignore
        safe_processes = [
            "system idle process",
            "system",
            "registry"
        ]

        if processes is None:
            processes = self.get_running_processes()

        for process in processes:

            suspicion_reasons = []
            suspicion_score = 0

            process_name = (
                process["name"] or ""
            ).lower()

            cpu_usage = (
                process["cpu_percent"] or 0
            )

            memory_usage = (
                process["memory_percent"] or 0
            )

            executable = (
                process["executable"] or ""
            )
            command_line = (
                process.get("command_line") or ""
            ).lower()

            executable_lower = executable.lower()

            # Ignore core Windows processes
            if process_name in safe_processes:
                continue


            # --------------------------------
            # 1. HIGH-CONFIDENCE PROCESS NAMES
            # --------------------------------

            if process_name in high_risk_names:

                suspicion_reasons.append(
                    "Process name matches known high-risk security indicator"
                )

                suspicion_score += 0.60


            # --------------------------------
            # 2. CONTEXTUAL PROCESS ANALYSIS
            # --------------------------------

            if process_name in contextual_names:

                suspicious_locations = [
                    "\\temp\\",
                    "\\appdata\\local\\temp\\",
                    "\\downloads\\"
                ]

                if any(
                    location in executable_lower
                    for location in suspicious_locations
                ):

                    suspicion_reasons.append(
                        "Administrative or scripting tool running from unusual location"
                    )

                    suspicion_score += 0.25


            # --------------------------------
            # 3. TEMP DIRECTORY EXECUTION
            # --------------------------------

            if "\\temp\\" in executable_lower:

                suspicion_reasons.append(
                    "Process executing from temporary directory"
                )

                suspicion_score += 0.15
            # --------------------------------
            # CONTROLLED HIGH-RISK TEST
            # --------------------------------

            if "test_high_risk.py" in command_line:

                suspicion_reasons.append(
                    "Controlled high-risk security test process detected"
                )

                suspicion_reasons.append(
                    "Simulated malicious behavior for automated response testing"
                )

                suspicion_score = 1.0

            # --------------------------------
            # CONTROLLED CRITICAL-RISK TEST
            # --------------------------------

            if "test_critical_risk.py" in command_line:

                suspicion_reasons.append(
                    "Controlled critical-risk security test process detected"
                )

                suspicion_reasons.append(
                    "Simulated high-confidence malicious behavior"
                )

                suspicion_reasons.append(
                    "Critical automated response testing enabled"
                )

                suspicion_score = 1.0

                # Explicit marker for escalation layer
                process["controlled_critical_test"] = True

            # --------------------------------
            # 4. SUSTAINED HIGH CPU USAGE
            # --------------------------------

            if cpu_usage >= 70:

                suspicion_reasons.append(
                    f"High CPU usage detected ({cpu_usage}%)"
                )

                suspicion_score += 0.15


            # --------------------------------
            # 5. EXTREMELY HIGH CPU USAGE
            # --------------------------------

            if cpu_usage >= 90:

                suspicion_reasons.append(
                    f"Extremely high CPU usage detected ({cpu_usage}%)"
                )

                suspicion_score += 0.20


            # --------------------------------
            # 6. HIGH MEMORY USAGE
            # --------------------------------

            if memory_usage >= 30:

                suspicion_reasons.append(
                    f"High memory usage detected ({memory_usage}%)"
                )

                suspicion_score += 0.15


            # --------------------------------
            # 7. MULTIPLE INDICATOR CORRELATION
            # --------------------------------

            if len(suspicion_reasons) >= 2:

                suspicion_reasons.append(
                    "Multiple suspicious behavioral indicators detected"
                )

                suspicion_score += 0.10


            # --------------------------------
            # ADD ONLY MEANINGFUL RESULTS
            # --------------------------------

            if suspicion_score >= 0.20:

                suspicious_processes.append({
                    "pid": process["pid"],
                    "name": process["name"],
                    "executable": executable,
                    "cpu_percent": cpu_usage,
                    "memory_percent": memory_usage,
                    "suspicion_score": round(
                        min(suspicion_score, 1.0),
                        2
                    ),
                    "reasons": suspicion_reasons,
                    "controlled_critical_test": process.get(
                        "controlled_critical_test",
                        False
                    ),
                })


        # Sort highest-risk processes first
        suspicious_processes.sort(
            key=lambda process: process["suspicion_score"],
            reverse=True
        )


        return {
            "total_suspicious_processes": len(
                suspicious_processes
            ),
            "suspicious_processes": suspicious_processes
        }


# Create monitor instance
process_monitor = ProcessMonitor()