import psutil
import os
from datetime import datetime


class ResponseEngine:

    PROTECTED_PROCESSES = [
        "system",
        "system idle process",
        "explorer.exe",
        "wininit.exe",
        "winlogon.exe",
        "csrss.exe",
        "services.exe",
        "lsass.exe"
    ]


    def __init__(self):

        # Protect the Endpoint Agent itself
        self.protected_pids = [
            os.getpid()
        ]


    def terminate_process(self, pid, process_name):

        process_name = process_name.lower()

        # Protect the Endpoint Agent PID
        if pid in self.protected_pids:
            return {
                "action": "PROCESS_PROTECTED",
                "pid": pid,
                "process": process_name,
                "message": "Endpoint Agent process cannot be terminated"
            }

        # Protect critical Windows processes
        if process_name in self.PROTECTED_PROCESSES:
            return {
                "action": "PROCESS_PROTECTED",
                "pid": pid,
                "process": process_name,
                "message": "Critical system process cannot be terminated"
            }

        try:
            process = psutil.Process(pid)

            # Extra safety: verify process still exists
            if not process.is_running():
                return {
                    "action": "PROCESS_NOT_RUNNING",
                    "pid": pid,
                    "process": process_name,
                    "message": "Process is no longer running"
                }

            process.terminate()

            try:
                process.wait(timeout=3)

                return {
                    "action": "PROCESS_TERMINATED",
                    "pid": pid,
                    "process": process_name,
                    "message": f"Successfully terminated {process_name}"
                }

            except psutil.TimeoutExpired:

                process.kill()

                return {
                    "action": "PROCESS_KILLED",
                    "pid": pid,
                    "process": process_name,
                    "message": f"Force killed {process_name}"
                }

        except psutil.NoSuchProcess:
            return {
                "action": "PROCESS_NOT_FOUND",
                "pid": pid,
                "process": process_name,
                "message": "Process no longer exists"
            }

        except psutil.AccessDenied:
            return {
                "action": "ACCESS_DENIED",
                "pid": pid,
                "process": process_name,
                "message": "Permission denied while terminating process"
            }

        except Exception as e:
            return {
                "action": "RESPONSE_ERROR",
                "pid": pid,
                "process": process_name,
                "message": str(e)
            }


    def execute_response(self, analysis):

        response_decision = analysis.get(
            "response_decision",
            {}
        )

        severity = response_decision.get(
            "response_priority",
            "LOW"
        )

        risk_score = analysis.get(
            "risk_score",
            0
        )

        actions = []
                # Get explicit response command from backend
        response_command = response_decision.get(
            "response_command"
        )

        # Execute backend-authorized process termination
        if (
            response_command
            and response_command.get("action") == "TERMINATE_PROCESS"
        ):

            target_pid = response_command.get("target_pid")
            target_process = response_command.get(
                "target_process"
            )

            # Validate target against suspicious processes
            suspicious_processes = analysis.get(
                "risk_contributors",
                {}
            ).get(
                "suspicious_processes",
                []
            )

            validated_target = False

            for process in suspicious_processes:

                if (
                    process.get("pid") == target_pid
                    and process.get(
                        "controlled_critical_test",
                        False
                    )
                ):
                    validated_target = True
                    break

            if validated_target and target_pid and target_process:

                result = self.terminate_process(
                    target_pid,
                    target_process
                )

                actions.append(result)

            else:

                actions.append({
                    "action": "TERMINATION_BLOCKED",
                    "message": (
                        "Backend termination command received, "
                        "but target process failed validation."
                    )
                })

            return {
                "timestamp": datetime.now().isoformat(),
                "severity": severity,
                "risk_score": risk_score,
                "actions_taken": actions
            }


        # LOW
        if severity == "LOW":

            actions.append({
                "action": "MONITORING_ONLY",
                "message": "Low risk detected. Continuing monitoring."
            })


        # MEDIUM
        elif severity == "MEDIUM":

            actions.append({
                "action": "INVESTIGATION_REQUIRED",
                "message": "Medium risk detected. Flagged for investigation."
            })


        # HIGH
        elif severity == "HIGH":

            actions.append({
                "action": "HIGH_RISK_ALERT",
                "message": (
                    "High-confidence threat detected. "
                    "Process flagged for investigation and monitoring."
                )
            })


        # CRITICAL
        elif severity == "CRITICAL":

            suspicious_processes = analysis.get(
                "risk_contributors",
                {}
            ).get(
                "suspicious_processes",
                []
            )

            for suspicious_process in suspicious_processes:

                # Only terminate the controlled critical test
                if not suspicious_process.get(
                    "controlled_critical_test",
                    False
                ):
                    continue

                pid = suspicious_process.get("pid")
                name = suspicious_process.get("name")

                if pid and name:

                    result = self.terminate_process(
                        pid,
                        name
                    )

                    actions.append(result)

            if not actions:

                actions.append({
                    "action": "CRITICAL_INCIDENT_ALERT",
                    "message": (
                        "Critical threat detected, but no "
                        "validated process was available for termination."
                    )
                })


                if not suspicious_processes:

                    actions.append({
                        "action": "ESCALATE_INCIDENT",
                        "message": (
                            "Critical threat detected but no specific "
                            "process was identified."
                        )
                    })


        return {
            "timestamp": datetime.now().isoformat(),
            "severity": severity,
            "risk_score": risk_score,
            "actions_taken": actions
        }