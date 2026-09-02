import psutil
from datetime import datetime


class SystemMonitor:

    def get_system_metrics(self):
        """
        Collect current system resource metrics.
        """

        cpu_usage = psutil.cpu_percent(interval=1)

        memory = psutil.virtual_memory()

        disk = psutil.disk_usage("C:\\")

        boot_time = datetime.fromtimestamp(
            psutil.boot_time()
        )

        current_time = datetime.now()

        uptime = current_time - boot_time

        return {
            "timestamp": current_time.isoformat(),
            "cpu_usage_percent": cpu_usage,
            "memory": {
                "total_gb": round(
                    memory.total / (1024 ** 3), 2
                ),
                "used_gb": round(
                    memory.used / (1024 ** 3), 2
                ),
                "usage_percent": memory.percent
            },
            "disk": {
                "total_gb": round(
                    disk.total / (1024 ** 3), 2
                ),
                "used_gb": round(
                    disk.used / (1024 ** 3), 2
                ),
                "usage_percent": disk.percent
            },
            "system_uptime": str(uptime).split(".")[0],
            "running_processes": len(
                psutil.pids()
            )
        }
    def detect_system_anomalies(self):
       

        metrics = self.get_system_metrics()

        anomaly_score = 0
        anomaly_reasons = []

        cpu_usage = metrics["cpu_usage_percent"]
        memory_usage = metrics["memory"]["usage_percent"]
        disk_usage = metrics["disk"]["usage_percent"]

        # High CPU usage
        if cpu_usage >= 85:
            anomaly_score += 0.4
            anomaly_reasons.append(
                f"High CPU usage detected: {cpu_usage}%"
            )

        # High memory usage
        if memory_usage >= 90:
            anomaly_score += 0.3
            anomaly_reasons.append(
                f"High memory usage detected: {memory_usage}%"
            )

        # High disk usage
        if disk_usage >= 95:
            anomaly_score += 0.3
            anomaly_reasons.append(
                f"Critical disk usage detected: {disk_usage}%"
            )

        anomaly_detected = anomaly_score > 0

        return {
            "system_metrics": metrics,
            "anomaly_detected": anomaly_detected,
            "anomaly_score": round(
                min(anomaly_score, 1.0), 2
            ),
            "anomaly_reasons": anomaly_reasons
        }


# Singleton instance
system_monitor = SystemMonitor()