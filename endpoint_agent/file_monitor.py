import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FileEventHandler(FileSystemEventHandler):

    def __init__(self):
        super().__init__()
        self.file_events = []

    def on_created(self, event):
        if not event.is_directory:
            self.file_events.append({
                "event_type": "CREATED",
                "file_path": event.src_path,
                "timestamp": datetime.now().isoformat()
            })

    def on_modified(self, event):
        if not event.is_directory:
            self.file_events.append({
                "event_type": "MODIFIED",
                "file_path": event.src_path,
                "timestamp": datetime.now().isoformat()
            })

    def on_deleted(self, event):
        if not event.is_directory:
            self.file_events.append({
                "event_type": "DELETED",
                "file_path": event.src_path,
                "timestamp": datetime.now().isoformat()
            })


class FileMonitor:

    def __init__(self, watch_path="."):
        self.watch_path = watch_path
        self.event_handler = FileEventHandler()
        self.observer = Observer()

    def start_monitoring(self):
        """
        Start monitoring file system changes.
        """

        self.observer.schedule(
            self.event_handler,
            self.watch_path,
            recursive=True
        )

        self.observer.start()

        print(
            f"File monitoring started: {self.watch_path}"
        )

    def stop_monitoring(self):
        """
        Stop file monitoring.
        """

        self.observer.stop()
        self.observer.join()

    def get_file_events(self):
        """
        Return collected file events.
        """

        return self.event_handler.file_events
    def analyze_suspicious_file_events(self):

        suspicious_events = []

        suspicious_extensions = [
            ".exe",
            ".bat",
            ".cmd",
            ".ps1",
            ".vbs",
            ".js",
            ".scr"
        ]

        file_events = self.get_file_events()

        for event in file_events:

            file_path = event["file_path"].lower()

            suspicion_score = 0
            reasons = []

            # Suspicious executable or script file
            if any(
                file_path.endswith(extension)
                for extension in suspicious_extensions
            ):
                suspicion_score += 0.4
                reasons.append(
                    "Executable or script file activity detected"
                )

            # File deletion can contribute slightly
            if event["event_type"] == "DELETED":
                suspicion_score += 0.1
                reasons.append(
                    "File deletion activity detected"
                )

            if suspicion_score > 0:
                suspicious_events.append({
                    "event_type": event["event_type"],
                    "file_path": event["file_path"],
                    "timestamp": event["timestamp"],
                    "suspicion_score": round(
                        min(suspicion_score, 1.0), 2
                    ),
                    "reasons": reasons
                })

        return {
            "total_suspicious_file_events": len(
                suspicious_events
            ),
            "suspicious_file_events": suspicious_events
        }


file_monitor = FileMonitor()