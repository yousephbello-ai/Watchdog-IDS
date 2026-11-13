import hashlib
import shutil
import threading
import time
from collections import deque
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

try:
    from .baseline import BaselineManager
except ImportError:  # Allows source-tree execution.
    from baseline import BaselineManager


class FileIntegrityMonitor:
    """Watch a directory and alert on file changes and suspicious activity."""

    DEFAULT_DANGEROUS_EXTENSIONS = {
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".com",
        ".js",
        ".vbs",
        ".ps1",
        ".scr",
        ".hta",
        ".lnk",
        ".jar",
    }

    def __init__(
        self,
        directory_to_watch,
        alerter,
        recursive=True,
        baseline_path=None,
        quarantine_path=None,
        suspicious_extensions=None,
        suspicious_file_action="alert",
        burst_threshold=20,
        burst_window_seconds=5.0,
        file_count_delta_threshold=10,
        extension_churn_threshold=5,
        rules=None,
    ):
        self.directory = Path(directory_to_watch).expanduser().resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        if not self.directory.is_dir():
            raise NotADirectoryError(self.directory)

        self.alerter = alerter
        self.recursive = bool(recursive)
        self.baseline_path = Path(baseline_path).expanduser().resolve() if baseline_path else None
        self.baseline_manager = BaselineManager(self.baseline_path) if self.baseline_path else None
        self.quarantine_path = Path(quarantine_path).expanduser().resolve() if quarantine_path else None
        self.suspicious_extensions = {
            str(ext).lower() if str(ext).startswith(".") else f".{str(ext).lower()}"
            for ext in (suspicious_extensions or set())
        } | self.DEFAULT_DANGEROUS_EXTENSIONS
        if suspicious_file_action not in {"alert", "quarantine"}:
            raise ValueError("suspicious_file_action must be 'alert' or 'quarantine'")
        self.suspicious_file_action = suspicious_file_action
        self.burst_threshold = max(1, int(burst_threshold))
        self.burst_window_seconds = max(0.1, float(burst_window_seconds))
        self.file_count_delta_threshold = max(1, int(file_count_delta_threshold))
        self.extension_churn_threshold = max(1, int(extension_churn_threshold))
        self.rules = rules or []

        self._observer = None
        self._lock = threading.RLock()
        self._events = deque()
        self._snapshot = self._capture_snapshot()
        self._event_handler = _IntegrityEventHandler(self)

    @staticmethod
    def _hash_file(path):
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
                size += len(chunk)
        stat = path.stat()
        return {"sha256": digest.hexdigest(), "size": size, "mtime_ns": stat.st_mtime_ns}

    def _relative_path(self, path):
        try:
            return Path(path).resolve().relative_to(self.directory).as_posix()
        except (OSError, ValueError):
            return None

    def _capture_snapshot(self):
        snapshot = {}
        for path in sorted(self.directory.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            relative = self._relative_path(path)
            if relative:
                try:
                    snapshot[relative] = self._hash_file(path)
                except OSError:
                    continue
        return snapshot

    def _alert(self, severity, title, details, key):
        self.alerter.trigger(module="FIM", severity=severity, title=title, details=details, dedup_key=key)

    def _quarantine(self, source, relative):
        if self.quarantine_path is None:
            raise ValueError("Quarantine action requires quarantine_path")
        if self.quarantine_path == self.directory or self.directory in self.quarantine_path.parents:
            raise ValueError("Quarantine path must be outside the monitored directory")
        self.quarantine_path.mkdir(parents=True, exist_ok=True)
        destination = self.quarantine_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            destination = destination.with_name(f"{destination.name}.{time.time_ns()}")
        shutil.move(str(source), str(destination))
        return str(destination)

    def _track_activity(self, action, relative):
        now = time.monotonic()
        extension = Path(relative).suffix.lower() or "[no extension]"
        self._events.append((now, action, relative, extension))
        cutoff = now - self.burst_window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

        changes = list(self._events)
        if len(changes) >= self.burst_threshold:
            self._alert(
                "CRITICAL",
                "Burst Activity Detected",
                {
                    "window_seconds": self.burst_window_seconds,
                    "event_count": len(changes),
                    "sample_paths": sorted({item[2] for item in changes})[:20],
                },
                "fim:burst",
            )
            self._events.clear()
            return

        net_count = sum(
            1 if item[1] == "created" else -1 if item[1] == "deleted" else 0 for item in changes
        )
        if abs(net_count) >= self.file_count_delta_threshold:
            self._alert(
                "HIGH",
                "Unusual File Count Change",
                {
                    "window_seconds": self.burst_window_seconds,
                    "net_file_count_change": net_count,
                },
                "fim:file-count-churn",
            )

        extensions = {item[3] for item in changes}
        if len(extensions) >= self.extension_churn_threshold:
            self._alert(
                "HIGH",
                "Extension Churn Detected",
                {
                    "window_seconds": self.burst_window_seconds,
                    "extensions": sorted(extensions),
                },
                "fim:extension-churn",
            )

    def _handle_file_event(self, event_type, raw_path):
        path = Path(raw_path)
        if path.is_symlink() or path.is_dir():
            return
        relative = self._relative_path(path)
        if relative is None:
            return

        with self._lock:
            previous = self._snapshot.get(relative)
            if event_type == "deleted" or not path.exists():
                if previous is not None:
                    self._snapshot.pop(relative, None)
                    self._alert(
                        "HIGH",
                        "File Deleted",
                        {"path": relative, "previous_state": previous},
                        f"fim:deleted:{relative}",
                    )
                    self._track_activity("deleted", relative)
                return

            try:
                current = self._hash_file(path)
            except OSError:
                return
            if previous == current:
                return

            action = "created" if previous is None else "modified"
            self._snapshot[relative] = current
            suspicious = path.suffix.lower() in self.suspicious_extensions
            details = {"path": relative, "current_state": current}
            if previous is not None:
                details["previous_state"] = previous

            if suspicious:
                details["rule"] = "suspicious_extension"
                if self.suspicious_file_action == "quarantine":
                    try:
                        details["quarantined_to"] = self._quarantine(path, relative)
                        self._snapshot.pop(relative, None)
                    except (OSError, ValueError) as exc:
                        details["quarantine_error"] = str(exc)
                self._alert(
                    "CRITICAL",
                    f"Suspicious File {action.title()}",
                    details,
                    f"fim:suspicious:{relative}",
                )
            else:
                self._alert("HIGH", f"File {action.title()}", details, f"fim:{action}:{relative}")
            self._track_activity(action, relative)

    def _check_startup_health(self):
        for label, path in (("baseline", self.baseline_path), ("quarantine", self.quarantine_path)):
            if path and (path == self.directory or self.directory in path.parents):
                raise ValueError(f"{label} path must be outside watched directory: {path}")
        if self.baseline_manager and self.baseline_path.exists():
            if self.baseline_path.is_dir():
                raise IsADirectoryError(self.baseline_path)
            self.baseline_manager.load()
        self._alert("LOW", "Health Check Passed", {"directory": str(self.directory)}, "fim:health")

    def _check_baseline(self):
        result = self.baseline_manager.compare(self.directory)
        for rel in result["added"]:
            self._alert("HIGH", "Baseline Drift: File Added", {"path": rel}, f"fim:baseline-added:{rel}")
        for rel in result["removed"]:
            self._alert("HIGH", "Baseline Drift: File Removed", {"path": rel}, f"fim:baseline-removed:{rel}")
        for rel in result["changed"]:
            self._alert("HIGH", "Baseline Drift: File Changed", {"path": rel}, f"fim:baseline-changed:{rel}")

    def start(self):
        if self._observer is not None:
            raise RuntimeError("FileIntegrityMonitor is already running")
        self._check_startup_health()
        if self.baseline_manager:
            if self.baseline_path.exists():
                self._check_baseline()
            else:
                self.baseline_manager.save(self.directory)
                self._alert("LOW", "Baseline Created", {"baseline": str(self.baseline_path)}, "fim:baseline-created")

        observer = Observer()
        observer.schedule(self._event_handler, str(self.directory), recursive=self.recursive)
        observer.start()
        self._observer = observer
        self._alert(
            "LOW",
            "Monitoring Started",
            {"directory": str(self.directory), "tracked_files": len(self._snapshot)},
            "fim:start",
        )
        return observer

    def stop(self):
        observer = self._observer
        if observer is not None:
            observer.stop()
            observer.join()
            self._observer = None


class _IntegrityEventHandler(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor

    def on_created(self, event):
        if not event.is_directory:
            self.monitor._handle_file_event("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.monitor._handle_file_event("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.monitor._handle_file_event("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.monitor._handle_file_event("deleted", event.src_path)
            self.monitor._handle_file_event("created", event.dest_path)
