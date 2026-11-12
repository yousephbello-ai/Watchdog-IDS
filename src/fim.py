import hashlib
import threading
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from src.baseline import BaselineManager


class FileIntegrityMonitor:
    """Watch a directory and alert when files are created, changed, or removed."""

    DANGEROUS_EXTENSIONS = {
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

    def __init__(self, directory_to_watch, alerter, recursive=True, baseline_path=None):
        self.directory = Path(directory_to_watch).expanduser().resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.alerter = alerter
        self.recursive = recursive
        self._observer = None
        self._lock = threading.RLock()
        self._snapshot = self._capture_snapshot()
        self._event_handler = _IntegrityEventHandler(self)
        self.baseline_path = Path(baseline_path).expanduser().resolve() if baseline_path else None
        self.baseline_manager = BaselineManager(self.baseline_path) if self.baseline_path else None

    @staticmethod
    def _hash_file(path: Path) -> dict:
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
                size += len(chunk)
        stat = path.stat()
        return {"sha256": digest.hexdigest(), "size": size, "mtime_ns": stat.st_mtime_ns}

    def _relative_path(self, path: Path):
        try:
            return path.resolve().relative_to(self.directory).as_posix()
        except (OSError, ValueError):
            return None

    def _capture_snapshot(self) -> dict:
        snapshot = {}
        for path in sorted(self.directory.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            relative = self._relative_path(path)
            if relative is None:
                continue
            try:
                snapshot[relative] = self._hash_file(path)
            except OSError:
                continue
        return snapshot

    def _is_dangerous_file(self, relative_path: str) -> bool:
        suffix = Path(relative_path).suffix.lower()
        return suffix in self.DANGEROUS_EXTENSIONS

    def _record_change(self, event_type: str, relative: str, details: dict):
        severity = "CRITICAL" if self._is_dangerous_file(relative) else "HIGH"
        title = f"Suspicious File {event_type.title()}" if self._is_dangerous_file(relative) else f"File {event_type.title()}"
        self.alerter.trigger(
            module="FIM",
            severity=severity,
            title=title,
            details={"path": relative, **details},
            dedup_key=f"fim:{event_type}:{relative}",
        )

    def _handle_file_event(self, event_type: str, raw_path: str):
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
                    self._record_change("deleted", relative, {"previous_state": previous})
                return

            try:
                current = self._hash_file(path)
            except OSError:
                return

            if previous is None:
                self._snapshot[relative] = current
                self._record_change("created", relative, {"current_state": current})
            elif previous != current:
                self._snapshot[relative] = current
                self._record_change(
                    "modified",
                    relative,
                    {"previous_state": previous, "current_state": current},
                )

    def _check_baseline(self):
        if not self.baseline_manager:
            return
        result = self.baseline_manager.compare(self.directory)
        if result["added"] or result["removed"] or result["changed"]:
            for rel in result["added"]:
                self.alerter.trigger(
                    module="FIM",
                    severity="HIGH",
                    title="Baseline Drift: File Added",
                    details={"path": rel, "current_state": result["current"].get(rel)},
                    dedup_key=f"fim:baseline-added:{rel}",
                )
            for rel in result["removed"]:
                self.alerter.trigger(
                    module="FIM",
                    severity="HIGH",
                    title="Baseline Drift: File Removed",
                    details={"path": rel, "previous_state": result["baseline"].get(rel)},
                    dedup_key=f"fim:baseline-removed:{rel}",
                )
            for rel in result["changed"]:
                self.alerter.trigger(
                    module="FIM",
                    severity="HIGH",
                    title="Baseline Drift: File Changed",
                    details={
                        "path": rel,
                        "previous_state": result["baseline"].get(rel),
                        "current_state": result["current"].get(rel),
                    },
                    dedup_key=f"fim:baseline-changed:{rel}",
                )
        else:
            self.alerter.trigger(
                module="FIM",
                severity="LOW",
                title="Baseline Matched",
                details={"baseline": str(self.baseline_path), "tracked_files": len(result["current"])},
                dedup_key="fim:baseline-match",
            )

    def start(self):
        if self._observer is not None:
            raise RuntimeError("FileIntegrityMonitor is already running")

        if self.baseline_manager and not self.baseline_path.exists():
            self.baseline_manager.save(self.directory)
            self.alerter.trigger(
                module="FIM",
                severity="LOW",
                title="Baseline Created",
                details={"baseline": str(self.baseline_path), "tracked_files": len(self._snapshot)},
                dedup_key="fim:baseline-create",
            )
        elif self.baseline_manager:
            self._check_baseline()

        observer = Observer()
        observer.schedule(self._event_handler, str(self.directory), recursive=self.recursive)
        observer.start()
        self._observer = observer
        self.alerter.trigger(
            module="FIM",
            severity="LOW",
            title="Monitoring Started",
            details={"directory": str(self.directory), "tracked_files": len(self._snapshot)},
            dedup_key="fim:start",
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
