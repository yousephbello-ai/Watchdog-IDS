import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


class BaselineManager:
    """Store and compare a known-good file snapshot for a watched directory."""

    def __init__(self, baseline_path):
        self.baseline_path = Path(baseline_path)
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)

    def _hash_file(self, path: Path) -> dict:
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
                size += len(chunk)
        stat = path.stat()
        return {"sha256": digest.hexdigest(), "size": size, "mtime_ns": stat.st_mtime_ns}

    def capture(self, directory: Path) -> dict:
        root = Path(directory).absolute()
        snapshot = {}
        if not root.exists():
            return snapshot

        try:
            baseline_abs = self.baseline_path.absolute()
            baseline_rel = os.path.relpath(str(baseline_abs), str(root))
        except (OSError, ValueError):
            baseline_rel = None

        for path in sorted(root.rglob("*")):
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                # relpath uses the host platform's path rules (including
                # Windows drive letters and case-insensitive comparisons).
                rel = os.path.relpath(str(path.absolute()), str(root))
                if rel == "." or rel.startswith(".." + os.sep):
                    continue
                rel = Path(rel).as_posix()
                if baseline_rel is not None and os.path.normcase(rel) == os.path.normcase(
                    Path(baseline_rel).as_posix()
                ):
                    continue
                snapshot[rel] = self._hash_file(path)
            except (OSError, ValueError):
                # A file may disappear or become inaccessible during a scan.
                continue
        return snapshot

    def save(self, directory: Path) -> dict:
        snapshot = self.capture(directory)
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "files": snapshot,
        }
        self.baseline_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )
        return snapshot

    def load(self) -> dict:
        if not self.baseline_path.exists():
            return {}
        try:
            return json.loads(
                self.baseline_path.read_text(encoding="utf-8")
            ).get("files", {})
        except (OSError, ValueError):
            return {}

    def compare(self, directory: Path):
        current = self.capture(directory)
        baseline = self.load()
        added = sorted(set(current) - set(baseline))
        removed = sorted(set(baseline) - set(current))
        changed = [
            rel for rel in sorted(set(current) & set(baseline))
            if current[rel] != baseline[rel]
        ]
        return {
            "added": added,
            "removed": removed,
            "changed": changed,
            "current": current,
            "baseline": baseline,
        }
