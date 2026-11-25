import hashlib
import json
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
        snapshot = {}
        root = Path(directory).resolve()
        if not root.exists():
            return snapshot
        for path in sorted(root.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                # Resolve both sides before relativizing. This is important on
                # Windows, where path casing and junction resolution can differ.
                rel = path.resolve().relative_to(root).as_posix()
            except (OSError, ValueError):
                continue
            try:
                snapshot[rel] = self._hash_file(path)
            except OSError:
                continue
        return snapshot

    def save(self, directory: Path) -> dict:
        snapshot = self.capture(directory)
        from datetime import datetime, timezone
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
        changed = []
        for rel in sorted(set(current) & set(baseline)):
            if current[rel] != baseline[rel]:
                changed.append(rel)
        return {
            "added": added,
            "removed": removed,
            "changed": changed,
            "current": current,
            "baseline": baseline,
        }
