import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from src.baseline import BaselineManager
from src.fim import FileIntegrityMonitor


class FileIntegrityMonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.alerter = Mock()
        self.monitor = FileIntegrityMonitor(self.root, self.alerter)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_new_file_raises_created_alert_once(self):
        path = self.root / "new.txt"
        path.write_text("hello", encoding="utf-8")

        self.monitor._handle_file_event("created", str(path))
        self.monitor._handle_file_event("modified", str(path))

        self.alerter.trigger.assert_called_once()
        args = self.alerter.trigger.call_args.kwargs
        self.assertEqual(args["title"], "File Created")
        self.assertEqual(args["details"]["path"], "new.txt")

    def test_changed_hash_raises_modified_alert(self):
        path = self.root / "tracked.txt"
        path.write_text("before", encoding="utf-8")
        self.monitor._snapshot = self.monitor._capture_snapshot()
        path.write_text("after", encoding="utf-8")

        self.monitor._handle_file_event("modified", str(path))

        args = self.alerter.trigger.call_args.kwargs
        self.assertEqual(args["title"], "File Modified")
        self.assertNotEqual(
            args["details"]["previous_state"]["sha256"],
            args["details"]["current_state"]["sha256"],
        )

    def test_delete_raises_alert_and_removes_snapshot_entry(self):
        path = self.root / "tracked.txt"
        path.write_text("contents", encoding="utf-8")
        self.monitor._snapshot = self.monitor._capture_snapshot()
        path.unlink()

        self.monitor._handle_file_event("deleted", str(path))

        self.assertNotIn("tracked.txt", self.monitor._snapshot)
        self.assertEqual(self.alerter.trigger.call_args.kwargs["title"], "File Deleted")

    def test_suspicious_extension_raises_critical_alert(self):
        path = self.root / "payload.ps1"
        path.write_text("Write-Host 'pwned'", encoding="utf-8")
        self.monitor._handle_file_event("created", str(path))

        args = self.alerter.trigger.call_args.kwargs
        self.assertEqual(args["severity"], "CRITICAL")
        self.assertEqual(args["title"], "Suspicious File Created")

    def test_baseline_manager_captures_and_compares_snapshot(self):
        baseline_path = self.root / "baseline.json"
        baseline = BaselineManager(baseline_path)
        test_file = self.root / "safe.txt"
        test_file.write_text("sandbox", encoding="utf-8")

        saved = baseline.save(self.root)
        test_file.write_text("new data", encoding="utf-8")
        diff = baseline.compare(self.root)

        self.assertIn("safe.txt", saved)
        self.assertIn("safe.txt", diff["changed"])


if __name__ == "__main__":
    unittest.main()
