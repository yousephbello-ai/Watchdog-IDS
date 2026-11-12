import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

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

    def test_outside_path_is_ignored(self):
        outside = Path(self.temp_dir.name).parent / "outside-watchdog-test.txt"
        try:
            outside.write_text("not watched", encoding="utf-8")
            self.monitor._handle_file_event("created", str(outside))
            self.alerter.trigger.assert_not_called()
        finally:
            outside.unlink(missing_ok=True)

    def test_symlink_is_not_followed(self):
        outside = self.root.parent / "outside-watchdog-target.txt"
        outside.write_text("target", encoding="utf-8")
        link = self.root / "link.txt"
        try:
            link.symlink_to(outside)
            self.monitor._handle_file_event("created", str(link))
            self.alerter.trigger.assert_not_called()
        finally:
            link.unlink(missing_ok=True)
            outside.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
