import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from src.cli import DEFAULT_CONFIG, load_config
from src.fim import FileIntegrityMonitor


class RepositorySmokeTests(unittest.TestCase):
    def test_checked_in_config_is_valid_json_and_has_required_paths(self):
        config_path = Path(__file__).parents[1] / "config" / "watchdog_config.json"
        config = load_config(config_path)
        self.assertEqual(config["watch_directory"], "secure_folder")
        self.assertTrue(config["log_path"])
        self.assertTrue(config["baseline_path"])

    def test_cli_defaults_match_config(self):
        self.assertEqual(DEFAULT_CONFIG["watch_directory"], "secure_folder")
        self.assertEqual(DEFAULT_CONFIG["suspicious_file_action"], "alert")

    def test_suspicious_extension_alert_title_is_action_specific(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            alerter = Mock()
            monitor = FileIntegrityMonitor(root, alerter)
            file_path = root / "sample.ps1"
            file_path.write_text("test", encoding="utf-8")
            monitor._handle_file_event("created", str(file_path))
            self.assertEqual(
                alerter.trigger.call_args.kwargs["title"],
                "Suspicious File Created",
            )

    def test_unknown_paths_are_ignored(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "watch"
            root.mkdir()
            alerter = Mock()
            monitor = FileIntegrityMonitor(root, alerter)
            monitor._handle_file_event("created", str(Path(temp_dir) / "outside.txt"))
            alerter.trigger.assert_not_called()


if __name__ == "__main__":
    unittest.main()
