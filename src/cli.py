import argparse
import json
import os
from pathlib import Path

from src.alerter import AlertManager
from src.fim import FileIntegrityMonitor


DEFAULT_CONFIG = {
    "watch_directory": "secure_folder",
    "log_path": "logs/alerts.jsonl",
    "baseline_path": "state/baseline.json",
    "quarantine_path": "state/quarantine",
    "recursive": True,
    "log_max_bytes": 5_000_000,
    "log_backup_count": 5,
    "burst_threshold": 20,
    "burst_window_seconds": 5.0,
    "file_count_delta_threshold": 10,
    "extension_churn_threshold": 5,
    "suspicious_extensions": [
        ".exe", ".dll", ".bat", ".cmd", ".com", ".js", ".vbs", ".ps1", ".scr",
        ".hta", ".lnk", ".jar",
    ],
    "suspicious_file_action": "alert",
    "rules": [],
}


def load_config(path):
    config_path = Path(path).expanduser().resolve()
    if not config_path.exists():
        if path != "config/watchdog_config.json":
            raise FileNotFoundError(f"Config file not found: {config_path}")
        return dict(DEFAULT_CONFIG)

    text = config_path.read_text(encoding="utf-8")
    if config_path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("YAML config requires PyYAML; install with `pip install watchdog-ids[yaml]`") from exc
        loaded = yaml.safe_load(text)
    else:
        loaded = json.loads(text)

    if not isinstance(loaded, dict):
        raise ValueError("Config must contain a JSON/YAML object")

    return {**DEFAULT_CONFIG, **loaded}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Defensive file-integrity monitoring for authorized systems."
    )
    parser.add_argument("--config", default=os.getenv("WATCHDOG_CONFIG", "config/watchdog_config.json"))
    parser.add_argument("--watch")
    parser.add_argument("--log")
    parser.add_argument("--baseline")
    parser.add_argument("--webhook-env", default="WATCHDOG_WEBHOOK_URL")
    parser.add_argument("--non-recursive", action="store_true")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    config = load_config(args.config)

    watch = Path(args.watch or config["watch_directory"]).expanduser().resolve()
    log_path = Path(args.log or config["log_path"]).expanduser().resolve()
    baseline = Path(args.baseline or config["baseline_path"]).expanduser().resolve()
    quarantine = Path(config["quarantine_path"]).expanduser().resolve()
    webhook = os.getenv(args.webhook_env)

    alerter = AlertManager(
        log_file=log_path,
        webhook_url=webhook,
        max_bytes=int(config["log_max_bytes"]),
        backup_count=int(config["log_backup_count"]),
    )

    monitor = FileIntegrityMonitor(
        directory_to_watch=watch,
        alerter=alerter,
        recursive=bool(config["recursive"]) and not args.non_recursive,
        baseline_path=baseline,
        quarantine_path=quarantine,
        suspicious_extensions=set(config["suspicious_extensions"]),
        suspicious_file_action=config["suspicious_file_action"],
        burst_threshold=int(config["burst_threshold"]),
        burst_window_seconds=float(config["burst_window_seconds"]),
        file_count_delta_threshold=int(config["file_count_delta_threshold"]),
        extension_churn_threshold=int(config["extension_churn_threshold"]),
        rules=config["rules"],
    )

    try:
        monitor.start()
        print(f"Watchdog IDS monitoring {watch}; Ctrl+C to stop.")
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Watchdog IDS...")
    finally:
        monitor.stop()
        if hasattr(alerter, "close"):
            alerter.close()
