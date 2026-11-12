import argparse
import json
import os
import time
from pathlib import Path

from src.alerter import AlertManager
from src.fim import FileIntegrityMonitor


DEFAULT_CONFIG = {
    "watch_directory": "secure_folder",
    "log_path": "logs/alerts.jsonl",
    "baseline_path": "logs/baseline.json",
    "recursive": True,
    "burst_threshold": 20,
    "burst_window_seconds": 5.0,
    "suspicious_extensions": [
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
    ],
}


def load_config(path=None):
    config_path = Path(path or os.getenv("WATCHDOG_CONFIG", "config/watchdog_config.json")).expanduser()
    config = dict(DEFAULT_CONFIG)
    if config_path.exists():
        try:
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                config.update(loaded)
        except (OSError, ValueError):
            print(f"[!] Could not read config at {config_path}; using defaults.", flush=True)
    return config


def parse_args():
    parser = argparse.ArgumentParser(description="Watch a directory for file integrity changes.")
    parser.add_argument("--config", default=os.getenv("WATCHDOG_CONFIG"), help="Path to a JSON config file.")
    parser.add_argument("--watch", default=None, help="Directory to monitor (overrides config).")
    parser.add_argument("--log", default=None, help="Alert log path (overrides config).")
    parser.add_argument("--baseline", default=None, help="Baseline snapshot path (overrides config).")
    parser.add_argument("--webhook-env", default="WATCHDOG_WEBHOOK_URL", help="Environment variable containing the optional webhook URL.")
    parser.add_argument("--non-recursive", action="store_true", help="Monitor only the selected directory.")
    return parser.parse_args()


def main():
    args = parse_args()
    config = load_config(args.config)

    watch_directory = Path(args.watch or config["watch_directory"]).expanduser().resolve()
    log_path = Path(args.log or config["log_path"]).expanduser()
    baseline_path = Path(args.baseline or config["baseline_path"]).expanduser()
    webhook_url = os.getenv(args.webhook_env)
    recursive = config.get("recursive", True) and not args.non_recursive

    print("==================================================")
    print("       Initializing Watchdog IDS Engine...         ")
    print("==================================================")
    print(f"[*] Monitoring: {watch_directory}")
    if config.get("baseline_path"):
        print(f"[*] Baseline: {baseline_path}")

    alerter = AlertManager(log_file=log_path, webhook_url=webhook_url)
    monitor = FileIntegrityMonitor(
        directory_to_watch=watch_directory,
        alerter=alerter,
        recursive=recursive,
        baseline_path=baseline_path,
        suspicious_extensions=set(config.get("suspicious_extensions", DEFAULT_CONFIG["suspicious_extensions"])),
        burst_threshold=int(config.get("burst_threshold", DEFAULT_CONFIG["burst_threshold"])),
        burst_window_seconds=float(config.get("burst_window_seconds", DEFAULT_CONFIG["burst_window_seconds"])),
    )

    try:
        monitor.start()
        print("[*] IDS is running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS observer...")
    except Exception as exc:
        print(f"\n[!] Startup validation failed: {exc}")
        raise
    finally:
        monitor.stop()
        print("[*] Watchdog IDS shut down safely.")


if __name__ == "__main__":
    main()
