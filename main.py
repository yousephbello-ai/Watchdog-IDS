import argparse
import os
import time
from pathlib import Path

from src.alerter import AlertManager
from src.fim import FileIntegrityMonitor


def parse_args():
    parser = argparse.ArgumentParser(description="Watch a directory for file integrity changes.")
    parser.add_argument(
        "--watch",
        default=os.getenv("WATCHDOG_DIRECTORY", "secure_folder"),
        help="Directory to monitor (default: WATCHDOG_DIRECTORY or secure_folder).",
    )
    parser.add_argument(
        "--log",
        default=os.getenv("WATCHDOG_LOG", "logs/alerts.jsonl"),
        help="JSONL alert log path (default: WATCHDOG_LOG or logs/alerts.jsonl).",
    )
    parser.add_argument(
        "--webhook-env",
        default="WATCHDOG_WEBHOOK_URL",
        help="Environment variable containing an optional Discord-compatible webhook URL.",
    )
    parser.add_argument("--non-recursive", action="store_true", help="Monitor only the selected directory.")
    return parser.parse_args()


def main():
    args = parse_args()
    watch_directory = Path(args.watch).expanduser().resolve()
    log_path = Path(args.log).expanduser()
    webhook_url = os.getenv(args.webhook_env)

    print("==================================================")
    print("       Initializing Watchdog IDS Engine...         ")
    print("==================================================")
    print(f"[*] Monitoring: {watch_directory}")

    alerter = AlertManager(log_file=log_path, webhook_url=webhook_url)
    monitor = FileIntegrityMonitor(
        directory_to_watch=watch_directory,
        alerter=alerter,
        recursive=not args.non_recursive,
    )

    try:
        monitor.start()
        print("[*] IDS is running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping IDS observer...")
    finally:
        monitor.stop()
        print("[*] Watchdog IDS shut down safely.")


if __name__ == "__main__":
    main()
