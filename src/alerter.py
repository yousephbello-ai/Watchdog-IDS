import json
import sys
import threading
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
import logging
from pathlib import Path

import requests
from colorama import Fore, Style, init

init(autoreset=True)


class _JsonFormatter(logging.Formatter):
    def format(self, record):
        return record.getMessage()


class AlertManager:
    """Write structured JSONL alerts, rotate logs, and optionally send webhooks."""

    VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def __init__(self, log_file="logs/alerts.jsonl", webhook_url=None, cooldown_seconds=10,
                 max_bytes=5_000_000, backup_count=5):
        if cooldown_seconds < 0 or max_bytes < 1 or backup_count < 0:
            raise ValueError("Invalid alert logging or cooldown configuration")
        self.log_path = Path(log_file)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.webhook_url = webhook_url
        self.cooldown = cooldown_seconds
        self._lock = threading.Lock()
        self._recent_alerts = {}
        self._logger = logging.getLogger(f"watchdog_ids.alerts.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._handler = RotatingFileHandler(self.log_path, maxBytes=max_bytes,
                                            backupCount=backup_count, encoding="utf-8")
        self._handler.setFormatter(_JsonFormatter())
        self._logger.addHandler(self._handler)

    def _is_rate_limited(self, key):
        now = time.monotonic()
        if now - self._recent_alerts.get(key, 0) < self.cooldown:
            return True
        self._recent_alerts[key] = now
        return False

    def trigger(self, module, severity, title, details, dedup_key=None):
        severity = severity.upper()
        if severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Unsupported alert severity: {severity}")
        payload = {"timestamp": datetime.now(timezone.utc).isoformat(), "module": module,
                   "severity": severity, "title": title, "details": details}
        with self._lock:
            if self._is_rate_limited(dedup_key or f"{module}:{title}"):
                return False
            self._logger.info(json.dumps(payload, ensure_ascii=False))
            self._print_console(payload)
        if self.webhook_url and severity in {"HIGH", "CRITICAL"}:
            threading.Thread(target=self._send_webhook, args=(payload,), daemon=True).start()
        return True

    def _print_console(self, payload):
        colors = {"LOW": Fore.CYAN, "MEDIUM": Fore.YELLOW, "HIGH": Fore.RED,
                  "CRITICAL": Fore.MAGENTA + Style.BRIGHT}
        print(f"{colors.get(payload['severity'], Fore.WHITE)}[{payload['severity']}] "
              f"{payload['timestamp']} | [{payload['module']}] {payload['title']} -> "
              f"{payload['details']}{Style.RESET_ALL}")

    def _send_webhook(self, payload):
        message = {"content": f"🚨 **[{payload['severity']}] {payload['title']}**\n"
                   f"**Module:** `{payload['module']}`\n**Details:** ```json\n"
                   f"{json.dumps(payload['details'], indent=2)}\n```"}
        try:
            response = requests.post(self.webhook_url, json=message, timeout=5)
            response.raise_for_status()
        except requests.RequestException as exc:
            print(f"[!] Webhook delivery failed: {exc}", file=sys.stderr)

    def close(self):
        with self._lock:
            self._handler.flush()
            self._handler.close()
            self._logger.removeHandler(self._handler)
