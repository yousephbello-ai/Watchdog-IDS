import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from colorama import Fore, Style, init

init(autoreset=True)


class AlertManager:
    """Write structured alerts and optionally deliver high-severity alerts."""

    VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def __init__(self, log_file="logs/alerts.jsonl", webhook_url=None, cooldown_seconds=10):
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must be non-negative")
        self.log_path = Path(log_file)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.webhook_url = webhook_url
        self.cooldown = cooldown_seconds
        self._lock = threading.Lock()
        self._recent_alerts = {}

    def _is_rate_limited(self, alert_key):
        now = time.monotonic()
        last_sent = self._recent_alerts.get(alert_key, 0)
        if now - last_sent < self.cooldown:
            return True
        self._recent_alerts[alert_key] = now
        return False

    def trigger(self, module: str, severity: str, title: str, details: dict, dedup_key: str = None):
        severity = severity.upper()
        if severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Unsupported alert severity: {severity}")

        key = dedup_key or f"{module}:{title}"
        with self._lock:
            if self._is_rate_limited(key):
                return False

            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "module": module,
                "severity": severity,
                "title": title,
                "details": details,
            }
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

            self._print_console(payload)

            if self.webhook_url and severity in {"HIGH", "CRITICAL"}:
                threading.Thread(target=self._send_webhook, args=(payload,), daemon=True).start()
            return True

    def _print_console(self, payload):
        colors = {
            "LOW": Fore.CYAN,
            "MEDIUM": Fore.YELLOW,
            "HIGH": Fore.RED,
            "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
        }
        color = colors.get(payload["severity"], Fore.WHITE)
        print(
            f"{color}[{payload['severity']}] {payload['timestamp']} | "
            f"[{payload['module']}] {payload['title']} -> {payload['details']}{Style.RESET_ALL}"
        )

    def _send_webhook(self, payload):
        message = {
            "content": f"🚨 **[{payload['severity']}] {payload['title']}**\n"
            f"**Module:** `{payload['module']}`\n"
            f"**Details:** ```json\n{json.dumps(payload['details'], indent=2)}\n```"
        }
        try:
            response = requests.post(self.webhook_url, json=message, timeout=5)
            response.raise_for_status()
        except requests.RequestException as exc:
            # Keep notification failures visible without crashing the monitor.
            print(f"[!] Webhook delivery failed: {exc}", file=sys.stderr)
