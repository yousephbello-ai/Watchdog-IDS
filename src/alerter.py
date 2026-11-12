import json
import time
import threading
import requests
from datetime import datetime, timezone
from pathlib import Path
from colorama import Fore, Style, init

init(autoreset=True)

class AlertManager:
    def __init__(self, log_file="logs/alerts.jsonl", webhook_url=None, cooldown_seconds=10):
        self.log_path = Path(log_file)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.webhook_url = webhook_url
        self.cooldown = cooldown_seconds
        self._lock = threading.Lock()
        self._recent_alerts = {}  # Tracks (alert_type, source) -> timestamp

    def _is_rate_limited(self, alert_key):
        now = time.time()
        last_sent = self._recent_alerts.get(alert_key, 0)
        if now - last_sent < self.cooldown:
            return True
        self._recent_alerts[alert_key] = now
        return False

    def trigger(self, module: str, severity: str, title: str, details: dict, dedup_key: str = None):
        """
        Triggers an alert across console, JSON log file, and optional webhook.
        """
        key = dedup_key or f"{module}:{title}"
        with self._lock:
            if self._is_rate_limited(key):
                return

            timestamp = datetime.now(timezone.utc).isoformat()
            alert_payload = {
                "timestamp": timestamp,
                "module": module,
                "severity": severity.upper(),
                "title": title,
                "details": details
            }

            # 1. Write structured JSON line to disk
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_payload) + "\n")

            # 2. Print color-coded alert to console
            self._print_console(alert_payload)

            # 3. Send external webhook for HIGH/CRITICAL alerts
            if self.webhook_url and severity.upper() in ("HIGH", "CRITICAL"):
                threading.Thread(target=self._send_webhook, args=(alert_payload,), daemon=True).start()

    def _print_console(self, payload):
        colors = {
            "LOW": Fore.CYAN,
            "MEDIUM": Fore.YELLOW,
            "HIGH": Fore.RED,
            "CRITICAL": Fore.MAGENTA + Style.BRIGHT
        }
        color = colors.get(payload["severity"], Fore.WHITE)
        print(
            f"{color}[{payload['severity']}] {payload['timestamp']} | "
            f"[{payload['module']}] {payload['title']} -> {payload['details']}{Style.RESET_ALL}"
        )

    def _send_webhook(self, payload):
        try:
            message = {
                "content": f"🚨 **[{payload['severity']}] {payload['title']}**\n"
                           f"**Module:** `{payload['module']}`\n"
                           f"**Details:** ```json\n{json.dumps(payload['details'], indent=2)}\n```"
            }
            requests.post(self.webhook_url, json=message, timeout=5)
        except Exception:
            pass  # Never let a failed webhook crash the IDS
