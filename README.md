# Watchdog IDS

A small, defensive file-integrity monitoring (FIM) starter project. It watches a directory, computes SHA-256 hashes, and reports file creation, modification, and deletion as JSONL alerts.

> **Scope and limitations:** This is a local runtime monitor, not a complete network IDS or endpoint protection product. Its initial baseline lives in process memory, so changes made while it is stopped are not detected. Use it only on directories and systems you own or are authorized to monitor. For production use, add a signed baseline stored outside the monitored host, durable service supervision, access controls, and monitoring of the alert log itself.

## Requirements

- Python 3.9 or newer
- Dependencies from `requirements.txt`

## Install and run

```bash
python -m venv .venv
# Linux/macOS
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

By default, `secure_folder/` is monitored recursively and alerts are appended to `logs/alerts.jsonl`. Stop with Ctrl+C.

## Options

```bash
python main.py --help
python main.py --watch ./important-files --log ./logs/fim.jsonl
python main.py --watch ./important-files --non-recursive
```

The `WATCHDOG_DIRECTORY` and `WATCHDOG_LOG` environment variables can set defaults. Set `WATCHDOG_WEBHOOK_URL` to enable optional Discord-compatible notifications for HIGH and CRITICAL alerts. Treat webhook URLs as secrets: do not commit them, and rotate any URL that has been exposed.

## Alerts

Each JSONL line contains a UTC timestamp, module, severity, title, and details. File change details include relative path and SHA-256 hash/size metadata. Alert deduplication is keyed per change type and path and rate-limited during the configured cooldown.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests exercise the local FIM event handling logic using temporary directories; they do not require elevated privileges or touch system files.
