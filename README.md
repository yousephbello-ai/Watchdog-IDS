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


## Desktop GUI (preview)

A PySide6 desktop interface is available in `gui.py`. It starts in light mode and includes a dark-mode toggle, dashboard, directory selection, monitoring controls, alert history, and log views.

### Run from source

```bash
python -m pip install -r requirements-gui.txt
python gui.py
```

The GUI stores its runtime alert log, baseline, and quarantine directory under the current user's home directory in `.watchdog-ids/`. Choose a dedicated test directory first; do not point it at your entire system.

### Build on GitHub Actions

Open **Actions → Build desktop applications → Run workflow** and select the `feature/desktop-gui-cross-platform` branch. The workflow builds a Windows executable folder and a Linux x86_64 executable archive. Download the matching artifact from the workflow run.

For a tagged release, create and push a version tag (for example `v0.3.0`); the workflow publishes release assets. The Linux artifact is currently a tar.gz containing the PyInstaller executable, not an AppImage or .deb package.

### Testing safely

Use a disposable folder that you own or are authorized to monitor. Start monitoring, create/edit/delete a harmless text file in that folder, and confirm the corresponding events appear in the Alerts and Activity Logs views. Watchdog IDS monitors file integrity; it does not inspect network packets or detect every exploit or intrusion.
