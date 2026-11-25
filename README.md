# Watchdog IDS

A defensive host-and-network monitoring starter project. Watchdog combines file-integrity monitoring (FIM) with a passive network intrusion detection module (NIDS). It watches selected directories, computes SHA-256 hashes, and inspects authorized network traffic for suspicious patterns.

> **Scope and limitations:** This is a learning-focused monitoring tool, not a complete enterprise IDS, firewall, antivirus, or endpoint protection product. Network detections are heuristic and can produce false positives or miss attacks. File baseline and alert persistence have limitations. Use it only on systems and networks you own or are authorized to monitor.

## Requirements

- Python 3.9 or newer
- Dependencies from requirements.txt
- For the desktop network IDS: Scapy and Npcap on Windows

## Install and run

```bash
python -m venv .venv
# Linux/macOS
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

By default, secure_folder/ is monitored recursively and alerts are appended to logs/alerts.jsonl. Stop with Ctrl+C.

## Options

```bash
python main.py --help
python main.py --watch ./important-files --log ./logs/fim.jsonl
python main.py --watch ./important-files --non-recursive
```

The WATCHDOG_DIRECTORY and WATCHDOG_LOG environment variables can set defaults. Set WATCHDOG_WEBHOOK_URL to enable optional Discord-compatible notifications for HIGH and CRITICAL alerts. Treat webhook URLs as secrets: do not commit them, and rotate any URL that has been exposed.

## Alerts

Each JSONL line contains a UTC timestamp, module, severity, title, and details. File change details include relative path and SHA-256 hash/size metadata. Alert deduplication is keyed per change type and path and rate-limited during the configured cooldown.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests exercise the local FIM event handling logic using temporary directories; they do not require elevated privileges or touch system files.

## Desktop GUI

A PySide6 desktop interface is available in gui.py. It starts in light mode and includes a dark-mode toggle, dashboard, file monitoring, passive network monitoring, alert history, and log views. The NIDS can flag possible TCP/UDP port scans, ICMP sweeps, and IP-to-MAC mapping changes that may indicate ARP spoofing.

### Windows compatibility

The desktop build targets 64-bit Windows 10 version 1809 or later and Windows 11. The same Windows build is intended to run on both. Windows 10 versions earlier than 1809 and 32-bit Windows are not supported by this Qt 6 desktop build. The GitHub Actions Windows runner builds the application and installer and runs the project's unit tests and GUI import smoke test; final confirmation still requires launching the packaged app on a real Windows 10 and Windows 11 machine.

### Install on Windows

Download **WatchdogIDS-Setup.exe** from the latest successful GitHub Actions run (Actions → Build Windows desktop application → Artifacts), or from the Assets section of a versioned GitHub Release. Double-click the installer and follow the prompts. The installer is per-user (no administrator permission required), installs under the current user's Local AppData Programs folder, and creates a Start Menu shortcut. You can optionally create a desktop shortcut.

The portable application-folder artifact is also available for users who prefer not to install. Keep the entire extracted folder together when running it.

### Run from source

Use 64-bit Python 3.11, then run in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-gui.txt
python gui.py
```

If PowerShell blocks activation, run Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass in that PowerShell window, then activate the environment again.

The GUI stores its runtime alert log, baseline, and quarantine directory under the current user's home directory in .watchdog-ids. Choose a dedicated test folder first; do not point it at your entire system.

### Network monitoring on Windows

Install [Npcap](https://npcap.com/#download) separately before using Network IDS. On Windows, packet capture commonly requires launching Watchdog IDS with **Run as administrator**. Start network monitoring only on a network you own or have permission to monitor. The detector passively observes packets; it does not send probes. It currently flags threshold-based TCP SYN and UDP port scans, ICMP echo sweeps, and an IP address appearing with a different MAC address (possible ARP spoofing). These are indicators, not proof of an attack. Network capture depends on Npcap and adapter permissions; this project does not yet provide packet payload inspection, signature rules, TLS decryption, automatic blocking, or guaranteed detection.

### Build on GitHub Actions

This release pipeline is Windows-only and builds a 64-bit Windows application. It runs automatically for pull requests into main, pushes to main or the desktop feature branch, and version tags. You can also run it manually from Actions → Build Windows desktop application → Run workflow. The Windows artifact is a PyInstaller application folder containing WatchdogIDS.exe and its required libraries; keep the entire folder together when moving or extracting it.

For a tagged release, create and push a version tag (for example v0.3.0); the workflow publishes the Windows executable.

### Testing safely

Use a disposable folder that you own or are authorized to monitor. Start monitoring, create/edit/delete a harmless text file in that folder, and confirm the corresponding events appear in the Alerts and Activity Logs views. Watchdog IDS can monitor file integrity and passively inspect network metadata for a limited set of suspicious patterns. It does not detect every exploit or intrusion.
