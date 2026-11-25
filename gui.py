import json
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QColor, QFont
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QHBoxLayout, QLabel,
    QMainWindow, QMessageBox, QPushButton, QStackedWidget, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget, QHeaderView
)

from src.alerter import AlertManager
from src.fim import FileIntegrityMonitor
from src.network_ids import NetworkIntrusionMonitor


APP_DIR = Path.home() / ".watchdog-ids"
LOG_PATH = APP_DIR / "logs" / "alerts.jsonl"
BASELINE_PATH = APP_DIR / "state" / "baseline.json"
QUARANTINE_PATH = APP_DIR / "state" / "quarantine"
DEFAULT_WATCH = Path.home() / "Documents"


LIGHT = """
QWidget { background:#f3f6ff; color:#17233f; font-family:'Segoe UI'; font-size:13px; }
QFrame#sidebar { background:#101d4d; border-radius:18px; }
QLabel#brand { color:white; font-size:21px; font-weight:800; }
QLabel#navhint { color:#a9b9e9; }
QPushButton#nav { color:#d9e3ff; background:transparent; border:0; padding:13px 15px; text-align:left; border-radius:10px; font-weight:600; }
QPushButton#nav:hover, QPushButton#nav[active="true"] { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #3277ee,stop:1 #16c9df); color:white; }
QFrame#panel { background:white; border:1px solid #e4eaff; border-radius:16px; }
QLabel#muted { color:#7381a4; }
QLabel#metric { font-size:27px; font-weight:800; color:#14254a; }
QLabel#pageTitle { font-size:27px; font-weight:800; color:#14254a; }
QPushButton#primary { color:white; background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #3778f6,stop:1 #8b5cf6); border:0; border-radius:10px; padding:10px 16px; font-weight:700; }
QPushButton#secondary { color:#31528e; background:#eaf0ff; border:1px solid #d9e3ff; border-radius:10px; padding:9px 14px; font-weight:600; }
QTableWidget { background:transparent; border:0; gridline-color:#edf1fb; selection-background-color:#e5edff; }
QHeaderView::section { background:#f1f5ff; color:#68799d; border:0; padding:9px; font-weight:700; }
QComboBox { background:white; border:1px solid #dce5fb; border-radius:8px; padding:8px; }
"""
DARK = """
QWidget { background:#0c1430; color:#e8eeff; font-family:'Segoe UI'; font-size:13px; }
QFrame#sidebar { background:#080f27; border-radius:18px; }
QLabel#brand { color:white; font-size:21px; font-weight:800; }
QLabel#navhint { color:#8294c4; }
QPushButton#nav { color:#c2cdef; background:transparent; border:0; padding:13px 15px; text-align:left; border-radius:10px; font-weight:600; }
QPushButton#nav:hover, QPushButton#nav[active="true"] { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #2866d7,stop:1 #06a9c6); color:white; }
QFrame#panel { background:#151f42; border:1px solid #29365f; border-radius:16px; }
QLabel#muted { color:#9baad0; }
QLabel#metric { font-size:27px; font-weight:800; color:#f2f5ff; }
QLabel#pageTitle { font-size:27px; font-weight:800; color:#f2f5ff; }
QPushButton#primary { color:white; background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #3778f6,stop:1 #8b5cf6); border:0; border-radius:10px; padding:10px 16px; font-weight:700; }
QPushButton#secondary { color:#d7e2ff; background:#202e57; border:1px solid #354777; border-radius:10px; padding:9px 14px; font-weight:600; }
QTableWidget { background:transparent; border:0; gridline-color:#29365f; selection-background-color:#263d70; }
QHeaderView::section { background:#1b294e; color:#aebde2; border:0; padding:9px; font-weight:700; }
QComboBox { background:#1b294e; border:1px solid #354777; border-radius:8px; padding:8px; color:#e8eeff; }
"""


def panel():
    frame = QFrame()
    frame.setObjectName("panel")
    return frame


class WatchdogWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Watchdog IDS")
        self.resize(1280, 820)
        self.monitor = None
        self.network_monitor = None
        self.network_alerter = None
        self.alerter = None
        self.watch_dir = DEFAULT_WATCH if DEFAULT_WATCH.exists() else Path.home()
        self.dark = False
        self.nav_buttons = []
        self._build()
        self._apply_theme()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh)
        self.refresh_timer.start(1200)
        self.refresh()

    def _build(self):
        root = QWidget()
        outer = QHBoxLayout(root)
        outer.setContentsMargins(14, 14, 14, 14)
        outer.setSpacing(14)
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(16, 22, 16, 18)
        brand = QLabel("🛡  Watchdog IDS")
        brand.setObjectName("brand")
        side.addWidget(brand)
        hint = QLabel("MONITOR • DETECT • PROTECT")
        hint.setObjectName("navhint")
        side.addWidget(hint)
        side.addSpacing(28)
        for label, page in [("◈  Dashboard", 0), ("▣  File Monitoring", 1), ("⌁  Network IDS", 2), ("⚑  Alerts", 3), ("☷  Activity Logs", 4), ("⚙  Settings", 5)]:
            btn = QPushButton(label)
            btn.setObjectName("nav")
            btn.clicked.connect(lambda checked=False, p=page: self.show_page(p))
            self.nav_buttons.append(btn)
            side.addWidget(btn)
        side.addStretch()
        self.sidebar_status = QLabel("●  SYSTEM IDLE\n\nChoose a folder and start monitoring.")
        self.sidebar_status.setObjectName("navhint")
        self.sidebar_status.setWordWrap(True)
        side.addWidget(self.sidebar_status)
        outer.addWidget(sidebar)

        content = QVBoxLayout()
        top = QHBoxLayout()
        self.page_title = QLabel("Security Overview")
        self.page_title.setObjectName("pageTitle")
        top.addWidget(self.page_title)
        top.addStretch()
        self.theme_button = QPushButton("☾  Dark mode")
        self.theme_button.setObjectName("secondary")
        self.theme_button.clicked.connect(self.toggle_theme)
        top.addWidget(self.theme_button)
        content.addLayout(top)
        self.stack = QStackedWidget()
        self.stack.addWidget(self._dashboard_page())
        self.stack.addWidget(self._monitor_page())
        self.stack.addWidget(self._network_page())
        self.stack.addWidget(self._alerts_page())
        self.stack.addWidget(self._logs_page())
        self.stack.addWidget(self._settings_page())
        content.addWidget(self.stack)
        footer = QLabel("WATCHDOG IDS  •  Local file-integrity monitoring  •  Use only on systems you own or are authorized to monitor")
        footer.setObjectName("muted")
        content.addWidget(footer)
        outer.addLayout(content, 1)
        self.setCentralWidget(root)
        self.show_page(0)

    def _metric_card(self, title, value, accent):
        card = panel()
        box = QVBoxLayout(card)
        name = QLabel(title.upper())
        name.setObjectName("muted")
        number = QLabel(value)
        number.setObjectName("metric")
        number.setStyleSheet(f"color:{accent};")
        box.addWidget(name)
        box.addWidget(number)
        box.addStretch()
        return card, number

    def _dashboard_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        cards = QHBoxLayout()
        c1, self.files_metric = self._metric_card("Files in baseline", "—", "#2675e8")
        c2, self.alert_metric = self._metric_card("Alerts recorded", "0", "#8b5cf6")
        c3, self.status_metric = self._metric_card("Protection", "IDLE", "#10a779")
        for c in (c1, c2, c3): cards.addWidget(c)
        layout.addLayout(cards)
        row = QHBoxLayout()
        status = panel()
        v = QVBoxLayout(status)
        v.addWidget(QLabel("LIVE SECURITY STATUS"))
        self.status_head = QLabel("Monitoring is stopped")
        self.status_head.setStyleSheet("font-size:21px;font-weight:800;")
        v.addWidget(self.status_head)
        self.status_detail = QLabel("Select a directory, then start monitoring to watch file changes.")
        self.status_detail.setObjectName("muted")
        self.status_detail.setWordWrap(True)
        v.addWidget(self.status_detail)
        controls = QHBoxLayout()
        self.start_btn = QPushButton("▶  Start monitoring")
        self.start_btn.setObjectName("primary")
        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn = QPushButton("■  Stop")
        self.stop_btn.setObjectName("secondary")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        controls.addWidget(self.start_btn)
        controls.addWidget(self.stop_btn)
        controls.addStretch()
        v.addLayout(controls)
        row.addWidget(status, 1)
        activity = panel()
        av = QVBoxLayout(activity)
        av.addWidget(QLabel("MONITORED DIRECTORY"))
        self.directory_label = QLabel(str(self.watch_dir))
        self.directory_label.setWordWrap(True)
        self.directory_label.setStyleSheet("font-weight:700;")
        av.addWidget(self.directory_label)
        choose = QPushButton("Choose folder")
        choose.setObjectName("secondary")
        choose.clicked.connect(self.choose_directory)
        av.addWidget(choose)
        av.addStretch()
        row.addWidget(activity, 1)
        layout.addLayout(row)
        recent = panel()
        rv = QVBoxLayout(recent)
        rv.addWidget(QLabel("RECENT SECURITY EVENTS"))
        self.recent_table = self._make_table(["Time", "Severity", "Event", "Details"])
        rv.addWidget(self.recent_table)
        layout.addWidget(recent, 1)
        return page

    def _make_table(self, headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        return table

    def _monitor_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        box = panel()
        v = QVBoxLayout(box)
        v.addWidget(QLabel("FILE INTEGRITY MONITOR"))
        self.monitor_info = QLabel("The selected directory is monitored recursively for file creation, modification and deletion.")
        self.monitor_info.setWordWrap(True)
        self.monitor_info.setObjectName("muted")
        v.addWidget(self.monitor_info)
        self.monitor_path = QLabel(str(self.watch_dir))
        self.monitor_path.setWordWrap(True)
        v.addWidget(self.monitor_path)
        b = QPushButton("Choose monitored directory")
        b.setObjectName("primary")
        b.clicked.connect(self.choose_directory)
        v.addWidget(b)
        layout.addWidget(box)
        layout.addStretch()
        return page


    def _network_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        box = panel()
        v = QVBoxLayout(box)
        v.addWidget(QLabel("PASSIVE NETWORK INTRUSION DETECTION"))
        self.network_info = QLabel(
            "Watches authorized network traffic for possible TCP/UDP port scans, "
            "ICMP sweeps and changes in IP-to-MAC address mappings (possible ARP spoofing). "
            "Detection is heuristic and can produce false positives."
        )
        self.network_info.setWordWrap(True)
        self.network_info.setObjectName("muted")
        v.addWidget(self.network_info)
        self.network_status = QLabel("Network monitoring is stopped.")
        self.network_status.setStyleSheet("font-size:18px;font-weight:700;")
        v.addWidget(self.network_status)
        controls = QHBoxLayout()
        self.network_start_btn = QPushButton("▶  Start network monitoring")
        self.network_start_btn.setObjectName("primary")
        self.network_start_btn.clicked.connect(self.start_network_monitoring)
        self.network_stop_btn = QPushButton("■  Stop network monitoring")
        self.network_stop_btn.setObjectName("secondary")
        self.network_stop_btn.clicked.connect(self.stop_network_monitoring)
        controls.addWidget(self.network_start_btn)
        controls.addWidget(self.network_stop_btn)
        controls.addStretch()
        v.addLayout(controls)
        note = QLabel(
            "Windows requirement: install Npcap from its official website. "
            "Packet capture may require running Watchdog IDS as Administrator. "
            "This feature is passive; it does not scan or send packets."
        )
        note.setWordWrap(True)
        note.setObjectName("muted")
        v.addWidget(note)
        layout.addWidget(box)
        layout.addStretch()
        return page

    def start_network_monitoring(self):
        if self.network_monitor:
            return
        try:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            self.network_alerter = AlertManager(log_file=LOG_PATH)
            self.network_monitor = NetworkIntrusionMonitor(self.network_alerter)
            self.network_monitor.start()
            self.network_status.setText("Starting packet capture…")
            self.sidebar_status.setText("●  NETWORK IDS STARTING\\n\\nPassive capture is initializing.")
        except Exception as exc:
            self.network_monitor = None
            if self.network_alerter:
                self.network_alerter.close()
                self.network_alerter = None
            QMessageBox.critical(self, "Could not start network monitoring", str(exc))
        self.refresh()

    def stop_network_monitoring(self):
        if self.network_monitor:
            self.network_monitor.stop()
            self.network_monitor = None
        if self.network_alerter:
            self.network_alerter.close()
            self.network_alerter = None
        if hasattr(self, "network_status"):
            self.network_status.setText("Network monitoring is stopped.")
        self.refresh()

    def _alerts_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        box = panel()
        v = QVBoxLayout(box)
        v.addWidget(QLabel("SECURITY ALERTS"))
        self.alerts_table = self._make_table(["Timestamp", "Severity", "Module", "Alert", "Details"])
        v.addWidget(self.alerts_table)
        layout.addWidget(box)
        return page

    def _logs_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        box = panel()
        v = QVBoxLayout(box)
        v.addWidget(QLabel("EVENT LOG"))
        self.logs_table = self._make_table(["Timestamp", "Severity", "Event", "Details"])
        v.addWidget(self.logs_table)
        layout.addWidget(box)
        return page

    def _settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        box = panel()
        v = QVBoxLayout(box)
        v.addWidget(QLabel("APPLICATION SETTINGS"))
        v.addWidget(QLabel("Theme"))
        self.theme_select = QComboBox()
        self.theme_select.addItems(["Light", "Dark"])
        self.theme_select.currentTextChanged.connect(self.set_theme)
        v.addWidget(self.theme_select)
        v.addWidget(QLabel("Monitoring scope"))
        v.addWidget(QLabel("Recursive directory monitoring is enabled. The initial baseline is stored locally in your user profile."))
        v.addWidget(QLabel("Alert log: " + str(LOG_PATH)))
        v.addWidget(QLabel("Baseline: " + str(BASELINE_PATH)))
        v.addStretch()
        layout.addWidget(box)
        return page

    def show_page(self, index):
        self.stack.setCurrentIndex(index)
        titles = ["Security Overview", "File Monitoring", "Network IDS", "Security Alerts", "Activity Logs", "Settings"]
        self.page_title.setText(titles[index])
        for i, button in enumerate(self.nav_buttons):
            button.setProperty("active", i == index)
            button.style().unpolish(button)
            button.style().polish(button)

    def choose_directory(self):
        selected = QFileDialog.getExistingDirectory(self, "Choose directory to monitor", str(self.watch_dir))
        if selected:
            if self.monitor:
                QMessageBox.information(self, "Monitoring active", "Stop monitoring before changing the watched directory.")
                return
            self.watch_dir = Path(selected)
            self.directory_label.setText(str(self.watch_dir))
            self.monitor_path.setText(str(self.watch_dir))

    def start_monitoring(self):
        if self.monitor:
            return
        try:
            APP_DIR.mkdir(parents=True, exist_ok=True)
            self.alerter = AlertManager(log_file=LOG_PATH)
            self.monitor = FileIntegrityMonitor(
                directory_to_watch=self.watch_dir,
                alerter=self.alerter,
                recursive=True,
                baseline_path=BASELINE_PATH,
                quarantine_path=QUARANTINE_PATH,
            )
            self.monitor.start()
            self.sidebar_status.setText("●  MONITORING ACTIVE\n\nWatching: " + str(self.watch_dir))
            self.status_head.setText("Your system is being monitored")
            self.status_detail.setText("File events are written to the local alert log. This is file-integrity monitoring, not network traffic inspection.")
            self.status_metric.setText("ACTIVE")
        except Exception as exc:
            self.monitor = None
            if self.alerter:
                self.alerter.close()
                self.alerter = None
            QMessageBox.critical(self, "Could not start monitoring", str(exc))
        self.refresh()

    def stop_monitoring(self):
        if self.monitor:
            self.monitor.stop()
            self.monitor = None
        if self.alerter:
            self.alerter.close()
            self.alerter = None
        self.sidebar_status.setText("●  SYSTEM IDLE\n\nMonitoring is stopped.")
        self.status_head.setText("Monitoring is stopped")
        self.status_metric.setText("IDLE")
        self.refresh()

    def _read_alerts(self):
        if not LOG_PATH.exists():
            return []
        rows = []
        try:
            with LOG_PATH.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try: rows.append(json.loads(line))
                    except json.JSONDecodeError: continue
        except OSError:
            pass
        return rows[-500:]

    @staticmethod
    def _details(alert):
        details = alert.get("details", {})
        if isinstance(details, dict):
            return json.dumps(details, ensure_ascii=False)
        return str(details)

    def _fill_table(self, table, rows, columns):
        table.setRowCount(0)
        for row in rows:
            index = table.rowCount()
            table.insertRow(index)
            for col, key in enumerate(columns):
                value = row.get(key, "")
                if key == "details": value = self._details(row)
                elif key == "timestamp": value = str(value).replace("T", " ")[:19]
                item = QTableWidgetItem(str(value))
                table.setItem(index, col, item)

    def refresh(self):
        if self.network_monitor and self.network_monitor.error:
            self.network_status.setText('Capture error: ' + self.network_monitor.error)
        elif self.network_monitor and self.network_monitor.running:
            self.network_status.setText('Network packet capture is active.')
        alerts = self._read_alerts()
        self.alert_metric.setText(str(len(alerts)))
        self.files_metric.setText(str(len(self.monitor._snapshot)) if self.monitor else "—")
        recent = list(reversed(alerts[-8:]))
        self._fill_table(self.recent_table, recent, ["timestamp", "severity", "title", "details"])
        self._fill_table(self.alerts_table, list(reversed(alerts)), ["timestamp", "severity", "module", "title", "details"])
        self._fill_table(self.logs_table, list(reversed(alerts)), ["timestamp", "severity", "title", "details"])

    def toggle_theme(self):
        self.set_theme("Light" if self.dark else "Dark")

    def set_theme(self, value):
        self.dark = value == "Dark"
        self._apply_theme()

    def _apply_theme(self):
        self.setStyleSheet(DARK if self.dark else LIGHT)
        if hasattr(self, "theme_button"):
            self.theme_button.setText("☀  Light mode" if self.dark else "☾  Dark mode")
        if hasattr(self, "theme_select"):
            self.theme_select.blockSignals(True)
            self.theme_select.setCurrentText("Dark" if self.dark else "Light")
            self.theme_select.blockSignals(False)

    def closeEvent(self, event):
        self.stop_network_monitoring()
        self.stop_monitoring()
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Watchdog IDS")
    app.setFont(QFont("Segoe UI", 10))
    window = WatchdogWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
