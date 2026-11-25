"""Defensive, passive network intrusion detection for authorized networks.

Windows packet capture requires Npcap. Capturing may require an elevated process.
This module never sends packets or actively scans hosts.
"""
from collections import defaultdict, deque
import threading
import time


class NetworkDetectionEngine:
    """Threshold-based detector testable without live packet capture."""

    def __init__(self, alerter, window_seconds=10.0, tcp_port_threshold=12,
                 udp_port_threshold=15, icmp_threshold=20):
        self.alerter = alerter
        self.window_seconds = float(window_seconds)
        self.tcp_port_threshold = int(tcp_port_threshold)
        self.udp_port_threshold = int(udp_port_threshold)
        self.icmp_threshold = int(icmp_threshold)
        self.events = defaultdict(deque)
        self.arp_mappings = {}

    def _record(self, key, item, now):
        events = self.events[key]
        events.append((now, item))
        cutoff = now - self.window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()
        return events

    def _alert(self, severity, title, details, key):
        self.alerter.trigger(module="NIDS", severity=severity, title=title,
                             details=details, dedup_key=key)

    def inspect(self, src_ip, dst_ip, protocol, dst_port=None, tcp_syn=False,
                icmp_echo=False, arp_ip=None, arp_mac=None, now=None):
        now = time.monotonic() if now is None else float(now)
        emitted = []
        if not src_ip:
            return emitted
        if protocol == "TCP" and tcp_syn and dst_port is not None:
            events = self._record(("tcp", src_ip), int(dst_port), now)
            ports = sorted({port for _, port in events})
            if len(ports) >= self.tcp_port_threshold:
                title = "Possible TCP Port Scan"
                self._alert("HIGH", title, {"source_ip": src_ip, "destination_ip": dst_ip,
                    "unique_destination_ports": ports, "window_seconds": self.window_seconds},
                    f"nids:tcp-scan:{src_ip}")
                emitted.append(title)
        elif protocol == "UDP" and dst_port is not None:
            events = self._record(("udp", src_ip), int(dst_port), now)
            ports = sorted({port for _, port in events})
            if len(ports) >= self.udp_port_threshold:
                title = "Possible UDP Port Scan"
                self._alert("HIGH", title, {"source_ip": src_ip, "destination_ip": dst_ip,
                    "unique_destination_ports": ports, "window_seconds": self.window_seconds},
                    f"nids:udp-scan:{src_ip}")
                emitted.append(title)
        if protocol == "ICMP" and icmp_echo:
            events = self._record(("icmp", src_ip), dst_ip, now)
            targets = sorted({target for _, target in events if target})
            if len(targets) >= self.icmp_threshold:
                title = "Possible ICMP Sweep"
                self._alert("MEDIUM", title, {"source_ip": src_ip,
                    "destination_count": len(targets), "sample_destinations": targets[:30],
                    "window_seconds": self.window_seconds}, f"nids:icmp-sweep:{src_ip}")
                emitted.append(title)
        if arp_ip and arp_mac:
            previous = self.arp_mappings.get(arp_ip)
            if previous and previous.lower() != arp_mac.lower():
                title = "Possible ARP Spoofing"
                self._alert("CRITICAL", title, {"claimed_ip": arp_ip,
                    "previous_mac": previous, "new_mac": arp_mac},
                    f"nids:arp-change:{arp_ip}:{arp_mac.lower()}")
                emitted.append(title)
            self.arp_mappings[arp_ip] = arp_mac
        return emitted


class NetworkIntrusionMonitor:
    """Passive Scapy packet listener. It does not generate network traffic."""

    def __init__(self, alerter, interface=None, on_error=None):
        self.alerter = alerter
        self.interface = interface
        self.on_error = on_error
        self.detector = NetworkDetectionEngine(alerter)
        self._stop = threading.Event()
        self._thread = None
        self.error = None

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def start(self):
        if self.running:
            raise RuntimeError("Network monitor is already running")
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
        except ImportError as exc:
            raise RuntimeError("Scapy is not installed. Install the desktop requirements and try again.") from exc
        self._stop.clear()
        self.error = None

        def consume(packet):
            try:
                src = dst = None
                protocol = "OTHER"
                dst_port = None
                tcp_syn = icmp_echo = False
                arp_ip = arp_mac = None
                if packet.haslayer(IP):
                    ip = packet[IP]
                    src, dst = ip.src, ip.dst
                    if packet.haslayer(TCP):
                        protocol = "TCP"
                        tcp = packet[TCP]
                        dst_port = int(tcp.dport)
                        tcp_syn = bool(int(tcp.flags) & 0x02) and not bool(int(tcp.flags) & 0x10)
                    elif packet.haslayer(UDP):
                        protocol, dst_port = "UDP", int(packet[UDP].dport)
                    elif packet.haslayer(ICMP):
                        protocol, icmp_echo = "ICMP", int(packet[ICMP].type) == 8
                if packet.haslayer(ARP):
                    arp = packet[ARP]
                    arp_ip, arp_mac = str(arp.psrc), str(arp.hwsrc)
                    src, protocol = src or arp_ip, "ARP"
                self.detector.inspect(src, dst, protocol, dst_port, tcp_syn,
                                      icmp_echo, arp_ip, arp_mac)
            except Exception:
                return

        def capture():
            try:
                while not self._stop.is_set():
                    sniff(iface=self.interface, prn=consume, store=False, timeout=1)
            except Exception as exc:
                self.error = str(exc)
                if self.on_error:
                    self.on_error(self.error)
                try:
                    self.alerter.trigger(module="NIDS", severity="HIGH",
                        title="Network Capture Failed",
                        details={"error": self.error, "hint":
                        "On Windows, install Npcap and run with suitable capture permissions."},
                        dedup_key="nids:capture-error")
                except Exception:
                    pass

        self._thread = threading.Thread(target=capture, name="Watchdog-NIDS", daemon=True)
        self._thread.start()
        return self._thread

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None
