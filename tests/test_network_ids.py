import unittest
from src.network_ids import NetworkDetectionEngine


class FakeAlerter:
    def __init__(self):
        self.alerts = []

    def trigger(self, **kwargs):
        self.alerts.append(kwargs)


class NetworkDetectionTests(unittest.TestCase):
    def setUp(self):
        self.alerter = FakeAlerter()
        self.detector = NetworkDetectionEngine(self.alerter, tcp_port_threshold=3,
            udp_port_threshold=3, icmp_threshold=3, window_seconds=10)

    def test_tcp_port_scan_threshold(self):
        for port in (21, 22, 23):
            self.detector.inspect("192.0.2.10", "192.0.2.20", "TCP",
                dst_port=port, tcp_syn=True, now=1)
        self.assertIn("Possible TCP Port Scan", [a["title"] for a in self.alerter.alerts])

    def test_udp_port_scan_threshold(self):
        for port in (53, 123, 161):
            self.detector.inspect("192.0.2.11", "192.0.2.20", "UDP",
                dst_port=port, now=1)
        self.assertIn("Possible UDP Port Scan", [a["title"] for a in self.alerter.alerts])

    def test_icmp_sweep_threshold(self):
        for host in ("192.0.2.1", "192.0.2.2", "192.0.2.3"):
            self.detector.inspect("192.0.2.12", host, "ICMP", icmp_echo=True, now=1)
        self.assertIn("Possible ICMP Sweep", [a["title"] for a in self.alerter.alerts])

    def test_arp_mapping_change(self):
        self.detector.inspect("192.0.2.1", None, "ARP", arp_ip="192.0.2.1",
            arp_mac="00:11:22:33:44:55", now=1)
        self.detector.inspect("192.0.2.1", None, "ARP", arp_ip="192.0.2.1",
            arp_mac="aa:bb:cc:dd:ee:ff", now=2)
        self.assertIn("Possible ARP Spoofing", [a["title"] for a in self.alerter.alerts])

    def test_below_threshold_does_not_alert(self):
        self.detector.inspect("192.0.2.10", "192.0.2.20", "TCP",
            dst_port=443, tcp_syn=True, now=1)
        self.assertEqual(self.alerter.alerts, [])


if __name__ == "__main__":
    unittest.main()
