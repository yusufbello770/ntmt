from collections import defaultdict
from core.utils.constants import PORT_SCAN_THRESHOLD

class PortScanDetector:
    def __init__(self):
        self.syn_packets = defaultdict(lambda: {'ports': set(), 'count': 0})

    def detect(self, packet):
        if TCP in packet and packet[TCP].flags == 'S':
            src = packet[IP].src
            dst_port = packet[TCP].dport
            self.syn_packets[src]['ports'].add(dst_port)
            self.syn_packets[src]['count'] += 1

            if self.syn_packets[src]['count'] >= PORT_SCAN_THRESHOLD:
                alert = f"Port scan detected from {src}"
                self.syn_packets[src]['count'] = 0  # Reset
                return alert
        return None