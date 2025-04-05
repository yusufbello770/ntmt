from collections import defaultdict
from core.utils.constants import BANDWIDTH_THRESHOLD

class BandwidthDetector:
    def __init__(self):
        self.usage = defaultdict(lambda: {'upload': 0, 'download': 0})

    def track_usage(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            length = len(packet)
            self.usage[src]['upload'] += length
            self.usage[dst]['download'] += length

    def check_thresholds(self):
        alerts = []
        for ip, stats in self.usage.items():
            total = stats['upload'] + stats['download']
            if total > BANDWIDTH_THRESHOLD:
                alerts.append(f"Bandwidth misuse: {ip} used {total//1024//1024} MB")
        return alerts