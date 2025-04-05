from scapy.all import *
from core.detectors import BandwidthDetector, PortScanDetector
from core.handlers.protocols import process_http, process_dns

class PacketHandler:
    def __init__(self):
        self.bw_detector = BandwidthDetector()
        self.port_scan_detector = PortScanDetector()

    def handle_packet(self, packet):
        # Track bandwidth
        self.bw_detector.track_usage(packet)

        # Detect threats
        scan_alert = self.port_scan_detector.detect(packet)
        if scan_alert:
            return {'type': 'malicious', 'message': scan_alert}

        # Process protocols
        if packet.haslayer(HTTPRequest):
            return process_http(packet)
        elif packet.haslayer(DNSQR):
            return process_dns(packet)
        return None