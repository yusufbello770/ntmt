from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR

def process_http(packet):
    http = packet[HTTPRequest]
    return {
        'time': packet.time,
        'src': packet[IP].src,
        'dst': packet[IP].dst,
        'protocol': 'HTTP',
        'info': f"{http.Method.decode()} {http.Host.decode()}{http.Path.decode()}"
    }

def process_dns(packet):
    dns = packet[DNSQR]
    return {
        'time': packet.time,
        'src': packet[IP].src,
        'dst': packet[IP].dst,
        'protocol': 'DNS',
        'info': f"Query: {dns.qname.decode()}"
    }