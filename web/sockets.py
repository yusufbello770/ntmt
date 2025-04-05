from web.app import socketio, packet_handler
from scapy.all import sniff
from threading import Thread

@socketio.on('start')
def handle_start(data):
    filter_str = data.get('filter', 'tcp port 80 or udp port 53')
    Thread(target=sniff_packets, args=(filter_str,)).start()

def sniff_packets(filter_str):
    sniff(filter=filter_str, prn=lambda p: socketio.emit('packet', packet_handler.handle_packet(p)), store=False)