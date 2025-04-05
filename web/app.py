from flask import Flask
from flask_socketio import SocketIO
from core.handlers.packet_handler import PacketHandler

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)
packet_handler = PacketHandler()