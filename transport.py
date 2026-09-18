import socket
import struct

MAX_MESSAGE_SIZE = 65535


def _recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed before complete message was received.")
        data.extend(chunk)
    return bytes(data)


def connect_to_peer(peer_ip, peer_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((peer_ip, peer_port))
    return sock


def accept_peer(listen_port, bind_ip="0.0.0.0"):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_ip, listen_port))
    server.listen(1)
    conn, addr = server.accept()
    server.close()
    return conn, addr


def send_message(sock, data):
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    data = bytes(data)
    if not data or len(data) > MAX_MESSAGE_SIZE:
        raise ValueError("message must contain 1..65535 bytes")
    sock.sendall(struct.pack("!H", len(data)) + data)


def receive_message(sock):
    length = struct.unpack("!H", _recv_exact(sock, 2))[0]
    if not length:
        raise ValueError("invalid zero-length message")
    return _recv_exact(sock, length)
