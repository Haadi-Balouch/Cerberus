import socket

def tcp_ping(ip: str, port: int, timeout: float = 1.0) -> bool:

    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        return True
    except:
        return False

