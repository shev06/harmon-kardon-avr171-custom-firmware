import socket
import sys
import time

HOST = "192.168.0.65"
PORT = 10025
TIMEOUT = 6

label = sys.argv[1] if len(sys.argv) > 1 else "?"
t0 = time.time()
try:
    s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    connected_at = time.time() - t0
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<harman><avr><common><staus>"
        "<name>query-status</name><zone></zone><para>power</para>"
        "</status></common></avr></harman>"
    ).encode("ascii")
    req = (
        b"POST AVR HTTP/1.1\r\n"
        b"Host: " + HOST.encode() + b":" + str(PORT).encode() + b"\r\n"
        b"User-Agent:Harman Kardon AVR171/AVR1710\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"\r\n" + body
    )
    try:
        s.sendall(req)
        data = s.recv(4096)
    except socket.timeout:
        data = b""
    finally:
        try:
            s.close()
        except Exception:
            pass
    elapsed = time.time() - t0
    snippet = data[:120].decode("ascii", errors="replace").replace("\n", " ").replace("\r", "")
    print(f"[{label}] CONNECTED (handshake {connected_at:.2f}s, total {elapsed:.2f}s) reply={snippet!r}")
except Exception as e:
    elapsed = time.time() - t0
    print(f"[{label}] UNREACHABLE - {type(e).__name__}: {e} ({elapsed:.2f}s)")
