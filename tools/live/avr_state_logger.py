#!/usr/bin/env python3
"""Read-only logger: polls query-status power/volume/mute/source on TCP:10025 every N seconds with timestamps.
Use it to correlate a glitch (e.g. HDMI ARC audio drop) with receiver state changes. Sends no control commands.
usage: avr_state_logger.py [ip] [interval_s] [logfile]"""
import re, socket, sys, time
IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.65"
EVERY = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
LOG = sys.argv[3] if len(sys.argv) > 3 else "avr_state.log"

def frame(name, para=""):
    x = f'<?xml version="1.0" encoding="UTF-8"?><harman><avr><common><staus><name>{name}</name><zone></zone><para>{para}</para></status></common></avr></harman>'.encode()
    return (f"POST AVR HTTP/1.1\r\nHost: {IP}:10025\r\nUser-Agent:Harman Kardon AVR171/AVR1710\r\nContent-Length: {len(x)}\r\n\r\n").encode() + x

def ask(para):
    for _ in range(4):
        try:
            s = socket.create_connection((IP, 10025), timeout=3); s.sendall(frame("query-status", para)); s.settimeout(4)
            try: d = s.recv(4096)
            except Exception: d = b""
            s.close()
            m = re.search(rb"<para>(.*?)</para>", d)
            return m.group(1).decode() if m else "?"
        except OSError:
            time.sleep(0.5)
    return "X"

last = None
with open(LOG, "a", buffering=1) as f:
    while True:
        cur = tuple(ask(p) for p in ("power", "volume", "mute", "source"))
        stamp = time.strftime("%H:%M:%S")
        line = f"{stamp} power={cur[0]} vol={cur[1]} mute={cur[2]} src={cur[3]}" + ("" if cur == last else "   <-- CHANGE")
        f.write(line + "\n"); last = cur
        time.sleep(EVERY)
