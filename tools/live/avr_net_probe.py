#!/usr/bin/env python3
"""
Read-only probe for the AVR 1710's TCP:10025 XML/HTTP command service.

This talks ONLY to the receiver's existing, unmodified, already-shipping
network service (reverse-engineered from FUN_08049d90 / FUN_08044dc4 in the
stock firmware). It does not touch the firmware in any way.

Wire format (confirmed by direct byte-read of the shipping image):
    POST AVR HTTP/1.1
    Host: <ip>:10025
    User-Agent:Harman Kardon AVR171/AVR1710
    Content-Length: <n>

    <?xml version="1.0" encoding="UTF-8"?><harman><avr><common><staus><name>CMD</name><zone>ZONE</zone><para>PARAM</para></status></common></avr></harman>

Note: the opening tag is "<staus>" (misspelled in the real firmware) but the
closing tag is the correctly-spelled "</status>" -- this exact asymmetry is
reproduced here deliberately; do not "fix" it.

Usage:
    python3 avr_net_probe.py <receiver-ip> [port]

By default this script only sends safe, read-only commands:
    heart-alive
    query-status / para=power
    query-status / para=source
    query-status / para=volume
    query-status / para=mute

CONFIRMED FIRMWARE LIMITATION (live-tested + statically proven, stock V002.23):
query-status replies are genuine dispatcher output (FUN_08049d90 really does
parse the request and rebuild <name> to the queried item), but the response
formatter FUN_08044dc4 only ever substitutes its 1st argument (the item
name) into the reply text -- its 2nd/3rd arguments (the computed "on"/"off",
source name, or similar value) are stored to local stack variables and then
never referenced again. On stock V002.23, every query-status reply looks
like:
    <name>power</name><zone></zone><para></para>
i.e. <zone> and <para> are permanently empty, regardless of real device
state, for every para value.

FIXED in the custom V002.24 build (binary patch in FUN_08044dc4, see
subsystem-findings.md "BUILT, FLASHED, AND LIVE-CONFIRMED..." section):
live-tested against the real device post-flash --
    query-status para=power  -> <para>on</para>      (real value)
    query-status para=source -> <para>Server</para>  (real value)
    query-status para=volume -> <para></para>        (still empty -- scoping limit)
    query-status para=mute   -> <para></para>        (still empty -- scoping limit)
volume/mute remain empty on the patched build too: their dispatcher call
sites pass a literal 0 for the value argument, so there is nothing for the
patch to surface -- this is a separate, unfixed gap, not a patch failure.
"""
import socket
import sys
import time

PORT_DEFAULT = 10025
TIMEOUT_SECS = 5


def build_message(name: str, zone: str = "", para: str = "") -> bytes:
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<harman><avr><common><staus>"
        f"<name>{name}</name><zone>{zone}</zone><para>{para}</para>"
        "</status></common></avr></harman>"
    )
    body = xml.encode("ascii")
    header = (
        "POST AVR HTTP/1.1\r\n"
        f"Host: {{host}}:{{port}}\r\n"
        "User-Agent:Harman Kardon AVR171/AVR1710\r\n"
        f"Content-Length: {len(body)}\r\n"
        "\r\n"
    )
    return header, body


def send_probe(host: str, port: int, name: str, zone: str = "", para: str = ""):
    header_tpl, body = build_message(name, zone, para)
    header = header_tpl.format(host=host, port=port).encode("ascii")
    msg = header + body

    print(f"\n=== sending name={name!r} zone={zone!r} para={para!r} ===")
    print(msg.decode("ascii"))

    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECS) as s:
            s.sendall(msg)
            s.settimeout(TIMEOUT_SECS)
            try:
                data = s.recv(4096)
            except socket.timeout:
                print("[no response within timeout -- connection stayed open, "
                      "device may be push-only or require a persistent listener]")
                return None
            if not data:
                print("[connection closed with no data]")
                return None
            print("--- raw response ---")
            print(data)
            try:
                print("--- decoded ---")
                print(data.decode("ascii", errors="replace"))
            except Exception:
                pass
            return data
    except ConnectionRefusedError:
        print(f"[connection refused on {host}:{port} -- nothing listening there]")
    except socket.timeout:
        print(f"[connection attempt to {host}:{port} timed out]")
    except OSError as e:
        print(f"[connection error: {e}]")
    return None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <receiver-ip> [port]")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT_DEFAULT

    print(f"Probing AVR 1710 at {host}:{port} (read-only commands only)")

    # Safest possible first probe: keepalive, no state change at all.
    send_probe(host, port, "heart-alive")
    time.sleep(0.5)

    for para in ("power", "source", "volume", "mute"):
        send_probe(host, port, "query-status", para=para)
        time.sleep(0.5)


if __name__ == "__main__":
    main()
