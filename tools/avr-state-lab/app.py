#!/usr/bin/env python3
"""Loopback-only AVR state mirror simulator; it does not control the receiver."""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import tempfile
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
STATE_FILE = ROOT / "state.json"
PAGE_FILE = ROOT / "index.html"
HOST = "127.0.0.1"
BIND_HOST = os.environ.get("AVR_STATE_LAB_BIND", HOST)
PORT = 8765
SOURCES = {
    "cable_sat": "Cable/Sat",
    "game": "Game",
    "media_server": "Media Server",
    "network": "Network",
    "radio": "Radio",
    "tv": "TV",
}


def new_state():
    return {
        "confidence": "assumed",
        "power": "unknown",
        "source": None,
        "volume": None,
        "muted": None,
        "updated_at": None,
        "history": [],
    }


def load_state():
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return new_state()
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Cannot read persisted state at {STATE_FILE}: {error}") from error
    if not isinstance(state, dict) or state.get("confidence") != "assumed":
        raise RuntimeError(f"Persisted state has an invalid format: {STATE_FILE}")
    return state


def save_state(state):
    fd, temporary_name = tempfile.mkstemp(prefix=".state-", dir=ROOT)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temporary_file:
            json.dump(state, temporary_file, indent=2)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_name, STATE_FILE)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def apply_command(state, command):
    action = command.get("action")
    if action == "power_on":
        state["power"] = "on"
    elif action == "power_off":
        state["power"] = "off"
    elif action == "power_toggle":
        state["power"] = "off" if state["power"] == "on" else "on"
    elif action == "source":
        value = command.get("value")
        if not isinstance(value, str) or value not in SOURCES:
            raise ValueError("Choose a source from the supported list.")
        state["source"] = value
    elif action == "volume_set":
        value = command.get("value")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Volume must be a number from -80 to 10 dB.")
        if value < -80 or value > 10 or not math.isfinite(value):
            raise ValueError("Volume must be between -80 and 10 dB.")
        state["volume"] = round(float(value), 1)
    elif action in ("volume_up", "volume_down"):
        if state["volume"] is None:
            raise ValueError("Set a starting volume before using volume up/down.")
        step = 1 if action == "volume_up" else -1
        state["volume"] = max(-80, min(10, state["volume"] + step))
    elif action == "mute_on":
        state["muted"] = True
    elif action == "mute_off":
        state["muted"] = False
    elif action == "mute_toggle":
        state["muted"] = not state["muted"] if state["muted"] is not None else True
    elif action == "reset":
        return new_state()
    else:
        raise ValueError("Unknown action.")

    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    state["updated_at"] = timestamp
    state["history"].append({"action": action, "value": command.get("value"), "at": timestamp})
    state["history"] = state["history"][-20:]
    return state


class Handler(BaseHTTPRequestHandler):
    server_version = "AVRStateLab/1.0"

    def _valid_local_request(self):
        host = self.headers.get("Host", "").split(":", 1)[0].strip("[]").lower()
        if host not in ("127.0.0.1", "localhost"):
            return False
        origin = self.headers.get("Origin")
        if origin:
            parsed = urlparse(origin)
            if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost"):
                return False
        return True

    def _send_json(self, status, value):
        payload = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if not self._valid_local_request():
            self._send_json(403, {"error": "Loopback requests only."})
            return
        if self.path == "/":
            try:
                page = PAGE_FILE.read_bytes()
            except OSError as error:
                self._send_json(500, {"error": f"Cannot read app page: {error}"})
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(page)
        elif self.path == "/api/state":
            try:
                self._send_json(200, load_state())
            except RuntimeError as error:
                self._send_json(500, {"error": str(error)})
        else:
            self._send_json(404, {"error": "Not found."})

    def do_POST(self):
        if not self._valid_local_request():
            self._send_json(403, {"error": "Loopback requests only."})
            return
        if self.path != "/api/command":
            self._send_json(404, {"error": "Not found."})
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
            self._send_json(415, {"error": "Send application/json."})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                raise ValueError("Request body must be between 1 and 4096 bytes.")
            command = json.loads(self.rfile.read(length))
            if not isinstance(command, dict):
                raise ValueError("Command must be a JSON object.")
            state = apply_command(load_state(), command)
            save_state(state)
            self._send_json(200, state)
        except (ValueError, json.JSONDecodeError) as error:
            self._send_json(400, {"error": str(error)})
        except RuntimeError as error:
            self._send_json(500, {"error": str(error)})
        except OSError as error:
            self._send_json(500, {"error": f"Could not persist state: {error}"})

    def log_message(self, format_string, *args):
        print(f"{self.address_string()} - {format_string % args}")


if __name__ == "__main__":
    print(f"AVR State Lab: http://{HOST}:{PORT}")
    print("Simulator only. No commands are sent to the receiver.")
    ThreadingHTTPServer((BIND_HOST, PORT), Handler).serve_forever()
