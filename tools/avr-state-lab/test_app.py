import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError


APP_PATH = Path(__file__).with_name("app.py")
SPEC = importlib.util.spec_from_file_location("avr_state_lab", APP_PATH)
app = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(app)


class StateLabTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        app.ROOT = Path(self.temp_dir.name)
        app.STATE_FILE = app.ROOT / "state.json"
        self.server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.temp_dir.cleanup()

    def post(self, command):
        request = Request(
            self.base_url + "/api/command",
            data=json.dumps(command).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return urlopen(request)

    def test_commands_update_and_persist_assumed_state(self):
        initial = json.load(urlopen(self.base_url + "/api/state"))
        self.assertEqual(initial["power"], "unknown")
        self.assertEqual(initial["confidence"], "assumed")

        self.post({"action": "power_on"}).close()
        self.post({"action": "source", "value": "network"}).close()
        self.post({"action": "volume_set", "value": -24.5}).close()
        self.post({"action": "mute_toggle"}).close()

        state = app.load_state()
        self.assertEqual(state["power"], "on")
        self.assertEqual(state["source"], "network")
        self.assertEqual(state["volume"], -24.5)
        self.assertIs(state["muted"], True)
        self.assertEqual(len(state["history"]), 4)

    def test_invalid_volume_is_rejected_without_state_change(self):
        before = app.load_state()
        with self.assertRaises(HTTPError) as error:
            self.post({"action": "volume_set", "value": 99})
        self.assertEqual(error.exception.code, 400)
        self.assertEqual(app.load_state(), before)

    def test_reset_returns_all_state_to_unknown(self):
        self.post({"action": "power_on"}).close()
        self.post({"action": "reset"}).close()
        state = app.load_state()
        self.assertEqual(state["power"], "unknown")
        self.assertIsNone(state["source"])
        self.assertIsNone(state["volume"])
        self.assertIsNone(state["muted"])
        self.assertEqual(state["history"], [])


if __name__ == "__main__":
    unittest.main()
