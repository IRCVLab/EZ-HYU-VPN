import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.control import (
    AutoReconnectPreference,
    ControlProtocolError,
    ControlServer,
    parse_control_request,
    send_control_command,
)


class ControlProtocolTests(unittest.TestCase):
    def test_parse_accepts_only_exact_known_control_commands_without_secret_fields(self):
        self.assertEqual(parse_control_request(b'{"schema_version":1,"command":"disconnect"}\n'), "disconnect")
        for payload in [
            b'{"schema_version":1,"command":"status"}\n',
            b'{"schema_version":1,"command":"disconnect","password":"CANARY"}\n',
            b'{"schema_version":1,"command":"disconnect"}' + (b"x" * 2048),
            b'not-json\n',
        ]:
            with self.subTest(payload=payload[:40]):
                with self.assertRaises(ControlProtocolError):
                    parse_control_request(payload)

    def test_auto_reconnect_preference_is_exact_schema_atomic_and_mode_0600(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state" / "auto-reconnect.json"
            pref = AutoReconnectPreference(path)

            pref.write(True)
            self.assertTrue(pref.read(default=False))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"schema_version": 1, "automatic_reconnect_enabled": True})

            path.write_text('{"schema_version":1,"automatic_reconnect_enabled":true,"password":"CANARY"}', encoding="utf-8")
            with self.assertRaises(ControlProtocolError):
                pref.read()

    def test_unix_socket_server_is_mode_0600_and_executes_one_exact_command(self):
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "hyu-control.sock"
            seen = []
            server = ControlServer(socket_path, lambda command: seen.append(command) or (True, None))
            thread = threading.Thread(target=server.serve_once, daemon=True)
            thread.start()
            server.wait_until_ready(timeout=2)

            mode = socket_path.stat().st_mode & 0o777
            response = send_control_command(socket_path, "reconnect")
            thread.join(timeout=2)

        self.assertEqual(mode, 0o600)
        self.assertEqual(seen, ["reconnect"])
        self.assertEqual(response, {"schema_version": 1, "ok": True, "error_code": None})

    def test_auto_reconnect_preference_read_refuses_broken_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state" / "auto.json"
            path.parent.mkdir()
            path.symlink_to(Path(td) / "missing.json")

            with self.assertRaises(ControlProtocolError):
                AutoReconnectPreference(path).read(default=True)

    def test_auto_reconnect_preference_refuses_existing_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "state" / "auto.json"
            path.parent.mkdir()
            target = Path(td) / "target.json"
            target.write_text("target", encoding="utf-8")
            path.symlink_to(target)

            with self.assertRaises(ControlProtocolError):
                AutoReconnectPreference(path).write(True)

            self.assertTrue(path.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), "target")

    def test_control_socket_refuses_existing_symlink_without_unlinking_target(self):
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "hyu-control.sock"
            target = Path(td) / "target"
            target.write_text("do-not-remove", encoding="utf-8")
            socket_path.symlink_to(target)

            with self.assertRaises(ControlProtocolError):
                ControlServer(socket_path, lambda command: (True, None)).serve_once()

            self.assertTrue(socket_path.is_symlink())
            self.assertEqual(target.read_text(encoding="utf-8"), "do-not-remove")

    def test_control_request_rejects_bool_schema_partial_and_extra_stream_bytes(self):
        with self.assertRaises(ControlProtocolError):
            parse_control_request(b'{"schema_version":true,"command":"connect"}\n')
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "hyu-control.sock"
            seen = []
            server = ControlServer(socket_path, lambda command: seen.append(command) or (True, None))
            thread = threading.Thread(target=server.serve_once, daemon=True)
            thread.start()
            server.wait_until_ready(timeout=2)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(socket_path))
                client.sendall(b'{"schema_version":1,"command":"connect"}\n{}')
                response = client.recv(1024)
            thread.join(timeout=2)

        self.assertIn(b"BAD_REQUEST", response)
        self.assertEqual(seen, [])

    def test_accepted_client_timeout_returns_bad_request_and_server_continues(self):
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "hyu-control.sock"
            seen = []
            stop = threading.Event()
            server = ControlServer(socket_path, lambda command: seen.append(command) or (True, None))
            thread = threading.Thread(target=server.serve_forever, args=(stop,), daemon=True)
            thread.start()
            server.wait_until_ready(timeout=2)

            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(str(socket_path))
                client.sendall(b'{"schema_version":1,"command":"connect"}')
                response = client.recv(1024)

            self.assertIn(b"BAD_REQUEST", response)
            self.assertEqual(send_control_command(socket_path, "connect"), {"schema_version": 1, "ok": True, "error_code": None})
            stop.set()
            thread.join(timeout=2)
            self.assertEqual(seen, ["connect"])

    def test_stopping_replaced_server_does_not_unlink_new_control_socket(self):
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "hyu-control.sock"
            first_stop = threading.Event()
            first = ControlServer(socket_path, lambda command: (True, None))
            first_thread = threading.Thread(target=first.serve_forever, args=(first_stop,), daemon=True)
            first_thread.start()
            first.wait_until_ready(timeout=2)

            second_stop = threading.Event()
            second = ControlServer(socket_path, lambda command: (command == "automatic-off", None))
            second_thread = threading.Thread(target=second.serve_forever, args=(second_stop,), daemon=True)
            second_thread.start()
            second.wait_until_ready(timeout=2)

            first_stop.set()
            first_thread.join(timeout=2)
            self.assertFalse(first_thread.is_alive())
            self.assertEqual(
                send_control_command(socket_path, "automatic-off"),
                {"schema_version": 1, "ok": True, "error_code": None},
            )

            second_stop.set()
            second_thread.join(timeout=2)
            self.assertFalse(second_thread.is_alive())
            self.assertFalse(socket_path.exists())

    def test_cli_uses_socket_without_shelling_out(self):
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "hyu-control.sock"
            server = ControlServer(socket_path, lambda command: (command == "automatic-off", None if command == "automatic-off" else "BAD"))
            thread = threading.Thread(target=server.serve_once, daemon=True)
            thread.start()
            server.wait_until_ready(timeout=2)

            completed = subprocess.run(
                [sys.executable, str(Path(__file__).resolve().parents[1] / "bin" / "hyu-vpn-control"), "automatic-off", "--socket", str(socket_path)],
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "HYU_VPN_CONTROL_ALLOW_SOCKET_OVERRIDE": "1"},
            )
            thread.join(timeout=2)

        self.assertEqual(completed.returncode, 0)
        self.assertIn("ok", completed.stdout)
        self.assertNotIn("shell", completed.stderr.lower())


if __name__ == "__main__":
    unittest.main()
