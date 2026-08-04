import json
import subprocess
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.native_client import NativeClientConflict, native_client_cli_main


class NativeClientCLITests(unittest.TestCase):
    _DEFAULT_SUDO_UID = object()

    def run_cli(self, argv, *, euid=0, sudo_uid=_DEFAULT_SUDO_UID, console_uid=501, suppress=None, restore=None, verify=None, env_extra=None):
        calls = []
        env = {} if sudo_uid is self._DEFAULT_SUDO_UID else {"SUDO_UID": sudo_uid}
        if sudo_uid is self._DEFAULT_SUDO_UID:
            env["SUDO_UID"] = "501"
        if env_extra:
            env.update(env_extra)

        def fake_console_uid():
            return console_uid

        def fake_suppress(record_path, *, console_uid):
            calls.append(("suppress", str(record_path), console_uid))
            if suppress:
                suppress()

        def fake_restore(record_path, *, console_uid):
            calls.append(("restore", str(record_path), console_uid))
            if restore:
                restore()

        def fake_verify(record_path, *, console_uid):
            calls.append(("verify", str(record_path), console_uid))
            if verify:
                verify()

        out = []
        err = []
        code = native_client_cli_main(
            argv,
            env=env,
            geteuid=lambda: euid,
            active_console_uid=fake_console_uid,
            suppress=fake_suppress,
            restore=fake_restore,
            verify=fake_verify,
            stdout=out.append,
            stderr=err.append,
        )
        payloads = [json.loads(line) for line in out + err]
        return code, payloads, calls

    def test_suppress_uses_fixed_record_path_and_console_uid_without_live_launchctl_in_tests(self):
        code, payloads, calls = self.run_cli(["suppress-auto-launch"])

        self.assertEqual(code, 0)
        self.assertEqual(payloads, [{"schema_version": 1, "ok": True, "operation": "suppress-auto-launch"}])
        self.assertEqual(calls, [("suppress", "/private/var/db/hyu-vpn/native-suppression.json", 501)])

    def test_restore_uses_same_fixed_record_path_and_console_uid(self):
        code, payloads, calls = self.run_cli(["restore-auto-launch"])

        self.assertEqual(code, 0)
        self.assertEqual(payloads, [{"schema_version": 1, "ok": True, "operation": "restore-auto-launch"}])
        self.assertEqual(calls, [("restore", "/private/var/db/hyu-vpn/native-suppression.json", 501)])

    def test_verify_uses_same_fixed_record_path_and_console_uid(self):
        code, payloads, calls = self.run_cli(["verify-suppressed"])

        self.assertEqual(code, 0)
        self.assertEqual(payloads, [{"schema_version": 1, "ok": True, "operation": "verify-suppressed"}])
        self.assertEqual(calls, [("verify", "/private/var/db/hyu-vpn/native-suppression.json", 501)])

    def test_rejects_any_arbitrary_label_path_uid_or_extra_option_surface(self):
        for argv in (
            ["suppress-auto-launch", "--label", "com.example"],
            ["restore-auto-launch", "--record", "/tmp/record.json"],
            ["suppress-auto-launch", "--uid", "501"],
            ["status"],
        ):
            with self.subTest(argv=argv):
                code, payloads, calls = self.run_cli(argv)
                self.assertEqual(code, 2)
                self.assertEqual(payloads, [{"schema_version": 1, "ok": False, "error_code": "BAD_REQUEST"}])
                self.assertEqual(calls, [])

    def test_requires_root_before_touching_native_state(self):
        code, payloads, calls = self.run_cli(["suppress-auto-launch"], euid=501)

        self.assertEqual(code, 77)
        self.assertEqual(payloads, [{"schema_version": 1, "ok": False, "error_code": "ROOT_REQUIRED"}])
        self.assertEqual(calls, [])

    def test_requires_numeric_nonzero_sudo_uid_matching_active_console_uid(self):
        cases = [None, "", "0", "abc", "502"]
        for sudo_uid in cases:
            with self.subTest(sudo_uid=sudo_uid):
                code, payloads, calls = self.run_cli(["restore-auto-launch"], sudo_uid=sudo_uid)
                self.assertIn(payloads[0]["error_code"], {"SUDO_UID_REQUIRED", "CONSOLE_UID_MISMATCH"})
                self.assertNotEqual(code, 0)
                self.assertEqual(calls, [])

    def test_redacts_underlying_conflict_details(self):
        def fail():
            raise NativeClientConflict("secret launchctl/path detail")

        code, payloads, calls = self.run_cli(["suppress-auto-launch"], suppress=fail)

        self.assertEqual(code, 1)
        self.assertEqual(payloads, [{"schema_version": 1, "ok": False, "error_code": "NATIVE_CLIENT_CONFLICT"}])
        self.assertEqual(calls, [("suppress", "/private/var/db/hyu-vpn/native-suppression.json", 501)])

    def test_script_routes_default_cli_errors_to_stderr_not_stdout(self):
        script = Path(__file__).resolve().parents[1] / "bin" / "hyu-vpn-native-client"

        result = subprocess.run([str(script), "--bad-option"], capture_output=True, text=True, check=False)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(json.loads(result.stderr), {"schema_version": 1, "ok": False, "error_code": "BAD_REQUEST"})


if __name__ == "__main__":
    unittest.main()
