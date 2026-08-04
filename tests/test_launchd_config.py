import plistlib
import stat
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLIST = ROOT / "launchd" / "local.hyu-openconnect.plist"
SERVICE = ROOT / "bin" / "hyu-vpn-service"
FINAL_SERVICE = "/Users/shchoi/workspace/hyu-openconnect/bin/hyu-vpn-service"


class LaunchdConfigTests(unittest.TestCase):
    def test_launchd_plist_uses_final_service_path_and_safe_restart_settings(self):
        with PLIST.open("rb") as fh:
            config = plistlib.load(fh)

        self.assertEqual(config["Label"], "local.hyu-openconnect")
        self.assertEqual(config["ProgramArguments"], [FINAL_SERVICE])
        self.assertTrue(config["RunAtLoad"])
        self.assertTrue(config["KeepAlive"])
        self.assertEqual(config["ThrottleInterval"], 120)

    def test_launchd_plist_uses_user_safe_redacted_logs_and_no_secrets_or_native_refs(self):
        text = PLIST.read_text(encoding="utf-8")
        with PLIST.open("rb") as fh:
            config = plistlib.load(fh)

        self.assertEqual(config["StandardOutPath"], "/Users/shchoi/Library/Logs/hyu-openconnect/service.log")
        self.assertEqual(config["StandardErrorPath"], "/Users/shchoi/Library/Logs/hyu-openconnect/service.err")
        forbidden = ["secure.hanyang.ac.kr", "password", "totp", "cookie", "PanGPS", "PanGPA", "PanGpHip", "GlobalProtect", "/Applications/GlobalProtect"]
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, text)

    def test_service_entrypoint_is_executable_and_imports_supervisor_main(self):
        text = SERVICE.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/usr/bin/env python3"))
        self.assertIn("from hyu_vpn.supervisor import main", text)
        self.assertTrue(SERVICE.stat().st_mode & stat.S_IXUSR)


if __name__ == "__main__":
    unittest.main()
