import io
import logging
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.connector import ConnectorConfig, build_helper_argv, build_openconnect_argv
from hyu_vpn.hip_xml import HostInfo, MacPosture, NetworkInterface


class BytesWriter:
    def __init__(self):
        self.buffer = io.BytesIO()


class SecurityPrivacyTests(unittest.TestCase):
    def test_hip_cli_and_connector_privacy_canaries_stay_out_of_stderr_and_logs(self):
        from hyu_vpn import hip_cli
        cookie = "user=USER-CANARY&domain=DOMAIN-CANARY&computer=HOST-CANARY&authcookie=AUTHCOOKIE-CANARY"
        password = "PASSWORD-CANARY"
        seed = "SEED-CANARY"
        otp = "654321"
        host_id = "HOST-ID-CANARY"
        mac = "de:ad:be:ef:00:42"
        stdout = BytesWriter()
        stderr = io.StringIO()
        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)
        old_level = root_logger.level
        root_logger.setLevel(logging.DEBUG)
        collector = mock.Mock()
        collector.collect.return_value = MacPosture(host_info=HostInfo(
            host_name="HOST-CANARY",
            host_id=host_id,
            interfaces=(NetworkInterface(name="en0", description="en0", mac_address=mac),),
        ))
        try:
            rc = hip_cli.main(
                ["--cookie", cookie, "--md5", "m", "--client-ip", "192.0.2.80"],
                _collector_factory=lambda: collector,
                _stdout=stdout,
                _stderr=stderr,
            )
        finally:
            root_logger.removeHandler(handler)
            root_logger.setLevel(old_level)

        self.assertEqual(rc, 0, stderr.getvalue())
        xml_text = stdout.buffer.getvalue().decode("utf-8")
        self.assertIn("USER-CANARY", xml_text)
        self.assertIn("HOST-CANARY", xml_text)
        self.assertIn(host_id, xml_text)
        self.assertIn(mac, xml_text)
        self.assertNotIn("AUTHCOOKIE-CANARY", xml_text)
        for forbidden in [password, seed, otp, cookie, "AUTHCOOKIE-CANARY"]:
            self.assertNotIn(forbidden, xml_text)
        for diagnostic in [stderr.getvalue(), log_stream.getvalue()]:
            self.assertNotIn("USER-CANARY", diagnostic)
            self.assertNotIn("HOST-CANARY", diagnostic)
            self.assertNotIn(host_id, diagnostic)
            self.assertNotIn(mac, diagnostic)
            self.assertNotIn(cookie, diagnostic)
            self.assertNotIn(password, diagnostic)
            self.assertNotIn(seed, diagnostic)
            self.assertNotIn(otp, diagnostic)
            self.assertNotIn("<hip-report", diagnostic)

    def test_connector_argv_uses_wrapper_without_password_seed_otp_or_full_cookie(self):
        argv = build_openconnect_argv("USER-CANARY", config=ConnectorConfig(hip_wrapper="/repo/bin/gp-hip-report"))
        joined = "\n".join(argv)

        self.assertIn("--csd-wrapper=/repo/bin/gp-hip-report", joined)
        self.assertIn("--user=USER-CANARY", joined)
        self.assertNotIn("PASSWORD-CANARY", joined)
        self.assertNotIn("SEED-CANARY", joined)
        self.assertNotIn("654321", joined)
        self.assertNotIn("authcookie=AUTHCOOKIE-CANARY", joined)
        self.assertFalse(any("PanGP" in part or "GlobalProtect" in part for part in argv))

    def test_production_helper_argv_contains_no_identity_credential_or_path_override(self):
        argv = build_helper_argv(config=ConnectorConfig())
        joined = "\n".join(argv)

        self.assertEqual(argv, [
            "/usr/bin/sudo",
            "-n",
            "/Library/PrivilegedHelperTools/com.hyu.vpn.helper",
            "start",
        ])
        for forbidden in ("USER-CANARY", "PASSWORD-CANARY", "SEED-CANARY", "654321", "authcookie", "--script", "openconnect"):
            self.assertNotIn(forbidden, joined)


if __name__ == "__main__":
    unittest.main()
