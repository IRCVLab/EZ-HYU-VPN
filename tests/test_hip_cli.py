import io
import os
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.hip_xml import HostInfo, MacPosture, NetworkInterface, Patch, Product

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "gp-hip-report"
ARGV = [
    "--cookie", "user=CLI-USER&domain=CLI-DOMAIN&computer=CLI-HOST",
    "--md5", "abcdef0123456789abcdef0123456789",
    "--client-ip", "192.0.2.55",
    "--client-ipv6", "2001:db8::55",
    "--client-os", "mac",
]


class BytesWriter:
    def __init__(self):
        self.buffer = io.BytesIO()

    def flush(self):
        pass


class FailingStdout:
    class Buffer:
        def write(self, _data):
            raise BrokenPipeError("PIPE-CANARY should be redacted")

        def flush(self):
            raise AssertionError("flush must not run after failed write")

    buffer = Buffer()


class HipCliTests(unittest.TestCase):
    def posture(self):
        return MacPosture(host_info=HostInfo(
            host_name="CLI-HOST",
            host_id="HOST-ID-CANARY",
            interfaces=(NetworkInterface(name="en0", description="en0", mac_address="aa:bb:cc:dd:ee:ff"),),
        ))

    def test_main_writes_exactly_one_xml_document_to_stdout_and_redacts_stderr(self):
        from hyu_vpn import hip_cli
        stdout = BytesWriter()
        stderr = io.StringIO()
        collector = mock.Mock()
        collector.collect.return_value = self.posture()

        rc = hip_cli.main(
            ARGV,
            environ={"APP_VERSION": "OpenConnect TEST"},
            _collector_factory=lambda: collector,
            _stdout=stdout,
            _stderr=stderr,
            _now=lambda: datetime(2026, 8, 4, 12, 13, 14),
        )

        xml_bytes = stdout.buffer.getvalue()
        self.assertEqual(rc, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertTrue(xml_bytes.startswith(b"<?xml"))
        self.assertEqual(xml_bytes.count(b"<?xml"), 1)
        self.assertEqual(xml_bytes.strip(), xml_bytes)
        root = ET.fromstring(xml_bytes)
        self.assertEqual(root.findtext("user-name"), "CLI-USER")
        self.assertEqual(root.findtext("host-name"), "CLI-HOST")
        self.assertEqual(root.findtext("ip-address"), "192.0.2.55")
        collector.collect.assert_called_once_with()

    def test_entrypoint_resolves_repo_src_and_emits_xml_only_stdout(self):
        completed = subprocess.run(
            [str(BIN), *ARGV],
            cwd="/",
            env={"PATH": os.environ.get("PATH", ""), "PYTHONIOENCODING": "utf-8", "APP_VERSION": "OpenConnect TEST"},
            capture_output=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        self.assertTrue(completed.stdout.startswith(b"<?xml"))
        self.assertEqual(completed.stdout.count(b"<?xml"), 1)
        self.assertEqual(completed.stdout.strip(), completed.stdout)
        ET.fromstring(completed.stdout)
        stderr = completed.stderr.decode("utf-8", "replace")
        self.assertNotIn("user=CLI-USER", stderr)
        self.assertNotIn("CLI-USER", stderr)
        self.assertNotIn("CLI-HOST", stderr)

    def test_missing_arguments_return_nonzero_with_safe_option_names_only(self):
        from hyu_vpn import hip_cli
        stdout = BytesWriter()
        stderr = io.StringIO()

        rc = hip_cli.main(["--cookie", "user=SECRET-USER"], _stdout=stdout, _stderr=stderr)

        self.assertNotEqual(rc, 0)
        self.assertEqual(stdout.buffer.getvalue(), b"")
        self.assertIn("--md5", stderr.getvalue())
        self.assertIn("--client-ip or --client-ipv6", stderr.getvalue())
        self.assertNotIn("SECRET-USER", stderr.getvalue())
        self.assertNotIn("user=", stderr.getvalue())

    def test_collector_failure_returns_nonzero_without_exception_details_or_partial_xml(self):
        from hyu_vpn import hip_cli
        stdout = BytesWriter()
        stderr = io.StringIO()

        rc = hip_cli.main(
            ARGV,
            _collector_factory=lambda: mock.Mock(collect=mock.Mock(side_effect=RuntimeError("HOST-ID-CANARY aa:bb:cc:dd:ee:ff"))),
            _stdout=stdout,
            _stderr=stderr,
        )

        self.assertNotEqual(rc, 0)
        self.assertEqual(stdout.buffer.getvalue(), b"")
        self.assertIn("HIP collection error", stderr.getvalue())
        self.assertNotIn("HOST-ID-CANARY", stderr.getvalue())
        self.assertNotIn("aa:bb:cc:dd:ee:ff", stderr.getvalue())

    def test_broken_pipe_returns_nonzero_without_traceback_or_identifiers(self):
        from hyu_vpn import hip_cli
        stderr = io.StringIO()
        collector = mock.Mock()
        collector.collect.return_value = self.posture()

        rc = hip_cli.main(ARGV, _collector_factory=lambda: collector, _stdout=FailingStdout(), _stderr=stderr)

        self.assertNotEqual(rc, 0)
        self.assertIn("HIP output error", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertNotIn("PIPE-CANARY", stderr.getvalue())
        self.assertNotIn("CLI-USER", stderr.getvalue())
        self.assertNotIn("HOST-ID-CANARY", stderr.getvalue())


    def test_non_utf8_surrogate_collected_posture_does_not_crash_or_leak(self):
        from hyu_vpn import hip_cli
        stdout = BytesWriter()
        stderr = io.StringIO()
        collector = mock.Mock()
        collector.collect.return_value = MacPosture(
            host_info=HostInfo(host_name="CLI-HOST", host_id="HOST-ID-CANARY"),
            anti_malware=(Product(vendor="Apple Inc.", name="Xprotect \udcff", version="1"),),
            patches=(Patch(title="Patch \udcff", description="Patch \udcff"),),
        )

        rc = hip_cli.main(ARGV, _collector_factory=lambda: collector, _stdout=stdout, _stderr=stderr)

        self.assertEqual(rc, 0, stderr.getvalue())
        ET.fromstring(stdout.buffer.getvalue())
        self.assertEqual(stderr.getvalue(), "")

    def test_non_utf8_surrogate_environment_does_not_crash_or_leak(self):
        from hyu_vpn import hip_cli
        stdout = BytesWriter()
        stderr = io.StringIO()
        collector = mock.Mock()
        collector.collect.return_value = self.posture()

        rc = hip_cli.main(
            ARGV,
            environ={"APP_VERSION": "OpenConnect \udcff TEST"},
            _collector_factory=lambda: collector,
            _stdout=stdout,
            _stderr=stderr,
        )

        self.assertEqual(rc, 0, stderr.getvalue())
        ET.fromstring(stdout.buffer.getvalue())
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
