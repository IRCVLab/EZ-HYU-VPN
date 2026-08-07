import io
import runpy
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


class ShortStdout:
    class Buffer:
        def __init__(self, writes):
            self.writes = list(writes)
            self.data = bytearray()
            self.flushed = False

        def write(self, data):
            requested = self.writes.pop(0) if self.writes else len(data)
            count = min(requested, len(data))
            self.data.extend(bytes(data[:count]))
            return count

        def flush(self):
            self.flushed = True

    def __init__(self, writes):
        self.buffer = self.Buffer(writes)


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

    def test_entrypoint_delegates_to_hip_main_without_collecting_live_posture(self):
        with mock.patch("hyu_vpn.hip_cli.main", return_value=0) as main_mock, mock.patch.object(sys, "argv", [str(BIN), *ARGV]):
            with self.assertRaisesRegex(SystemExit, "0"):
                runpy.run_path(str(BIN), run_name="__main__")

        main_mock.assert_called_once_with()

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

    def test_short_writes_are_retried_until_the_complete_xml_is_written(self):
        from hyu_vpn import hip_cli
        stderr = io.StringIO()
        collector = mock.Mock()
        collector.collect.return_value = self.posture()
        stdout = ShortStdout([7, 11, 19])

        rc = hip_cli.main(ARGV, _collector_factory=lambda: collector, _stdout=stdout, _stderr=stderr)

        self.assertEqual(rc, 0, stderr.getvalue())
        ET.fromstring(bytes(stdout.buffer.data))
        self.assertTrue(stdout.buffer.flushed)

    def test_zero_progress_after_partial_write_returns_redacted_error(self):
        from hyu_vpn import hip_cli
        stderr = io.StringIO()
        collector = mock.Mock()
        collector.collect.return_value = self.posture()
        stdout = ShortStdout([7, 0])

        rc = hip_cli.main(ARGV, _collector_factory=lambda: collector, _stdout=stdout, _stderr=stderr)

        self.assertNotEqual(rc, 0)
        self.assertIn("HIP output error", stderr.getvalue())
        self.assertNotIn("CLI-USER", stderr.getvalue())
        self.assertFalse(stdout.buffer.flushed)

    def test_surrogates_in_authoritative_openconnect_identifiers_are_rejected(self):
        from hyu_vpn import hip_cli
        cases = [
            ["--cookie", "user=USER\udcff&domain=D&computer=H", "--md5", "a" * 32, "--client-ip", "192.0.2.1"],
            ["--cookie", "user=U&domain=D&computer=H", "--md5", "a\udcff", "--client-ip", "192.0.2.1"],
            ["--cookie", "user=U&domain=D&computer=H", "--md5", "a" * 32, "--client-ip", "192.0.2.1\udcff"],
        ]
        for argv in cases:
            with self.subTest(argv_index=cases.index(argv)):
                stdout = BytesWriter()
                stderr = io.StringIO()
                rc = hip_cli.main(argv, _stdout=stdout, _stderr=stderr)
                self.assertNotEqual(rc, 0)
                self.assertEqual(stdout.buffer.getvalue(), b"")
                self.assertNotIn("USER", stderr.getvalue())
                self.assertNotIn("192.0.2.1", stderr.getvalue())


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
