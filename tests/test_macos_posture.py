import os
import plistlib
import sys
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.hip_xml import Drive, Patch, Product
from hyu_vpn.macos_posture import CommandResult, CommandRunner, MacPostureCollector


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "commands"


class FakeRunner:
    def __init__(self, results):
        self.results = [(tuple(argv), result) for argv, result in results]
        self.calls = []

    def run(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append((argv, timeout))
        for expected_argv, result in self.results:
            if expected_argv == argv:
                if isinstance(result, BaseException):
                    raise result
                return result
        return CommandResult(argv, 127, "", "missing fake result")


def result(argv, stdout="", stderr="", returncode=0):
    return CommandResult(tuple(argv), returncode, stdout, stderr)


def write_plist(path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        plistlib.dump(values, fh)


def subprocess_completed(stdout="", stderr="", returncode=0):
    return mock.Mock(stdout=stdout, stderr=stderr, returncode=returncode)


class CommandRunnerTests(unittest.TestCase):
    def test_run_forces_deterministic_c_locale_for_child_process(self):
        completed = subprocess_completed(stdout="ok\n")
        with mock.patch.dict(os.environ, {"LC_ALL": "ko_KR.UTF-8", "LANG": "ko_KR.UTF-8"}, clear=False):
            with mock.patch("hyu_vpn.macos_posture.subprocess.run", return_value=completed) as run:
                result_value = CommandRunner().run(("/usr/bin/true",), timeout=3.0)

        self.assertEqual(result_value.stdout, "ok\n")
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["env"]["LC_ALL"], "C")
        self.assertEqual(kwargs["env"]["LANG"], "C")
        self.assertEqual(run.call_args.args[0], ["/usr/bin/true"])


class MacPostureCollectorTests(unittest.TestCase):
    def test_collects_os_and_xprotect_without_build_in_product_version(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            system_plist = root / "SystemVersion.plist"
            xprotect_plist = root / "XProtectInfo.plist"
            write_plist(system_plist, {"ProductName": "macOS", "ProductVersion": "14.5", "ProductBuildVersion": "23F79"})
            write_plist(xprotect_plist, {"CFBundleShortVersionString": "2176", "LastModification": datetime(2026, 8, 1, tzinfo=timezone.utc)})

            posture = MacPostureCollector(
                runner=FakeRunner([]),
                system_version_plist=system_plist,
                xprotect_plist=xprotect_plist,
                software_update_cache=root / "updates.json",
            ).collect()

        self.assertEqual(posture.host_info.os, "Apple Mac OS X 14.5")
        self.assertEqual(posture.host_info.os_version, "14.5")
        self.assertEqual(posture.host_info.os_vendor, "Apple")
        self.assertEqual(posture.anti_malware[0], Product(
            vendor="Apple Inc.", name="Xprotect", version="2176", defver="2176", engver="",
            datemon="08", dateday="01", dateyear="2026", prod_type="3", os_type="4",
            real_time_protection="yes", last_full_scan_time="n/a",
        ))

    def test_xprotect_date_falls_back_to_plist_mtime_and_unknown_install_is_na(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            xprotect_plist = root / "XProtectInfo.plist"
            write_plist(xprotect_plist, {"CFBundleShortVersionString": "2177"})
            mtime = datetime(2026, 7, 29, 12, 34, 56, tzinfo=timezone.utc).timestamp()
            os.utime(xprotect_plist, (mtime, mtime))

            posture = MacPostureCollector(
                runner=FakeRunner([]),
                xprotect_plist=xprotect_plist,
                software_update_cache=root / "updates.json",
            ).collect()

        self.assertEqual(posture.anti_malware[0].datemon, "07")
        self.assertEqual(posture.anti_malware[0].dateday, "29")
        self.assertEqual(posture.anti_malware[0].dateyear, "2026")
        self.assertEqual(posture.anti_malware[0].real_time_protection, "yes")

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            posture = MacPostureCollector(runner=FakeRunner([]), xprotect_plist=root / "missing.plist", software_update_cache=root / "updates.json").collect()
        self.assertEqual(posture.anti_malware[0].version, "n/a")
        self.assertEqual(posture.anti_malware[0].real_time_protection, "n/a")

    def test_collects_security_states_from_enabled_outputs(self):
        runner = FakeRunner([
            (("/usr/sbin/spctl", "--status"), result(("/usr/sbin/spctl", "--status"), "assessments enabled\n")),
            (("/usr/bin/fdesetup", "status"), result(("/usr/bin/fdesetup", "status"), "FileVault is On.\n")),
            (("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"), result(("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"), "Firewall is enabled. (State = 1)\n")),
            (("/sbin/pfctl", "-s", "info"), result(("/sbin/pfctl", "-s", "info"), "Status: Enabled for 0 days\n")),
        ])

        posture = MacPostureCollector(runner=runner).collect()

        self.assertEqual(posture.anti_malware[1].name, "Gatekeeper")
        self.assertEqual(posture.anti_malware[1].real_time_protection, "yes")
        self.assertEqual(posture.disk_encryption, (Drive(drive_name="All", enc_state="encrypted"),))
        self.assertEqual([p.name for p in posture.firewall], ["Mac OS X Builtin Firewall", "Packet Filter"])
        self.assertEqual([p.is_enabled for p in posture.firewall], ["yes", "yes"])

    def test_collects_security_states_from_disabled_outputs(self):
        runner = FakeRunner([
            (("/usr/sbin/spctl", "--status"), result(("/usr/sbin/spctl", "--status"), "assessments disabled\n")),
            (("/usr/bin/fdesetup", "status"), result(("/usr/bin/fdesetup", "status"), "FileVault is Off.\n")),
            (("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"), result(("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"), "Firewall is disabled. (State = 0)\n")),
            (("/sbin/pfctl", "-s", "info"), result(("/sbin/pfctl", "-s", "info"), "Status: Disabled\n")),
        ])

        posture = MacPostureCollector(runner=runner).collect()

        self.assertEqual(posture.anti_malware[1].real_time_protection, "no")
        self.assertEqual(posture.disk_encryption, (Drive(drive_name="All", enc_state="unencrypted"),))
        self.assertEqual([p.is_enabled for p in posture.firewall], ["no", "no"])

    def test_security_command_missing_permission_denied_malformed_and_timeout_are_na_or_unknown(self):
        cases = [
            ("command-missing", 127, "", "not found"),
            ("permission-denied", 1, "", "Operation not permitted"),
            ("malformed-output", 0, "unexpected status text", ""),
            ("timeout", -1, "", "timed out"),
        ]
        for _name, code, stdout, stderr in cases:
            with self.subTest(_name):
                runner = FakeRunner([
                    (("/usr/sbin/spctl", "--status"), result(("/usr/sbin/spctl", "--status"), stdout, stderr, code)),
                    (("/usr/bin/fdesetup", "status"), result(("/usr/bin/fdesetup", "status"), stdout, stderr, code)),
                    (("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"), result(("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"), stdout, stderr, code)),
                    (("/sbin/pfctl", "-s", "info"), result(("/sbin/pfctl", "-s", "info"), stdout, stderr, code)),
                ])

                posture = MacPostureCollector(runner=runner).collect()

                self.assertEqual(posture.anti_malware[1].real_time_protection, "n/a")
                self.assertEqual(posture.disk_encryption, (Drive(drive_name="All", enc_state="unknown"),))
                self.assertEqual([p.is_enabled for p in posture.firewall], ["n/a", "n/a"])

    def test_prefers_stable_primary_hardware_mac_for_interface_and_host_id(self):
        networksetup_output = (FIXTURES / "networksetup-listallhardwareports.txt").read_text(encoding="utf-8")
        runner = FakeRunner([
            (("/usr/sbin/networksetup", "-listallhardwareports"), result(("/usr/sbin/networksetup", "-listallhardwareports"), networksetup_output)),
            (("/sbin/ifconfig",), result(("/sbin/ifconfig",), "en0: flags=...\n\tether de:ad:be:ef:00:01\nlo0: flags=...\n\tether 00:00:00:00:00:00\nutun3: flags=...\n\tether 12:34:56:78:9a:bc\n")),
        ])

        posture = MacPostureCollector(runner=runner).collect()

        self.assertEqual(posture.host_info.interface_name, "en0")
        self.assertEqual(posture.host_info.mac_address, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(posture.host_info.host_id, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(posture.host_info.interfaces[0].name, "en0")
        self.assertEqual(posture.host_info.interfaces[0].mac_address, "aa:bb:cc:dd:ee:ff")

    def test_physical_interface_falls_back_to_ifconfig_and_excludes_loopback_tunnels_and_invalid_macs(self):
        runner = FakeRunner([
            (("/usr/sbin/networksetup", "-listallhardwareports"), result(("/usr/sbin/networksetup", "-listallhardwareports"), "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: not-a-mac\n")),
            (("/sbin/ifconfig",), result(("/sbin/ifconfig",), "lo0: flags=8049<UP,LOOPBACK>\n\tether 00:00:00:00:00:00\nutun4: flags=8051<UP>\n\tether 12:34:56:78:9a:bc\nen5: flags=8863<UP,BROADCAST>\n\tether 22:33:44:55:66:77\n")),
        ])

        posture = MacPostureCollector(runner=runner).collect()

        self.assertEqual(posture.host_info.interface_name, "en5")
        self.assertEqual(posture.host_info.mac_address, "22:33:44:55:66:77")
        self.assertEqual(posture.host_info.host_id, "22:33:44:55:66:77")

    def test_missing_physical_identity_is_explicit(self):
        runner = FakeRunner([
            (("/usr/sbin/networksetup", "-listallhardwareports"), result(("/usr/sbin/networksetup", "-listallhardwareports"), "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: invalid\n")),
            (("/sbin/ifconfig",), result(("/sbin/ifconfig",), "lo0: flags=8049<UP,LOOPBACK>\n\tether 00:00:00:00:00:00\nutun4: flags=8051<UP>\n\tether 12:34:56:78:9a:bc\n")),
        ])

        posture = MacPostureCollector(runner=runner).collect()

        self.assertIsNone(posture.host_info.interface_name)
        self.assertIsNone(posture.host_info.mac_address)
        self.assertIsNone(posture.host_info.host_id)
        self.assertEqual(posture.host_info.interfaces, ())

    def test_software_update_no_updates_produces_known_empty_patches_and_uses_bounded_timeout(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "updates.json"
            argv = ("/usr/sbin/softwareupdate", "--list")
            runner = FakeRunner([(argv, result(argv, "Software Update Tool\nFinding available software\nNo new software available.\n"))])

            posture = MacPostureCollector(runner=runner, software_update_cache=cache, software_update_timeout=12.5).collect()

            self.assertEqual(posture.patches, ())
            self.assertEqual(posture.patch_management_product.is_enabled, "yes")
            self.assertIn((argv, 12.5), runner.calls)
            self.assertTrue(cache.exists())
            self.assertEqual(cache.stat().st_mode & 0o777, 0o600)

    def test_software_update_multiple_updates_and_restart_required_are_rich_missing_patches(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "updates.json"
            argv = ("/usr/sbin/softwareupdate", "--list")
            runner = FakeRunner([(argv, result(argv, (FIXTURES / "softwareupdate-list.txt").read_text(encoding="utf-8")))])

            posture = MacPostureCollector(runner=runner, software_update_cache=cache).collect()

            self.assertEqual(posture.patches, (
                Patch(title="macOS Sonoma 14.6-23G80", description="macOS Sonoma 14.6-23G80", product="macOS", vendor="Apple Inc.", severity="2", category="update", is_installed="no"),
                Patch(title="Safari17.6-19618.3.11.11.5", description="Safari17.6-19618.3.11.11.5", product="macOS", vendor="Apple Inc.", severity="1", category="update", is_installed="no"),
            ))
            self.assertEqual(posture.patch_management_product.is_enabled, "yes")
            self.assertEqual(cache.stat().st_mode & 0o777, 0o600)

    def test_software_update_localized_or_malformed_output_is_unknown_not_cached(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "updates.json"
            argv = ("/usr/sbin/softwareupdate", "--list")
            runner = FakeRunner([(argv, result(argv, "소프트웨어 업데이트 도구\n사용 가능한 업데이트를 확인하는 중\n알 수 없는 형식\n"))])

            posture = MacPostureCollector(runner=runner, software_update_cache=cache).collect()

            self.assertEqual(posture.patches, ())
            self.assertEqual(posture.patch_management_product.is_enabled, "n/a")
            self.assertFalse(cache.exists())

    def test_software_update_timeout_uses_fresh_six_hour_cache_when_available(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "updates.json"
            now = datetime(2026, 8, 4, 6, 0, tzinfo=timezone.utc)
            cache.write_text('{"created_at":"2026-08-04T02:00:00+00:00","patches":[{"title":"CachedUpdate-1","severity":"1"}]}', encoding="utf-8")
            os.chmod(cache, 0o600)
            argv = ("/usr/sbin/softwareupdate", "--list")
            runner = FakeRunner([(argv, result(argv, "", "timed out", -1))])

            posture = MacPostureCollector(runner=runner, software_update_cache=cache, now=lambda: now).collect()

        self.assertEqual(posture.patches, (Patch(title="CachedUpdate-1", description="CachedUpdate-1", product="macOS", vendor="Apple Inc.", severity="1", category="update", is_installed="no"),))
        self.assertEqual(posture.patch_management_product.is_enabled, "yes")
        self.assertNotIn((argv, 45.0), runner.calls)

    def test_software_update_timeout_without_fresh_cache_is_unknown_empty_not_positive(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "updates.json"
            argv = ("/usr/sbin/softwareupdate", "--list")
            runner = FakeRunner([(argv, result(argv, "", "timed out", -1))])

            posture = MacPostureCollector(runner=runner, software_update_cache=cache).collect()

        self.assertEqual(posture.patches, ())
        self.assertEqual(posture.patch_management_product.is_enabled, "n/a")

    def test_software_update_cache_corruption_is_ignored_and_replaced_atomically(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td) / "updates.json"
            cache.write_text("not json", encoding="utf-8")
            argv = ("/usr/sbin/softwareupdate", "--list")
            runner = FakeRunner([(argv, result(argv, "   * Label: Replacement-1\n        Title: Replacement, Version: 1.0, Recommended: YES,\n"))])

            posture = MacPostureCollector(runner=runner, software_update_cache=cache).collect()

            self.assertEqual(posture.patches, (Patch(title="Replacement-1", description="Replacement-1", product="macOS", vendor="Apple Inc.", severity="1", category="update", is_installed="no"),))
            self.assertEqual(posture.patch_management_product.is_enabled, "yes")
            self.assertEqual(cache.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(cache.read_text(encoding="utf-8"), "not json")


if __name__ == "__main__":
    unittest.main()
