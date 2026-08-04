import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.native_client import (
    AutoLaunchMechanism,
    NativeAutoLaunchManager,
    NativeClientConflict,
    NativeClientState,
)


class FakeAutoLaunchStore:
    def __init__(self, mechanisms):
        self.mechanisms = {m.identifier: m for m in mechanisms}
        self.set_calls = []

    def list_mechanisms(self):
        return list(self.mechanisms.values())

    def set_enabled(self, identifier, enabled):
        current = self.mechanisms[identifier]
        self.mechanisms[identifier] = AutoLaunchMechanism(current.identifier, current.kind, enabled, current.exact_target)
        self.set_calls.append((identifier, enabled))


class NativeClientTests(unittest.TestCase):
    def test_suppresses_only_exact_globalprotect_auto_launch_and_records_prior_state(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangps", "launchd", True, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangps.plist"),
            AutoLaunchMechanism("com.example.unrelated", "launchd", True, "/Library/LaunchDaemons/com.example.unrelated.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "native-suppression.json"
            manager = NativeAutoLaunchManager(store=store)

            manager.suppress_auto_launch(record_path)
            record = json.loads(record_path.read_text(encoding="utf-8"))

        self.assertEqual(store.set_calls, [("com.paloaltonetworks.gp.pangps", False)])
        self.assertEqual(record["mechanisms"], [{
            "identifier": "com.paloaltonetworks.gp.pangps",
            "kind": "launchd",
            "enabled": True,
            "exact_target": "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangps.plist",
        }])
        self.assertNotIn("com.example.unrelated", json.dumps(record))

    def test_restore_only_unchanged_recorded_targets_and_refuses_user_modified_state(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangps", "launchd", False, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangps.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "native-suppression.json"
            manager = NativeAutoLaunchManager(store=store)
            manager.suppress_auto_launch(record_path)
            store.mechanisms["com.paloaltonetworks.gp.pangps"] = AutoLaunchMechanism(
                "com.paloaltonetworks.gp.pangps", "launchd", True, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangps.plist"
            )

            with self.assertRaises(NativeClientConflict):
                manager.restore_auto_launch(record_path)

        self.assertEqual(store.set_calls, [])

    def test_restore_reenables_exact_recorded_disabled_target(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangps", "launchd", True, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangps.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "native-suppression.json"
            manager = NativeAutoLaunchManager(store=store)
            manager.suppress_auto_launch(record_path)
            manager.restore_auto_launch(record_path)

        self.assertEqual(store.set_calls, [
            ("com.paloaltonetworks.gp.pangps", False),
            ("com.paloaltonetworks.gp.pangps", True),
        ])

    def test_real_native_connected_or_connecting_blocks_openconnect_but_disabled_hyu_allows_manual_recovery(self):
        self.assertTrue(NativeClientState(processes={"PanGPS"}, route_interface="utun2", status="connected", hyu_enabled=True).blocks_openconnect())
        self.assertTrue(NativeClientState(processes={"GlobalProtect"}, route_interface=None, status="connecting", hyu_enabled=True).blocks_openconnect())
        self.assertFalse(NativeClientState(processes={"GlobalProtect"}, route_interface="utun2", status="connected", hyu_enabled=False).blocks_openconnect())

    def test_ambiguous_or_non_globalprotect_mechanisms_are_not_changed(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.unknown", "launchd", True, "/Library/LaunchDaemons/com.paloaltonetworks.gp.unknown.plist"),
            AutoLaunchMechanism("com.example.GlobalProtectHelper", "login-item", True, "/Applications/Example.app"),
        ])
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(NativeClientConflict):
                NativeAutoLaunchManager(store=store).suppress_auto_launch(Path(td) / "record.json")

        self.assertEqual(store.set_calls, [])


if __name__ == "__main__":
    unittest.main()

class FakeStat:
    def __init__(self, *, st_uid=0, st_mode=0o100644, st_mtime=1000):
        self.st_uid = st_uid
        self.st_mode = st_mode
        self.st_mtime = st_mtime


class FakePlistFS:
    def __init__(self, plists, *, symlinks=None, stats=None, log_text="", log_stat=None):
        self.plists = dict(plists)
        self.symlinks = set(symlinks or [])
        self.stats = stats or {}
        self.log_text = log_text
        self.log_stat = log_stat or FakeStat(st_mtime=1000)

    def is_file(self, path):
        return str(path) in self.plists or str(path).endswith("PanGPA.log")

    def is_symlink(self, path):
        return str(path) in self.symlinks

    def stat(self, path):
        if str(path).endswith("PanGPA.log"):
            return self.log_stat
        return self.stats.get(str(path), FakeStat())

    def read_plist(self, path):
        return self.plists[str(path)]

    def read_text(self, path):
        return self.log_text

    def open_binary(self, path):
        import io
        return io.BytesIO(self.log_text.encode("utf-8", errors="replace"))


class MacOSProductionNativeClientTests(unittest.TestCase):
    def test_macos_store_validates_exact_plists_and_uses_fixed_launchctl_domains(self):
        from hyu_vpn.native_client import MacOSLaunchctlAutoLaunchStore, production_auto_launch_manager

        plists = {
            "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist": {
                "Label": "com.paloaltonetworks.gp.pangpsd",
                "Program": "/Applications/GlobalProtect.app/Contents/Resources/PanGPS",
            },
            "/Library/LaunchAgents/com.paloaltonetworks.gp.pangpa.plist": {
                "Label": "com.paloaltonetworks.gp.pangpa",
                "Program": "/Applications/GlobalProtect.app/Contents/MacOS/GlobalProtect",
            },
            "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist": {
                "Label": "com.paloaltonetworks.gp.pangps",
                "Program": "/Applications/GlobalProtect.app/Contents/Resources/PanGPS",
            },
        }
        calls = []

        def runner(argv, timeout):
            calls.append(tuple(argv))
            if argv == ["/bin/launchctl", "print-disabled", "system"]:
                return type("R", (), {"returncode": 0, "stdout": '"com.paloaltonetworks.gp.pangpsd" => false\n', "stderr": ""})()
            if argv == ["/bin/launchctl", "print-disabled", "gui/501"]:
                return type("R", (), {"returncode": 0, "stdout": '"com.paloaltonetworks.gp.pangpa" => true\n"com.paloaltonetworks.gp.pangps" => false\n', "stderr": ""})()
            return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        store = MacOSLaunchctlAutoLaunchStore(console_uid=501, fs=FakePlistFS(plists), runner=runner)

        mechanisms = store.list_mechanisms()
        store.set_enabled("com.paloaltonetworks.gp.pangps", False)
        manager = production_auto_launch_manager(console_uid=501, fs=FakePlistFS(plists), runner=runner)

        self.assertIsInstance(manager.store, MacOSLaunchctlAutoLaunchStore)
        self.assertEqual([(m.identifier, m.kind, m.enabled, m.exact_target) for m in mechanisms], [
            ("com.paloaltonetworks.gp.pangpsd", "launchd-system", True, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
            ("com.paloaltonetworks.gp.pangpa", "launchd-gui", False, "/Library/LaunchAgents/com.paloaltonetworks.gp.pangpa.plist"),
            ("com.paloaltonetworks.gp.pangps", "launchd-gui", True, "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"),
        ])
        self.assertIn(("/bin/launchctl", "disable", "gui/501/com.paloaltonetworks.gp.pangps"), calls)
        self.assertNotIn(("launchctl", "disable", "gui/501/com.paloaltonetworks.gp.pangps"), calls)


    def test_macos_store_accepts_exact_program_or_matching_program_arguments_only(self):
        from hyu_vpn.native_client import MacOSLaunchctlAutoLaunchStore, NativeClientConflict

        path = "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"
        expected_program = "/Applications/GlobalProtect.app/Contents/Resources/PanGPS"
        runner = lambda argv, timeout: type("R", (), {"returncode": 0, "stdout": '"com.paloaltonetworks.gp.pangpsd" => false\n', "stderr": ""})()

        matching = FakePlistFS({path: {"Label": "com.paloaltonetworks.gp.pangpsd", "Program": expected_program, "ProgramArguments": [expected_program, "--flag"]}})
        mechanisms = MacOSLaunchctlAutoLaunchStore(console_uid=501, fs=matching, runner=runner).list_mechanisms()
        self.assertEqual(mechanisms[0].identifier, "com.paloaltonetworks.gp.pangpsd")

        basename_only = FakePlistFS({path: {"Label": "com.paloaltonetworks.gp.pangpsd", "Program": "/tmp/PanGPS"}})
        with self.assertRaises(NativeClientConflict):
            MacOSLaunchctlAutoLaunchStore(console_uid=501, fs=basename_only, runner=runner).list_mechanisms()

        disagree = FakePlistFS({path: {"Label": "com.paloaltonetworks.gp.pangpsd", "Program": expected_program, "ProgramArguments": ["/tmp/PanGPS"]}})
        with self.assertRaises(NativeClientConflict):
            MacOSLaunchctlAutoLaunchStore(console_uid=501, fs=disagree, runner=runner).list_mechanisms()

    def test_macos_store_rejects_symlink_wrong_owner_mode_or_label(self):
        from hyu_vpn.native_client import MacOSLaunchctlAutoLaunchStore, NativeClientConflict

        base = "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"
        valid = {base: {"Label": "com.paloaltonetworks.gp.pangpsd", "ProgramArguments": ["/Applications/GlobalProtect.app/Contents/Resources/PanGPS"]}}
        cases = [
            FakePlistFS(valid, symlinks={base}),
            FakePlistFS(valid, stats={base: FakeStat(st_uid=501)}),
            FakePlistFS(valid, stats={base: FakeStat(st_mode=0o100666)}),
            FakePlistFS({base: {"Label": "wrong", "ProgramArguments": ["/Applications/GlobalProtect.app/Contents/Resources/PanGPS"]}}),
        ]
        for fs in cases:
            with self.subTest(fs=fs):
                with self.assertRaises(NativeClientConflict):
                    MacOSLaunchctlAutoLaunchStore(console_uid=501, fs=fs, runner=lambda *_: None).list_mechanisms()

    def test_record_schema_validates_exact_keys_and_empty_snapshot(self):
        store = FakeAutoLaunchStore([])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            manager = NativeAutoLaunchManager(store=store, console_uid=501)
            manager.suppress_auto_launch(record_path)
            data = json.loads(record_path.read_text(encoding="utf-8"))
            self.assertEqual(data, {"schema_version": 1, "console_uid": 501, "mechanisms": []})

            record_path.write_text(json.dumps({"schema_version": 1, "console_uid": 501, "mechanisms": [], "extra": True}), encoding="utf-8")
            with self.assertRaises(NativeClientConflict):
                manager.restore_auto_launch(record_path)


    def test_restore_rejects_cross_user_record_console_uid(self):
        store = FakeAutoLaunchStore([])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({"schema_version": 1, "console_uid": 502, "mechanisms": []}), encoding="utf-8")

            with self.assertRaises(NativeClientConflict):
                NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)

    def test_restore_validates_all_record_items_before_any_change(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", False, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangps", "launchd-gui", False, "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({
                "schema_version": 1,
                "console_uid": 501,
                "mechanisms": [
                    {"identifier": "com.paloaltonetworks.gp.pangpsd", "kind": "launchd-system", "enabled": True, "exact_target": "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"},
                    {"identifier": "com.paloaltonetworks.gp.pangps", "kind": "launchd-gui", "enabled": True, "exact_target": "/changed.plist"},
                ],
            }), encoding="utf-8")

            with self.assertRaises(NativeClientConflict):
                NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)

        self.assertEqual(store.set_calls, [])


    def test_pangpa_status_reader_uses_bounded_binary_tail_and_strict_state_tokens(self):
        from hyu_vpn.native_client import GlobalProtectStatusReader

        class BinaryLogFS:
            def __init__(self, payload):
                self.payload = payload
                self.read_text_called = False
            def stat(self, path):
                return FakeStat(st_mtime=1000)
            def open_binary(self, path):
                import io
                return io.BytesIO(self.payload)
            def read_text(self, path):
                self.read_text_called = True
                raise AssertionError("unbounded read_text must not be used")

        payload = b"phrase Connected should not count\n" + (b"x" * 100) + b"<state>Disconnected</state>\nSTATE_TUNNEL_CONNECTING\n"
        fs = BinaryLogFS(payload)
        reader = GlobalProtectStatusReader(path=Path("PanGPA.log"), fs=fs, clock=lambda: 1000, max_age=30, max_bytes=64)

        self.assertEqual(reader.read_state(), "connecting")
        self.assertFalse(fs.read_text_called)

        false_positive = BinaryLogFS(b"user clicked Connected button but no XML/token\n")
        self.assertEqual(GlobalProtectStatusReader(path=Path("PanGPA.log"), fs=false_positive, clock=lambda: 1000, max_age=30).read_state(), "unknown")

    def test_pangpa_status_reader_uses_latest_fresh_bounded_state_without_persisting_raw_log(self):
        from hyu_vpn.native_client import GlobalProtectStatusReader

        fs = FakePlistFS({}, log_text="old <state>Disconnected</state>\nnew <state>Connecting</state>\n", log_stat=FakeStat(st_mtime=990))
        reader = GlobalProtectStatusReader(path=Path.home() / "Library/Logs/PaloAltoNetworks/GlobalProtect/PanGPA.log", fs=fs, clock=lambda: 1000, max_age=30)
        self.assertEqual(reader.read_state(), "connecting")

        stale = FakePlistFS({}, log_text="<state>Connecting</state>\n", log_stat=FakeStat(st_mtime=900))
        self.assertEqual(GlobalProtectStatusReader(path=Path("PanGPA.log"), fs=stale, clock=lambda: 1000, max_age=30).read_state(), "unknown")
