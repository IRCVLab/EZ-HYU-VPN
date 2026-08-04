import json
import tempfile
import unittest
from unittest import mock
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
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangps", "launchd-gui", True, "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"),
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
            "kind": "launchd-gui",
            "enabled": True,
            "exact_target": "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist",
        }])
        self.assertNotIn("com.example.unrelated", json.dumps(record))

    def test_restore_only_unchanged_recorded_targets_and_refuses_user_modified_state(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangps", "launchd-gui", False, "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "native-suppression.json"
            manager = NativeAutoLaunchManager(store=store)
            manager.suppress_auto_launch(record_path)
            store.mechanisms["com.paloaltonetworks.gp.pangps"] = AutoLaunchMechanism(
                "com.paloaltonetworks.gp.pangps", "launchd-gui", True, "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"
            )

            with self.assertRaises(NativeClientConflict):
                manager.restore_auto_launch(record_path)

        self.assertEqual(store.set_calls, [])

    def test_restore_reenables_exact_recorded_disabled_target(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangps", "launchd-gui", True, "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"),
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

    def test_known_globalprotect_identifier_with_wrong_absolute_target_is_rejected_before_mutation(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism(
                "com.paloaltonetworks.gp.pangpsd",
                "launchd-system",
                True,
                "/tmp/com.paloaltonetworks.gp.pangpsd.plist",
            ),
        ])
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(NativeClientConflict):
                NativeAutoLaunchManager(store=store, console_uid=501).suppress_auto_launch(Path(td) / "record.json")

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



    def test_restore_recovers_interrupted_disabling_journal_using_applied_targets_only(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", False, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangps", "launchd-gui", True, "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({
                "schema_version": 1,
                "console_uid": 501,
                "phase": "disabling",
                "pending_identifier": None,
                "applied_identifiers": ["com.paloaltonetworks.gp.pangpsd"],
                "mechanisms": [
                    {"identifier": "com.paloaltonetworks.gp.pangpsd", "kind": "launchd-system", "enabled": True, "exact_target": "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"},
                    {"identifier": "com.paloaltonetworks.gp.pangps", "kind": "launchd-gui", "enabled": True, "exact_target": "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"},
                ],
            }), encoding="utf-8")

            NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)

            self.assertFalse(record_path.exists())
        self.assertEqual(store.set_calls, [("com.paloaltonetworks.gp.pangpsd", True)])

    def test_restore_recovers_interrupted_rolling_back_journal_in_reverse_and_advances_phase(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", False, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangps", "launchd-gui", False, "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            mechanisms = [
                {"identifier": "com.paloaltonetworks.gp.pangpsd", "kind": "launchd-system", "enabled": True, "exact_target": "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"},
                {"identifier": "com.paloaltonetworks.gp.pangps", "kind": "launchd-gui", "enabled": True, "exact_target": "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"},
            ]
            record_path.write_text(json.dumps({"schema_version": 1, "console_uid": 501, "phase": "rolling-back", "pending_identifier": None, "applied_identifiers": ["com.paloaltonetworks.gp.pangpsd", "com.paloaltonetworks.gp.pangps"], "mechanisms": mechanisms}), encoding="utf-8")

            NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)

            self.assertFalse(record_path.exists())
        self.assertEqual(store.set_calls, [
            ("com.paloaltonetworks.gp.pangps", True),
            ("com.paloaltonetworks.gp.pangpsd", True),
        ])

    def test_restore_removes_preparing_empty_journal_as_safe_noop(self):
        store = FakeAutoLaunchStore([])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({"schema_version": 1, "console_uid": 501, "phase": "preparing", "pending_identifier": None, "applied_identifiers": [], "mechanisms": []}), encoding="utf-8")

            NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)

            self.assertFalse(record_path.exists())
        self.assertEqual(store.set_calls, [])

    def test_restore_removes_completed_rolling_back_journal_as_safe_noop(self):
        store = FakeAutoLaunchStore([])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({"schema_version": 1, "console_uid": 501, "phase": "rolling-back", "pending_identifier": None, "applied_identifiers": [], "mechanisms": []}), encoding="utf-8")

            NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)

            self.assertFalse(record_path.exists())
        self.assertEqual(store.set_calls, [])

    def test_restore_rejects_impossible_interrupted_journal_combinations(self):
        store = FakeAutoLaunchStore([])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({"schema_version": 1, "console_uid": 501, "phase": "preparing", "pending_identifier": None, "applied_identifiers": ["com.paloaltonetworks.gp.pangpsd"], "mechanisms": [{"identifier": "com.paloaltonetworks.gp.pangpsd", "kind": "launchd-system", "enabled": True, "exact_target": "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"}]}), encoding="utf-8")

            with self.assertRaises(NativeClientConflict):
                NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)


    def test_restore_recovers_retained_rollback_required_with_pending_after_snapshot_later_recovers(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", False, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({
                "schema_version": 1,
                "console_uid": 501,
                "phase": "rollback-required",
                "pending_identifier": "com.paloaltonetworks.gp.pangpsd",
                "applied_identifiers": [],
                "mechanisms": [{"identifier": "com.paloaltonetworks.gp.pangpsd", "kind": "launchd-system", "enabled": True, "exact_target": "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"}],
            }), encoding="utf-8")

            NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)

            self.assertFalse(record_path.exists())
        self.assertEqual(store.set_calls, [("com.paloaltonetworks.gp.pangpsd", True)])

    def test_restore_retains_rollback_required_when_interrupted_journal_recovery_fails(self):
        class FailingRestoreStore(FakeAutoLaunchStore):
            def set_enabled(self, identifier, enabled):
                raise NativeClientConflict("restore failed")

        store = FailingRestoreStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", False, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({"schema_version": 1, "console_uid": 501, "phase": "disabling", "pending_identifier": None, "applied_identifiers": ["com.paloaltonetworks.gp.pangpsd"], "mechanisms": [{"identifier": "com.paloaltonetworks.gp.pangpsd", "kind": "launchd-system", "enabled": True, "exact_target": "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"}]}), encoding="utf-8")

            with self.assertRaises(NativeClientConflict):
                NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)
            journal = json.loads(record_path.read_text(encoding="utf-8"))

        self.assertEqual(journal["phase"], "rollback-required")
        self.assertEqual(journal["applied_identifiers"], ["com.paloaltonetworks.gp.pangpsd"])


    def test_restore_removes_disabling_empty_no_pending_as_safe_noop(self):
        store = FakeAutoLaunchStore([])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({"schema_version": 1, "console_uid": 501, "phase": "disabling", "pending_identifier": None, "applied_identifiers": [], "mechanisms": []}), encoding="utf-8")

            NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)

            self.assertFalse(record_path.exists())
        self.assertEqual(store.set_calls, [])

    def test_restore_removes_rolling_back_empty_no_pending_as_safe_completion(self):
        store = FakeAutoLaunchStore([])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({"schema_version": 1, "console_uid": 501, "phase": "rolling-back", "pending_identifier": None, "applied_identifiers": [], "mechanisms": []}), encoding="utf-8")

            NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)

            self.assertFalse(record_path.exists())
        self.assertEqual(store.set_calls, [])

    def test_restore_treats_pending_disabled_target_as_owned_effect_and_restores_it(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", False, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({
                "schema_version": 1,
                "console_uid": 501,
                "phase": "disabling",
                "pending_identifier": "com.paloaltonetworks.gp.pangpsd",
                "applied_identifiers": [],
                "mechanisms": [{"identifier": "com.paloaltonetworks.gp.pangpsd", "kind": "launchd-system", "enabled": True, "exact_target": "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"}],
            }), encoding="utf-8")

            NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)

            self.assertFalse(record_path.exists())
        self.assertEqual(store.set_calls, [("com.paloaltonetworks.gp.pangpsd", True)])

    def test_restore_treats_pending_enabled_target_as_no_effect(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", True, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({
                "schema_version": 1,
                "console_uid": 501,
                "phase": "disabling",
                "pending_identifier": "com.paloaltonetworks.gp.pangpsd",
                "applied_identifiers": [],
                "mechanisms": [{"identifier": "com.paloaltonetworks.gp.pangpsd", "kind": "launchd-system", "enabled": True, "exact_target": "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"}],
            }), encoding="utf-8")

            NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)

            self.assertFalse(record_path.exists())
        self.assertEqual(store.set_calls, [])

    def test_restore_rejects_impossible_pending_already_applied_combination(self):
        store = FakeAutoLaunchStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", False, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            record_path.write_text(json.dumps({
                "schema_version": 1,
                "console_uid": 501,
                "phase": "disabling",
                "pending_identifier": "com.paloaltonetworks.gp.pangpsd",
                "applied_identifiers": ["com.paloaltonetworks.gp.pangpsd"],
                "mechanisms": [{"identifier": "com.paloaltonetworks.gp.pangpsd", "kind": "launchd-system", "enabled": True, "exact_target": "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"}],
            }), encoding="utf-8")

            with self.assertRaises(NativeClientConflict):
                NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)


    def test_suppress_rolls_back_pending_when_disable_applies_then_raises(self):
        class AppliesThenRaisesStore(FakeAutoLaunchStore):
            def set_enabled(self, identifier, enabled):
                super().set_enabled(identifier, enabled)
                if identifier == "com.paloaltonetworks.gp.pangpsd" and enabled is False:
                    raise NativeClientConflict("transport timeout after disable")

        store = AppliesThenRaisesStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", True, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            with self.assertRaises(NativeClientConflict):
                NativeAutoLaunchManager(store=store, console_uid=501).suppress_auto_launch(record_path)

            self.assertFalse(record_path.exists())

        self.assertEqual(store.set_calls, [
            ("com.paloaltonetworks.gp.pangpsd", False),
            ("com.paloaltonetworks.gp.pangpsd", True),
        ])


    def test_suppress_snapshot_failure_retained_pending_journal_is_later_restorable(self):
        class ToggleSnapshotStore(FakeAutoLaunchStore):
            def __init__(self, mechanisms):
                super().__init__(mechanisms)
                self.fail_snapshot = False
            def set_enabled(self, identifier, enabled):
                super().set_enabled(identifier, enabled)
                if identifier == "com.paloaltonetworks.gp.pangpsd" and enabled is False:
                    self.fail_snapshot = True
                    raise NativeClientConflict("transport timeout after disable")
            def list_mechanisms(self):
                if self.fail_snapshot:
                    raise NativeClientConflict("snapshot failed")
                return super().list_mechanisms()

        store = ToggleSnapshotStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", True, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            with self.assertRaises(NativeClientConflict):
                NativeAutoLaunchManager(store=store, console_uid=501).suppress_auto_launch(record_path)

            retained = json.loads(record_path.read_text(encoding="utf-8"))
            self.assertEqual(retained["phase"], "rollback-required")
            self.assertEqual(retained["pending_identifier"], "com.paloaltonetworks.gp.pangpsd")
            self.assertEqual(retained["applied_identifiers"], [])

            store.fail_snapshot = False
            NativeAutoLaunchManager(store=store, console_uid=501).restore_auto_launch(record_path)

            self.assertFalse(record_path.exists())
        self.assertEqual(store.set_calls, [
            ("com.paloaltonetworks.gp.pangpsd", False),
            ("com.paloaltonetworks.gp.pangpsd", True),
        ])

    def test_suppress_retains_rollback_required_when_pending_snapshot_fails_after_disable_error(self):
        class SnapshotFailsAfterDisableStore(FakeAutoLaunchStore):
            def __init__(self, mechanisms):
                super().__init__(mechanisms)
                self.fail_snapshot = False
            def set_enabled(self, identifier, enabled):
                super().set_enabled(identifier, enabled)
                if identifier == "com.paloaltonetworks.gp.pangpsd" and enabled is False:
                    self.fail_snapshot = True
                    raise NativeClientConflict("transport timeout after disable")
            def list_mechanisms(self):
                if self.fail_snapshot:
                    raise NativeClientConflict("snapshot failed")
                return super().list_mechanisms()

        store = SnapshotFailsAfterDisableStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", True, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            with self.assertRaises(NativeClientConflict):
                NativeAutoLaunchManager(store=store, console_uid=501).suppress_auto_launch(record_path)
            journal = json.loads(record_path.read_text(encoding="utf-8"))

        self.assertEqual(journal["phase"], "rollback-required")
        self.assertEqual(journal["pending_identifier"], "com.paloaltonetworks.gp.pangpsd")
        self.assertEqual(journal["applied_identifiers"], [])

    def test_suppress_journals_pending_identifier_before_external_disable(self):
        snapshots = []
        class InspectingStore(FakeAutoLaunchStore):
            def __init__(self, mechanisms, record_path):
                super().__init__(mechanisms)
                self.record_path = record_path
            def set_enabled(self, identifier, enabled):
                snapshots.append(json.loads(self.record_path.read_text(encoding="utf-8")))
                super().set_enabled(identifier, enabled)

        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            store = InspectingStore([
                AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", True, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
            ], record_path)

            NativeAutoLaunchManager(store=store, console_uid=501).suppress_auto_launch(record_path)

        self.assertEqual(snapshots[0]["phase"], "disabling")
        self.assertEqual(snapshots[0]["pending_identifier"], "com.paloaltonetworks.gp.pangpsd")
        self.assertEqual(snapshots[0]["applied_identifiers"], [])

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



    def test_suppress_auto_launch_rolls_back_applied_targets_when_later_disable_fails(self):
        class FailingSecondDisableStore(FakeAutoLaunchStore):
            def set_enabled(self, identifier, enabled):
                if identifier == "com.paloaltonetworks.gp.pangps" and enabled is False:
                    raise NativeClientConflict("disable failed")
                super().set_enabled(identifier, enabled)

        store = FailingSecondDisableStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", True, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangps", "launchd-gui", True, "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            with self.assertRaises(NativeClientConflict):
                NativeAutoLaunchManager(store=store, console_uid=501).suppress_auto_launch(record_path)

            self.assertFalse(record_path.exists())

        self.assertEqual(store.set_calls, [
            ("com.paloaltonetworks.gp.pangpsd", False),
            ("com.paloaltonetworks.gp.pangpsd", True),
        ])

    def test_suppress_auto_launch_retains_rollback_required_journal_when_rollback_fails_and_restore_uses_applied_only(self):
        class RollbackFailStore(FakeAutoLaunchStore):
            def set_enabled(self, identifier, enabled):
                if identifier == "com.paloaltonetworks.gp.pangps" and enabled is False:
                    raise NativeClientConflict("disable failed")
                if identifier == "com.paloaltonetworks.gp.pangpsd" and enabled is True:
                    raise NativeClientConflict("rollback failed")
                super().set_enabled(identifier, enabled)

        store = RollbackFailStore([
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", True, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
            AutoLaunchMechanism("com.paloaltonetworks.gp.pangps", "launchd-gui", True, "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"),
        ])
        with tempfile.TemporaryDirectory() as td:
            record_path = Path(td) / "record.json"
            with self.assertRaises(NativeClientConflict):
                NativeAutoLaunchManager(store=store, console_uid=501).suppress_auto_launch(record_path)
            journal = json.loads(record_path.read_text(encoding="utf-8"))

            self.assertEqual(journal["phase"], "rollback-required")
            self.assertEqual(journal["applied_identifiers"], ["com.paloaltonetworks.gp.pangpsd"])

            restore_store = FakeAutoLaunchStore([
                AutoLaunchMechanism("com.paloaltonetworks.gp.pangpsd", "launchd-system", False, "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist"),
                AutoLaunchMechanism("com.paloaltonetworks.gp.pangps", "launchd-gui", True, "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist"),
            ])
            NativeAutoLaunchManager(store=restore_store, console_uid=501).restore_auto_launch(record_path)

        self.assertEqual(restore_store.set_calls, [("com.paloaltonetworks.gp.pangpsd", True)])

    def test_production_suppress_restore_entrypoints_construct_manager(self):
        from hyu_vpn.native_client import suppress_globalprotect_auto_launch, restore_globalprotect_auto_launch
        with mock.patch("hyu_vpn.native_client.production_auto_launch_manager") as factory:
            suppress_globalprotect_auto_launch("/tmp/record.json", console_uid=501, fs=mock.sentinel.fs, runner=mock.sentinel.runner)
            restore_globalprotect_auto_launch("/tmp/record.json", console_uid=501, fs=mock.sentinel.fs, runner=mock.sentinel.runner)

        factory.assert_has_calls([
            mock.call(console_uid=501, fs=mock.sentinel.fs, runner=mock.sentinel.runner),
            mock.call().suppress_auto_launch("/tmp/record.json"),
            mock.call(console_uid=501, fs=mock.sentinel.fs, runner=mock.sentinel.runner),
            mock.call().restore_auto_launch("/tmp/record.json"),
        ])

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
