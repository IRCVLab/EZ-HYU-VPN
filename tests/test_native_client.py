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
