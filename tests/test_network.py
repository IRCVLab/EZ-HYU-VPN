import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.network import NetworkReadiness, OwnedSessionEvidence, route_interface
from hyu_vpn.supervisor import CommandResult, NativeConflictDetector


class FakeClock:
    def __init__(self, values=None):
        self.values = list(values or [])
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        if self.values:
            self.now = self.values.pop(0)
        return self.now

    def sleep(self, delay):
        self.sleeps.append(delay)
        self.now += delay


class NetworkReadinessTests(unittest.TestCase):
    def test_requires_repeated_stable_default_route_and_dns_probes(self):
        calls = []
        route_outputs = [
            "gateway: 192.0.2.1\ninterface: en0\n",
            "gateway: 192.0.2.1\ninterface: en0\n",
        ]

        def runner(argv, timeout):
            calls.append(tuple(argv))
            if argv[:3] == ["/sbin/route", "-n", "get"]:
                return CommandResult(tuple(argv), 0, route_outputs.pop(0), "")
            if argv[:2] == ["/usr/bin/dig", "+short"]:
                return CommandResult(tuple(argv), 0, "166.104.1.1\n", "")
            raise AssertionError(argv)

        clock = FakeClock()
        readiness = NetworkReadiness(command_runner=runner, sleep=clock.sleep, stable_samples=2, poll_interval=3)

        self.assertTrue(readiness.wait_until_ready(max_attempts=2))
        self.assertEqual(clock.sleeps, [3])
        self.assertEqual(calls, [
            ("/sbin/route", "-n", "get", "default"),
            ("/usr/bin/dig", "+short", "secure.hanyang.ac.kr"),
            ("/sbin/route", "-n", "get", "default"),
            ("/usr/bin/dig", "+short", "secure.hanyang.ac.kr"),
        ])

    def test_route_or_dns_failures_wait_instead_of_spinning(self):
        route_outputs = [
            CommandResult(("route",), 1, "", "network down"),
            CommandResult(("route",), 0, "gateway: 192.0.2.1\ninterface: en0\n", ""),
            CommandResult(("route",), 0, "gateway: 192.0.2.1\ninterface: en0\n", ""),
            CommandResult(("route",), 0, "gateway: 192.0.2.1\ninterface: en0\n", ""),
        ]
        dns_outputs = [
            CommandResult(("dig",), 1, "", "timeout"),
            CommandResult(("dig",), 0, "166.104.1.1\n", ""),
            CommandResult(("dig",), 0, "166.104.1.1\n", ""),
        ]

        def runner(argv, timeout):
            if argv[:3] == ["/sbin/route", "-n", "get"]:
                return route_outputs.pop(0)
            return dns_outputs.pop(0)

        clock = FakeClock()
        readiness = NetworkReadiness(command_runner=runner, sleep=clock.sleep, stable_samples=2, poll_interval=5)

        self.assertTrue(readiness.wait_until_ready(max_attempts=4))
        self.assertEqual(clock.sleeps, [5, 5, 5])

    def test_sleep_wake_clock_jump_resets_stability_and_sleeps(self):
        routes = [
            "gateway: 192.0.2.1\ninterface: en0\n",
            "gateway: 192.0.2.1\ninterface: en0\n",
            "gateway: 192.0.2.1\ninterface: en0\n",
        ]

        def runner(argv, timeout):
            if argv[:3] == ["/sbin/route", "-n", "get"]:
                return CommandResult(tuple(argv), 0, routes.pop(0), "")
            return CommandResult(tuple(argv), 0, "166.104.1.1\n", "")

        clock = FakeClock(values=[0.0, 120.0, 121.0])
        readiness = NetworkReadiness(command_runner=runner, monotonic=clock.monotonic, sleep=clock.sleep, stable_samples=2, poll_interval=2, wake_gap=30)

        self.assertTrue(readiness.wait_until_ready(max_attempts=3))
        self.assertEqual(clock.sleeps, [2, 2])

    def test_helper_owned_utun_is_not_a_native_conflict_but_foreign_utun_is(self):
        owned = OwnedSessionEvidence(interfaces={"utun4"})
        self.assertEqual(route_interface("interface: utun4\n"), "utun4")

        def runner(argv, timeout):
            if argv == ["/bin/ps", "-axo", "comm="]:
                return CommandResult(tuple(argv), 0, "/Applications/GlobalProtect.app/Contents/MacOS/PanGPS\n", "")
            return CommandResult(tuple(argv), 0, "interface: utun4\n", "")

        self.assertFalse(NativeConflictDetector(command_runner=runner, owned_session=owned).conflict_active())

        def foreign_runner(argv, timeout):
            if argv == ["/bin/ps", "-axo", "comm="]:
                return CommandResult(tuple(argv), 0, "/Applications/GlobalProtect.app/Contents/MacOS/PanGPS\n", "")
            return CommandResult(tuple(argv), 0, "interface: utun7\n", "")

        self.assertTrue(NativeConflictDetector(command_runner=foreign_runner, owned_session=owned).conflict_active())


if __name__ == "__main__":
    unittest.main()

class HelperOwnedSessionProviderTests(unittest.TestCase):
    def test_helper_status_provider_accepts_only_strict_running_one_line_json(self):
        from hyu_vpn.network import HelperOwnedSessionProvider
        calls = []

        def runner(argv, timeout):
            calls.append((tuple(argv), timeout))
            return CommandResult(tuple(argv), 0, '{"schema_version":1,"state":"running","pid":123,"session_nonce":"abc-DEF_123","tunnel_interface":"utun4"}\n', "")

        evidence = HelperOwnedSessionProvider(command_runner=runner, timeout=1.5).evidence()

        self.assertTrue(evidence.owns_interface("utun4"))
        self.assertEqual(calls, [(("/usr/bin/sudo", "-n", "/Library/PrivilegedHelperTools/com.hyu.vpn.helper", "status"), 1.5)])

        max_width = HelperOwnedSessionProvider(command_runner=lambda argv, timeout: CommandResult(tuple(argv), 0, '{"schema_version":1,"state":"running","pid":123,"session_nonce":"abc","tunnel_interface":"utun12345678"}\n', "")).evidence()
        self.assertTrue(max_width.owns_interface("utun12345678"))

    def test_helper_status_provider_rejects_malformed_nonzero_or_unsafe_fields(self):
        from hyu_vpn.network import HelperOwnedSessionProvider
        bad_outputs = [
            (1, '{"schema_version":1,"state":"running","pid":123,"session_nonce":"abc","tunnel_interface":"utun4"}\n'),
            (0, '{"schema_version":1,"state":"running","pid":123,"session_nonce":"abc","tunnel_interface":"utun4"}\nextra'),
            (0, '{"schema_version":1,"state":"stopped","pid":123,"session_nonce":"abc","tunnel_interface":"utun4"}\n'),
            (0, '{"schema_version":1,"state":"running","pid":0,"session_nonce":"abc","tunnel_interface":"utun4"}\n'),
            (0, '{"schema_version":1,"state":"running","pid":123,"session_nonce":"bad space","tunnel_interface":"utun4"}\n'),
            (0, '{"schema_version":1,"state":"running","pid":123,"session_nonce":"abc","tunnel_interface":"en0"}\n'),
            (0, '{"schema_version":1,"state":"running","pid":123,"session_nonce":"abc","tunnel_interface":"utun123456789"}\n'),
        ]
        for returncode, stdout in bad_outputs:
            with self.subTest(stdout=stdout):
                provider = HelperOwnedSessionProvider(command_runner=lambda argv, timeout, r=returncode, s=stdout: CommandResult(tuple(argv), r, s, ""))
                self.assertFalse(provider.evidence().interfaces)
