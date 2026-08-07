import ast
import fcntl
import io
import json
import os
import stat
import signal
import subprocess
import threading
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.network import OwnedSessionEvidence
from hyu_vpn.control import AutoReconnectPreference
from hyu_vpn.supervisor import CommandResult, NativeConflictDetector, ReconnectPolicy, Supervisor, SupervisorConfig, main


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, delay):
        self.sleeps.append(delay)
        self.now += delay


class ReconnectPolicyTests(unittest.TestCase):
    def test_backoff_sequence_caps_at_120_seconds(self):
        policy = ReconnectPolicy()
        self.assertEqual([policy.next_delay(i) for i in range(1, 8)], [10, 20, 40, 80, 120, 120, 120])

    def test_session_runtime_at_least_five_minutes_resets_failure_count(self):
        policy = ReconnectPolicy()
        self.assertEqual(policy.record_exit(1, runtime_seconds=12), 1)
        self.assertEqual(policy.record_exit(1, runtime_seconds=299), 2)
        self.assertEqual(policy.record_exit(1, runtime_seconds=300), 0)
        self.assertEqual(policy.next_delay(policy.record_exit(1, runtime_seconds=1)), 10)

    def test_explicit_reset_clears_failure_count(self):
        policy = ReconnectPolicy()
        self.assertEqual(policy.record_exit(1, runtime_seconds=1), 1)

        policy.reset()

        self.assertEqual(policy.consecutive_failures, 0)


class NativeConflictDetectorTests(unittest.TestCase):
    def test_detects_conflict_only_when_native_process_and_protected_utun_route_exist(self):
        calls = []
        def runner(argv, timeout):
            calls.append((tuple(argv), timeout))
            if argv == ["/bin/ps", "-axo", "comm="]:
                return CommandResult(tuple(argv), 0, "/Applications/GlobalProtect.app/Contents/MacOS/PanGPS\n/usr/sbin/syslogd\n", "")
            if argv == ["/sbin/route", "-n", "get", "166.104.100.100"]:
                return CommandResult(tuple(argv), 0, "route to: 166.104.100.100\ninterface: utun4\n", "")
            raise AssertionError(argv)

        detector = NativeConflictDetector(command_runner=runner)

        self.assertTrue(detector.conflict_active())
        self.assertEqual(calls, [
            (("/bin/ps", "-axo", "comm="), 2.0),
            (("/sbin/route", "-n", "get", "166.104.100.100"), 2.0),
        ])

    def test_does_not_suppress_without_both_process_and_utun_route(self):
        cases = [
            ("/Applications/GlobalProtect.app/Contents/MacOS/PanGPS\n", "interface: en0\n"),
            ("/usr/sbin/syslogd\n", "interface: utun5\n"),
            ("", "interface: utun5\n"),
            ("/Applications/GlobalProtect.app/Contents/MacOS/PanGPS\n", "malformed\n"),
            ("/tmp/notGlobalProtectButContainsGlobalProtectHelper\n", "interface: utun5\n"),
        ]
        for processes, route in cases:
            with self.subTest(processes=processes, route=route):
                def runner(argv, timeout):
                    if argv == ["/bin/ps", "-axo", "comm="]:
                        return CommandResult(tuple(argv), 0, processes, "secret process stderr")
                    if argv == ["/sbin/route", "-n", "get", "166.104.100.100"]:
                        return CommandResult(tuple(argv), 0, route, "secret route stderr")
                    raise AssertionError(argv)

                self.assertFalse(NativeConflictDetector(command_runner=runner).conflict_active())



    def test_refreshes_helper_owned_evidence_on_every_conflict_check(self):
        evidences = iter([OwnedSessionEvidence(interfaces={"utun4"}), OwnedSessionEvidence(interfaces={"utun7"})])
        routes = iter(["interface: utun4\n", "interface: utun4\n"])
        def runner(argv, timeout):
            if argv == ["/bin/ps", "-axo", "comm="]:
                return CommandResult(tuple(argv), 0, "/Applications/GlobalProtect.app/Contents/MacOS/PanGPS\n", "")
            return CommandResult(tuple(argv), 0, next(routes), "")

        detector = NativeConflictDetector(command_runner=runner, owned_session_provider=lambda: next(evidences), native_status=lambda: "connected")

        self.assertFalse(detector.conflict_active())
        self.assertTrue(detector.conflict_active())

    def test_later_malformed_helper_evidence_fails_closed_on_next_conflict_check(self):
        evidences = iter([OwnedSessionEvidence(interfaces={"utun4"}), OwnedSessionEvidence()])
        def runner(argv, timeout):
            if argv == ["/bin/ps", "-axo", "comm="]:
                return CommandResult(tuple(argv), 0, "/Applications/GlobalProtect.app/Contents/MacOS/PanGPS\n", "")
            return CommandResult(tuple(argv), 0, "interface: utun4\n", "")

        detector = NativeConflictDetector(command_runner=runner, owned_session_provider=lambda: next(evidences), native_status=lambda: "connected")

        self.assertFalse(detector.conflict_active())
        self.assertTrue(detector.conflict_active())

    def test_main_passes_helper_provider_callback_not_captured_evidence(self):
        with mock.patch("hyu_vpn.supervisor.HelperOwnedSessionProvider") as provider_cls, \
             mock.patch("hyu_vpn.supervisor.NativeConflictDetector") as detector_cls, \
             mock.patch("hyu_vpn.supervisor.Supervisor") as supervisor_cls:
            supervisor_cls.return_value.run.return_value = 0
            self.assertEqual(main([]), 0)

        provider_cls.return_value.evidence.assert_not_called()
        self.assertIs(detector_cls.call_args.kwargs["owned_session_provider"], provider_cls.return_value.evidence)

    def test_main_wires_helper_owned_evidence_into_native_conflict_detector(self):
        with mock.patch("hyu_vpn.supervisor.HelperOwnedSessionProvider") as provider_cls, \
             mock.patch("hyu_vpn.supervisor.NativeConflictDetector") as detector_cls, \
             mock.patch("hyu_vpn.supervisor.Supervisor") as supervisor_cls:
            supervisor_cls.return_value.run.return_value = 0

            self.assertEqual(main([]), 0)

        detector_cls.assert_called_once()
        self.assertIs(detector_cls.call_args.kwargs["owned_session_provider"], provider_cls.return_value.evidence)

    def test_disconnected_native_daemon_with_foreign_utun_does_not_conflict(self):
        def runner(argv, timeout):
            if argv == ["/bin/ps", "-axo", "comm="]:
                return CommandResult(tuple(argv), 0, "/Applications/GlobalProtect.app/Contents/MacOS/PanGPS\n", "")
            return CommandResult(tuple(argv), 0, "interface: utun7\n", "")

        detector = NativeConflictDetector(command_runner=runner, native_status=lambda: "disconnected")
        self.assertFalse(detector.conflict_active())

    def test_connecting_native_without_route_blocks_when_status_is_fresh(self):
        def runner(argv, timeout):
            if argv == ["/bin/ps", "-axo", "comm="]:
                return CommandResult(tuple(argv), 0, "/Applications/GlobalProtect.app/Contents/MacOS/GlobalProtect\n", "")
            return CommandResult(tuple(argv), 1, "", "no route")

        detector = NativeConflictDetector(command_runner=runner, native_status=lambda: "connecting")
        self.assertTrue(detector.conflict_active())

    def test_helper_owned_utun_does_not_block_even_when_native_status_connected(self):
        owned = OwnedSessionEvidence(interfaces={"utun4"})
        def runner(argv, timeout):
            if argv == ["/bin/ps", "-axo", "comm="]:
                return CommandResult(tuple(argv), 0, "/Applications/GlobalProtect.app/Contents/MacOS/PanGPS\n", "")
            return CommandResult(tuple(argv), 0, "interface: utun4\n", "")

        detector = NativeConflictDetector(command_runner=runner, owned_session=owned, native_status=lambda: "connected")
        self.assertFalse(detector.conflict_active())

    def test_command_errors_are_not_conflicts(self):
        def runner(argv, timeout):
            return CommandResult(tuple(argv), 1, "PanGPS\ninterface: utun3\n", "permission denied with details")

        self.assertFalse(NativeConflictDetector(command_runner=runner).conflict_active())



class FakeProcess:
    def __init__(self, returncode=0, wait_side_effect=None, pid=4321):
        self.returncode = returncode
        self.pid = pid
        self.wait_side_effect = list(wait_side_effect or [])
        self.wait_calls = []
        self.poll_calls = 0

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        if self.wait_side_effect:
            effect = self.wait_side_effect.pop(0)
            if isinstance(effect, BaseException):
                raise effect
            self.returncode = effect
            return effect
        return self.returncode

    def poll(self):
        self.poll_calls += 1
        return self.returncode




def managed_temp_path(testcase: unittest.TestCase, *parts: str) -> Path:
    td = tempfile.TemporaryDirectory()
    testcase.addCleanup(td.cleanup)
    return Path(td.name).joinpath(*parts)


def isolated_supervisor_config(testcase: unittest.TestCase, **overrides) -> SupervisorConfig:
    state_dir = managed_temp_path(testcase, "supervisor-state")
    values = {
        "connect_path": str(state_dir / "hyu-vpn-connect"),
        "helper_path": str(state_dir / "hyu-vpn-helper"),
        "lock_path": str(state_dir / "supervisor.lock"),
        "status_path": str(state_dir / "status.json"),
        "preference_path": str(state_dir / "auto-reconnect.json"),
        "control_socket_path": str(state_dir / "control.sock"),
    }
    values.update(overrides)
    for key in ("connect_path", "helper_path", "lock_path", "status_path", "preference_path", "control_socket_path"):
        production_value = SupervisorConfig.__dataclass_fields__[key].default
        if Path(values[key]).expanduser() == Path(production_value).expanduser():
            raise AssertionError(f"test config must isolate {key}")
    return SupervisorConfig(**values)


class SupervisorTestIsolationContractTests(unittest.TestCase):
    def test_supervisor_configs_use_the_single_isolated_factory(self):
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        direct_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "SupervisorConfig"
        ]
        self.assertEqual(len(direct_calls), 1, "test SupervisorConfig calls must use isolated_supervisor_config")
        isolated = isolated_supervisor_config(self)
        temp_root = Path(tempfile.gettempdir()).resolve()
        for key in ("connect_path", "helper_path", "lock_path", "status_path", "preference_path", "control_socket_path"):
            self.assertIn(temp_root, Path(getattr(isolated, key)).resolve().parents)

    def test_offline_integration_supervisor_configs_explicitly_isolate_all_state_paths(self):
        source = Path(__file__).with_name("test_offline_integration.py").read_text(encoding="utf-8")
        config_lines = [line for line in source.splitlines() if "SupervisorConfig(" in line]
        self.assertGreaterEqual(len(config_lines), 2)
        for line in config_lines:
            for key in ("lock_path", "status_path", "preference_path", "control_socket_path"):
                self.assertIn(f"{key}=", line)


def enable_auto_reconnect(path: Path) -> str:
    AutoReconnectPreference(path).write(True)
    return str(path)


def enabled_auto_reconnect_path(testcase: unittest.TestCase) -> str:
    return enable_auto_reconnect(managed_temp_path(testcase, "auto.json"))

class SupervisorLoopTests(unittest.TestCase):

    def test_missing_auto_reconnect_preference_idles_disabled_without_launching_or_live_reads(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            popen = mock.Mock()
            detector = mock.Mock(conflict_active=mock.Mock(return_value=False))

            supervisor = None
            def stop_after_idle(_delay):
                supervisor._stop_requested = True

            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                    conflict_poll_interval=0.01,
                ),
                conflict_detector=detector,
                popen_factory=popen,
                sleep=stop_after_idle,
            )

            self.assertEqual(supervisor.run(), 0)

            from hyu_vpn.status import read_status
            self.assertFalse(pref_path.exists())
            self.assertEqual(read_status(status_path).state, "disabled")
            self.assertFalse(read_status(status_path).automatic_reconnect_enabled)
            detector.conflict_active.assert_not_called()
            popen.assert_not_called()

    def test_explicit_connect_control_enables_auto_reconnect_preference(self):
        with tempfile.TemporaryDirectory() as td:
            pref_path = Path(td) / "auto.json"
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(Path(td) / "status.json"),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
            )

            self.assertEqual(supervisor.handle_control_command("connect"), (True, None))
            self.assertTrue(json.loads(pref_path.read_text(encoding="utf-8"))["automatic_reconnect_enabled"])

    def test_idempotent_connect_when_automatic_already_enabled_preserves_backoff_without_wake(self):
        with tempfile.TemporaryDirectory() as td:
            pref_path = Path(td) / "auto.json"
            status_path = Path(td) / "status.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(
                    self,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
            )
            retry_at = datetime(2026, 8, 7, 12, 0, tzinfo=timezone.utc)
            supervisor._write_current_status(state="backoff", automatic=True, next_retry_at=retry_at)

            class RecordingControlEvent:
                def __init__(self):
                    self.set_calls = 0

                def set(self):
                    self.set_calls += 1

                def wait(self, timeout=None):
                    return False

                def clear(self):
                    pass

            event = RecordingControlEvent()
            supervisor._control_event = event

            self.assertEqual(supervisor.handle_control_command("connect"), (True, None))

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(event.set_calls, 0)
            self.assertEqual(status.state, "backoff")
            self.assertTrue(status.automatic_reconnect_enabled)
            self.assertEqual(status.next_retry_at, retry_at)

    def test_idempotent_connect_when_automatic_already_enabled_preserves_error_latch_without_wake(self):
        with tempfile.TemporaryDirectory() as td:
            pref_path = Path(td) / "auto.json"
            status_path = Path(td) / "status.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(
                    self,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
            )
            error_code = "NETWORK_SCRIPT_POSTCONDITION_FAILED"
            supervisor._connector_failure_code = error_code
            supervisor._write_current_status(state="error", automatic=True, error_code=error_code)

            class RecordingControlEvent:
                def __init__(self):
                    self.set_calls = 0

                def set(self):
                    self.set_calls += 1

                def wait(self, timeout=None):
                    return False

                def clear(self):
                    pass

            event = RecordingControlEvent()
            supervisor._control_event = event

            self.assertEqual(supervisor.handle_control_command("connect"), (True, None))

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(event.set_calls, 0)
            self.assertEqual(supervisor._connector_failure_code, error_code)
            self.assertEqual(status.state, "error")
            self.assertTrue(status.automatic_reconnect_enabled)
            self.assertEqual(status.error_code, error_code)

    def test_connect_when_automatic_disabled_enables_and_wakes_supervisor(self):
        with tempfile.TemporaryDirectory() as td:
            pref_path = Path(td) / "auto.json"
            status_path = Path(td) / "status.json"
            AutoReconnectPreference(pref_path).write(False)
            supervisor = Supervisor(
                isolated_supervisor_config(
                    self,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
            )

            class RecordingControlEvent:
                def __init__(self):
                    self.set_calls = 0

                def set(self):
                    self.set_calls += 1

                def wait(self, timeout=None):
                    return False

                def clear(self):
                    pass

            event = RecordingControlEvent()
            supervisor._control_event = event

            self.assertEqual(supervisor.handle_control_command("connect"), (True, None))

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(event.set_calls, 1)
            self.assertEqual(status.state, "connecting")
            self.assertTrue(status.automatic_reconnect_enabled)

    def test_polls_native_conflict_with_sleep_and_starts_only_after_clear(self):
        clock = FakeClock()
        conflicts = iter([True, True, False])
        started = []
        def popen(argv, **kwargs):
            started.append((argv, kwargs))
            return FakeProcess(returncode=0)

        supervisor = Supervisor(
            isolated_supervisor_config(self, lock_path=str(managed_temp_path(self, "state", "supervisor.lock")), preference_path=enabled_auto_reconnect_path(self), conflict_poll_interval=7, max_iterations=1),
            conflict_detector=mock.Mock(conflict_active=lambda: next(conflicts)),
            popen_factory=popen,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )

        self.assertEqual(supervisor.run(), 0)
        self.assertEqual(clock.sleeps, [7, 7])
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0][0], [supervisor.config.connect_path])
        self.assertIn(Path(tempfile.gettempdir()).resolve(), Path(supervisor.config.connect_path).resolve().parents)
        self.assertTrue(started[0][1]["start_new_session"])

    def test_failed_children_back_off_without_spin_and_long_runtime_resets(self):
        clock = FakeClock()
        processes = [FakeProcess(returncode=1), FakeProcess(returncode=1), FakeProcess(returncode=1)]
        def popen(argv, **kwargs):
            if len(processes) == 1:
                clock.now += 300
            return processes.pop(0)

        supervisor = Supervisor(
            isolated_supervisor_config(self, lock_path=str(managed_temp_path(self, "supervisor.lock")), preference_path=enabled_auto_reconnect_path(self), max_iterations=3),
            conflict_detector=mock.Mock(conflict_active=lambda: False),
            popen_factory=popen,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )

        self.assertEqual(supervisor.run(), 1)
        self.assertEqual(clock.sleeps, [10, 20])

    def test_clean_child_exit_still_reconnects_without_spinning(self):
        clock = FakeClock()
        processes = [FakeProcess(returncode=0), FakeProcess(returncode=0)]

        supervisor = Supervisor(
            isolated_supervisor_config(self, lock_path=str(managed_temp_path(self, "supervisor.lock")), preference_path=enabled_auto_reconnect_path(self), max_iterations=2),
            conflict_detector=mock.Mock(conflict_active=lambda: False),
            popen_factory=lambda *_args, **_kwargs: processes.pop(0),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )

        self.assertEqual(supervisor.run(), 0)
        self.assertEqual(clock.sleeps, [10])
        self.assertEqual(processes, [])

    def test_launch_failures_obey_backoff_and_test_iteration_bound(self):
        clock = FakeClock()
        calls = []

        def fail_launch(*args, **kwargs):
            calls.append((args, kwargs))
            raise FileNotFoundError("path canary")

        supervisor = Supervisor(
            isolated_supervisor_config(self, lock_path=str(managed_temp_path(self, "supervisor.lock")), preference_path=enabled_auto_reconnect_path(self), max_iterations=3),
            conflict_detector=mock.Mock(conflict_active=lambda: False),
            popen_factory=fail_launch,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )

        self.assertEqual(supervisor.run(), 1)
        self.assertEqual(len(calls), 3)
        self.assertEqual(clock.sleeps, [10, 20])


    def test_backoff_wait_wakes_for_reconnect_command_without_remaining_delay(self):
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "control.sock"
            status_path = Path(td) / "status.json"
            processes = [FakeProcess(returncode=1), FakeProcess(returncode=0)]
            starts = []
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "supervisor.lock"),
                    max_iterations=2,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(socket_path),
                    conflict_poll_interval=30,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                popen_factory=lambda *_args, **_kwargs: starts.append(time.monotonic()) or processes.pop(0),
                command_runner=lambda argv, timeout: CommandResult(tuple(argv), 0, "", ""),
            )
            run_thread = threading.Thread(target=supervisor.run)
            run_thread.start()
            from hyu_vpn.control import send_control_command
            from hyu_vpn.status import read_status
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    if socket_path.exists() and read_status(status_path).state == "backoff":
                        break
                except Exception:
                    pass
                time.sleep(0.01)
            self.assertEqual(read_status(status_path).state, "backoff")

            self.assertEqual(send_control_command(socket_path, "reconnect"), {"schema_version": 1, "ok": True, "error_code": None})
            run_thread.join(timeout=2)

            self.assertFalse(run_thread.is_alive())
            self.assertEqual(len(starts), 2)

    def test_connecting_without_connected_event_times_out_stops_helper_and_reports_no_tunnel(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            clock = FakeClock()
            wait_timeouts = []
            killed = []

            class StalledAuthenticatedProcess:
                pid = 6789
                returncode = None
                stdout = io.StringIO(
                    '{"schema_version":1,"event":"hip-succeeded","timestamp":"2026-08-06T05:27:01Z"}\n'
                    '{"schema_version":1,"event":"session-expiry","timestamp":"2026-08-06T09:27:00Z"}\n'
                )

                def wait(self, timeout=None):
                    wait_timeouts.append(timeout)
                    if timeout is None:
                        raise AssertionError("supervisor must not wait forever before tunnel establishment")
                    if killed:
                        self.returncode = 0
                        return 0
                    clock.now += timeout
                    raise subprocess.TimeoutExpired(["child"], timeout)

                def poll(self):
                    return self.returncode

            process = StalledAuthenticatedProcess()
            commands = []

            def runner(argv, timeout):
                commands.append((tuple(argv), timeout))
                return CommandResult(tuple(argv), 0, "", "")

            supervisor = Supervisor(
                isolated_supervisor_config(
                    self,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    helper_path="/helper",
                    max_iterations=1,
                    stop_timeout=0.5,
                    connect_establish_timeout=2.0,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                popen_factory=lambda *_args, **_kwargs: process,
                command_runner=runner,
                monotonic=clock.monotonic,
                sleep=clock.sleep,
            )

            with mock.patch("hyu_vpn.supervisor.os.killpg", side_effect=lambda pid, sig: killed.append((pid, sig))):
                self.assertEqual(supervisor.run(), 1)

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(status.state, "error")
            self.assertEqual(status.error_code, "CONNECT_TIMEOUT_NO_TUNNEL")
            self.assertFalse(status.automatic_reconnect_enabled)
            self.assertEqual(commands, [(("/usr/bin/sudo", "-n", "/helper", "stop"), 5.0)])
            self.assertNotIn(None, wait_timeouts)
            self.assertEqual(killed, [(6789, signal.SIGKILL)])

    def test_connect_timeout_handler_does_not_tear_down_a_session_that_connected_at_deadline(self):
        status_path = managed_temp_path(self, "status.json")
        pref_path = managed_temp_path(self, "auto.json")
        enable_auto_reconnect(pref_path)
        commands = []
        child = FakeProcess(returncode=None)
        supervisor = Supervisor(
            isolated_supervisor_config(self, status_path=str(status_path), preference_path=str(pref_path), helper_path="/helper"),
            conflict_detector=mock.Mock(conflict_active=lambda: False),
            command_runner=lambda argv, timeout: commands.append((tuple(argv), timeout)) or CommandResult(tuple(argv), 0, "", ""),
        )
        supervisor._child = child
        supervisor._active_generation = 1
        supervisor._write_current_status(state="connecting", automatic=True)
        supervisor.apply_connector_event_line(
            '{"schema_version":1,"event":"connected","timestamp":"2026-08-06T06:00:00Z","tunnel_interface":"utun7"}',
            generation=1,
        )

        result = supervisor._handle_connect_establish_timeout(expected_child=child, expected_generation=1)

        from hyu_vpn.status import read_status
        status = read_status(status_path)
        self.assertIsNone(result)
        self.assertEqual(commands, [])
        self.assertEqual(status.state, "connected")
        self.assertEqual(status.tunnel_interface, "utun7")

    def test_connect_timeout_handler_does_not_overwrite_concurrent_disconnect(self):
        status_path = managed_temp_path(self, "status.json")
        pref_path = managed_temp_path(self, "auto.json")
        enable_auto_reconnect(pref_path)
        commands = []
        child = FakeProcess(returncode=None)
        supervisor = Supervisor(
            isolated_supervisor_config(self, status_path=str(status_path), preference_path=str(pref_path), helper_path="/helper"),
            conflict_detector=mock.Mock(conflict_active=lambda: False),
            command_runner=lambda argv, timeout: commands.append((tuple(argv), timeout)) or CommandResult(tuple(argv), 0, "", ""),
        )
        supervisor._child = child
        supervisor._active_generation = 1
        supervisor._write_current_status(state="connecting", automatic=True)
        supervisor._disconnect_in_progress = True
        supervisor._active_generation = None
        supervisor._write_current_status(state="disconnecting", automatic=False)

        result = supervisor._handle_connect_establish_timeout(expected_child=child, expected_generation=1)

        from hyu_vpn.status import read_status
        status = read_status(status_path)
        self.assertIsNone(result)
        self.assertEqual(commands, [])
        self.assertEqual(status.state, "disconnecting")
        self.assertFalse(status.automatic_reconnect_enabled)

    def test_failed_child_writes_backoff_status_with_next_retry(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            now = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "supervisor.lock"),
                    max_iterations=1,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                popen_factory=lambda *_args, **_kwargs: FakeProcess(returncode=1),
                now=lambda: now,
            )

            self.assertEqual(supervisor.run(), 1)

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(status.state, "backoff")
            self.assertEqual(status.next_retry_at.isoformat(), "2026-08-04T12:00:10+00:00")


    def test_supervisor_drains_child_stdout_connector_events_into_status(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            stdout = io.StringIO(
                '{"schema_version":1,"event":"hip-succeeded","timestamp":"2026-08-04T12:00:00Z"}\n'
                '{"schema_version":1,"event":"session-expiry","timestamp":"2026-08-04T12:59:30Z"}\n'
                '{"schema_version":1,"event":"connected","timestamp":"2026-08-04T12:01:00Z","tunnel_interface":"utun7"}\n'
                '{"schema_version":1,"event":"connected","timestamp":"2026-08-04T12:01:00Z","password":"CANARY"}\n'
            )
            process = FakeProcess(returncode=0)
            process.stdout = stdout

            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "supervisor.lock"),
                    max_iterations=1,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                popen_factory=lambda *_args, **_kwargs: process,
            )

            self.assertEqual(supervisor.run(), 0)

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            raw = status_path.read_text(encoding="utf-8")
            self.assertEqual(status.state, "backoff")
            self.assertNotIn("CANARY", raw)


    def test_waits_for_network_readiness_before_starting_child(self):
        clock = FakeClock()
        started = []
        readiness = mock.Mock()
        readiness.wait_until_ready.return_value = True

        supervisor = Supervisor(
            isolated_supervisor_config(self, lock_path=str(managed_temp_path(self, "supervisor.lock")), preference_path=enabled_auto_reconnect_path(self), max_iterations=1),
            conflict_detector=mock.Mock(conflict_active=lambda: False),
            readiness=readiness,
            popen_factory=lambda argv, **kwargs: started.append(argv) or FakeProcess(returncode=0),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )

        self.assertEqual(supervisor.run(), 0)
        self.assertEqual(len(started), 1)
        readiness.wait_until_ready.assert_called_once()

    def test_does_not_start_child_when_network_readiness_stops(self):
        readiness = mock.Mock()
        readiness.wait_until_ready.return_value = False
        popen = mock.Mock()

        supervisor = Supervisor(
            isolated_supervisor_config(self, lock_path=str(managed_temp_path(self, "supervisor.lock")), preference_path=enabled_auto_reconnect_path(self), max_iterations=1),
            conflict_detector=mock.Mock(conflict_active=lambda: False),
            readiness=readiness,
            popen_factory=popen,
        )

        self.assertEqual(supervisor.run(), 0)
        popen.assert_not_called()

    def test_disconnect_interrupts_offline_readiness_and_service_settles_disabled_without_launch(self):
        with tempfile.TemporaryDirectory() as td:
            pref_path = Path(td) / "auto.json"
            status_path = Path(td) / "status.json"
            enable_auto_reconnect(pref_path)
            starts = []
            allow_readiness_check = threading.Event()
            disabled_wait_entered = threading.Event()
            release_disabled_wait = threading.Event()

            class OfflineReadiness:
                def __init__(self):
                    self.entered = threading.Event()
                    self.stop_values = []

                def wait_until_ready(self, *, stop_requested=None):
                    self.entered.set()
                    allow_readiness_check.wait(2)
                    value = stop_requested()
                    self.stop_values.append(value)
                    return False

            readiness = OfflineReadiness()

            supervisor = None

            def observed_sleep(_delay):
                from hyu_vpn.status import read_status

                status = read_status(status_path)
                if status.state == "disabled" and not status.automatic_reconnect_enabled:
                    disabled_wait_entered.set()
                release_disabled_wait.wait(2)
                supervisor._stop_requested = True

            supervisor = Supervisor(
                isolated_supervisor_config(
                    self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                    helper_path="/helper",
                    conflict_poll_interval=30,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                readiness=readiness,
                popen_factory=lambda argv, **kwargs: starts.append(argv) or FakeProcess(returncode=0),
                command_runner=lambda argv, timeout: CommandResult(tuple(argv), 0, "", ""),
                sleep=observed_sleep,
            )

            run_result = []
            run_thread = threading.Thread(target=lambda: run_result.append(supervisor.run()))
            run_thread.start()
            self.assertTrue(readiness.entered.wait(2), "supervisor did not enter offline readiness")

            self.assertEqual(supervisor.handle_control_command("disconnect"), (True, None))
            allow_readiness_check.set()
            self.assertTrue(disabled_wait_entered.wait(2), "service did not settle into disabled wait")

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(readiness.stop_values, [True])
            self.assertEqual(status.state, "disabled")
            self.assertFalse(status.automatic_reconnect_enabled)
            self.assertEqual(starts, [])
            self.assertTrue(run_thread.is_alive())

            release_disabled_wait.set()
            run_thread.join(timeout=2)
            self.assertFalse(run_thread.is_alive())
            self.assertEqual(run_result, [0])

    def test_existing_lock_causes_safe_failure_and_lock_file_is_mode_0600(self):
        with tempfile.TemporaryDirectory() as td:
            lock_path = Path(td) / "state" / "supervisor.lock"
            lock_path.parent.mkdir(parents=True)
            lock_file = lock_path.open("w")
            self.addCleanup(lock_file.close)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

            supervisor = Supervisor(isolated_supervisor_config(self, lock_path=str(lock_path), max_iterations=1))

            self.assertEqual(supervisor.run(), 75)
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)

    def test_unusable_lock_path_returns_safe_failure_without_starting_child(self):
        with tempfile.TemporaryDirectory() as td:
            blocker = Path(td) / "not-a-directory"
            blocker.write_text("block", encoding="utf-8")
            popen = mock.Mock()
            supervisor = Supervisor(
                isolated_supervisor_config(self, lock_path=str(blocker / "supervisor.lock"), max_iterations=1),
                popen_factory=popen,
            )

            self.assertEqual(supervisor.run(), 75)
            popen.assert_not_called()

    def test_signal_stop_forwards_to_child_group_waits_then_kills_on_timeout(self):
        proc = FakeProcess(returncode=None, wait_side_effect=[subprocess.TimeoutExpired(["child"], 0.25), 0])
        sent = []
        supervisor = Supervisor(isolated_supervisor_config(self, lock_path=str(managed_temp_path(self, "supervisor.lock")), stop_timeout=0.25))
        supervisor._child = proc

        with mock.patch("hyu_vpn.supervisor.os.killpg", side_effect=lambda pid, sig: sent.append((pid, sig))):
            supervisor._handle_signal(signal.SIGTERM, None)

        self.assertTrue(supervisor._stop_requested)
        self.assertEqual(sent, [(4321, signal.SIGTERM), (4321, signal.SIGKILL)])
        self.assertEqual(proc.wait_calls, [0.25, 0.25])


    def test_main_enables_network_readiness_gate(self):
        with mock.patch("hyu_vpn.supervisor.Supervisor") as supervisor_cls:
            supervisor_cls.return_value.run.return_value = 0

            self.assertEqual(main([]), 0)

        readiness = supervisor_cls.call_args.kwargs["readiness"]
        self.assertEqual(readiness.__class__.__name__, "NetworkReadiness")

    def test_real_sigterm_interrupts_native_conflict_sleep_promptly(self):
        with tempfile.TemporaryDirectory() as td:
            script = (
                "import sys; "
                f"sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / 'src')!r}); "
                "from pathlib import Path; "
                "from hyu_vpn.control import AutoReconnectPreference; "
                "from hyu_vpn.supervisor import Supervisor, SupervisorConfig; "
                "detector=type('Detector', (), {'conflict_active': lambda self: True})(); "
                f"pref={str(Path(td) / 'auto.json')!r}; AutoReconnectPreference(pref).write(True); "
                f"raise SystemExit(Supervisor(SupervisorConfig(lock_path={str(Path(td) / 'lock')!r}, status_path={str(Path(td) / 'status.json')!r}, preference_path=pref, control_socket_path={str(Path(td) / 'control.sock')!r}, conflict_poll_interval=120), conflict_detector=detector).run())"
            )
            proc = subprocess.Popen([sys.executable, "-c", script])
            try:
                time.sleep(0.2)
                started = time.monotonic()
                proc.send_signal(signal.SIGTERM)

                self.assertEqual(proc.wait(timeout=2), 0)
                self.assertLess(time.monotonic() - started, 1.5)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=2)


class SupervisorControlTests(unittest.TestCase):
    def test_blocked_popen_timeout_late_publication_gets_helper_stop_reap_but_stays_repair(self):
        with tempfile.TemporaryDirectory() as td:
            popen_entered = threading.Event()
            release_popen = threading.Event()
            events = []

            class LateProcess(FakeProcess):
                stdout = io.StringIO("")

                def __init__(self):
                    super().__init__(returncode=0)

                def wait(self, timeout=None):
                    events.append("child-reap")
                    return super().wait(timeout=timeout)

            def popen(*_args, **_kwargs):
                events.append("popen-enter")
                popen_entered.set()
                release_popen.wait(2)
                events.append("popen-return")
                return LateProcess()

            def runner(argv, timeout):
                events.append("helper-stop")
                return CommandResult(tuple(argv), 0, "", "")

            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                    helper_path="/helper",
                    max_iterations=1,
                    stop_timeout=0.1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=runner,
                popen_factory=popen,
            )
            run_thread = threading.Thread(target=supervisor.run)
            run_thread.start()
            self.assertTrue(popen_entered.wait(2))

            self.assertEqual(supervisor.handle_control_command("disconnect"), (False, "REPAIR_REQUIRED"))
            self.assertEqual(events, ["popen-enter"])
            release_popen.set()
            run_thread.join(timeout=2)

            from hyu_vpn.status import read_status
            self.assertFalse(run_thread.is_alive())
            self.assertEqual(events, ["popen-enter", "popen-return", "helper-stop", "child-reap"])
            status = read_status(status_path)
            self.assertEqual(status.state, "error")
            self.assertEqual(status.error_code, "REPAIR_REQUIRED")

    def test_concurrent_second_disconnect_does_not_duplicate_late_start_teardown(self):
        with tempfile.TemporaryDirectory() as td:
            popen_entered = threading.Event()
            release_popen = threading.Event()
            helper_entered = threading.Event()
            release_helper = threading.Event()
            events = []

            class LateProcess(FakeProcess):
                stdout = io.StringIO("")

                def wait(self, timeout=None):
                    events.append("child-reap")
                    return super().wait(timeout=timeout)

            def popen(*_args, **_kwargs):
                popen_entered.set()
                release_popen.wait(2)
                events.append("popen-return")
                return LateProcess(returncode=0)

            def runner(argv, timeout):
                events.append("helper-stop")
                helper_entered.set()
                release_helper.wait(2)
                return CommandResult(tuple(argv), 0, "", "")

            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(Path(td) / "status.json"),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                    helper_path="/helper",
                    max_iterations=1,
                    stop_timeout=0.1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=runner,
                popen_factory=popen,
            )
            run_thread = threading.Thread(target=supervisor.run)
            run_thread.start()
            self.assertTrue(popen_entered.wait(2))
            self.assertEqual(supervisor.handle_control_command("disconnect"), (False, "REPAIR_REQUIRED"))
            release_popen.set()
            self.assertTrue(helper_entered.wait(2))

            second_result = []
            second = threading.Thread(target=lambda: second_result.append(supervisor.handle_control_command("disconnect")))
            second.start()
            time.sleep(0.05)
            release_helper.set()
            second.join(timeout=2)
            run_thread.join(timeout=2)

            self.assertEqual(events.count("helper-stop"), 1)
            self.assertEqual(events.count("child-reap"), 1)
            self.assertEqual(second_result, [(False, "REPAIR_REQUIRED")])

    def test_disconnect_blocked_popen_timeout_enters_repair_without_deadlock(self):
        with tempfile.TemporaryDirectory() as td:
            popen_entered = threading.Event()
            release_popen = threading.Event()
            helper_calls = []

            def popen(*_args, **_kwargs):
                popen_entered.set()
                release_popen.wait(2)
                return FakeProcess(returncode=0)

            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(Path(td) / "status.json"),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                    helper_path="/helper",
                    max_iterations=1,
                    stop_timeout=0.1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=lambda argv, timeout: helper_calls.append(tuple(argv)) or CommandResult(tuple(argv), 0, "", ""),
                popen_factory=popen,
            )
            run_thread = threading.Thread(target=supervisor.run)
            run_thread.start()
            self.assertTrue(popen_entered.wait(2))

            started = time.monotonic()
            self.assertEqual(supervisor.handle_control_command("disconnect"), (False, "REPAIR_REQUIRED"))
            elapsed = time.monotonic() - started
            self.assertEqual(helper_calls, [])
            release_popen.set()
            run_thread.join(timeout=2)

            self.assertLess(elapsed, 1.0)
            self.assertEqual(helper_calls, [("/usr/bin/sudo", "-n", "/helper", "stop")])
            self.assertEqual(supervisor.handle_control_command("connect"), (True, None))
            self.assertEqual(helper_calls, [
                ("/usr/bin/sudo", "-n", "/helper", "stop"),
                ("/usr/bin/sudo", "-n", "/helper", "repair"),
            ])

    def test_disconnect_orders_post_publication_helper_stop_before_reap_and_response(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            popen_entered = threading.Event()
            release_popen = threading.Event()
            events = []

            class PublishedProcess(FakeProcess):
                stdout = io.StringIO("")

                def __init__(self):
                    super().__init__(returncode=0)

                def wait(self, timeout=None):
                    events.append("child-reap")
                    return super().wait(timeout=timeout)

            process = PublishedProcess()

            def popen(*_args, **_kwargs):
                events.append("popen-enter")
                popen_entered.set()
                release_popen.wait(2)
                events.append("popen-return")
                return process

            def runner(argv, timeout):
                events.append("helper-stop")
                return CommandResult(tuple(argv), 0, "", "")

            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                    helper_path="/helper",
                    max_iterations=1,
                    stop_timeout=1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=runner,
                popen_factory=popen,
            )
            run_thread = threading.Thread(target=supervisor.run)
            run_thread.start()
            self.assertTrue(popen_entered.wait(2))

            result = []
            disconnect_thread = threading.Thread(target=lambda: result.append(supervisor.handle_control_command("disconnect")))
            disconnect_thread.start()
            time.sleep(0.05)
            self.assertEqual(events, ["popen-enter"])
            self.assertEqual(result, [])

            release_popen.set()
            disconnect_thread.join(timeout=2)
            run_thread.join(timeout=2)

            self.assertEqual(result, [(True, None)])
            self.assertLess(events.index("popen-return"), events.index("helper-stop"))
            self.assertLess(events.index("helper-stop"), events.index("child-reap"))
            self.assertEqual(events[-1], "child-reap")

    def test_disconnect_waits_for_blocked_popen_publication_and_reaps_invalid_child(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            socket_path = Path(td) / "control.sock"
            popen_entered = threading.Event()
            release_popen = threading.Event()
            child_waited = []

            class PublishedAfterDisconnectProcess(FakeProcess):
                stdout = io.StringIO("")

                def __init__(self):
                    super().__init__(returncode=0)

                def wait(self, timeout=None):
                    child_waited.append(timeout)
                    return super().wait(timeout=timeout)

            process = PublishedAfterDisconnectProcess()

            def popen(*_args, **_kwargs):
                popen_entered.set()
                release_popen.wait(2)
                return process

            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(socket_path),
                    helper_path="/helper",
                    max_iterations=1,
                    stop_timeout=1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=lambda argv, timeout: CommandResult(tuple(argv), 0, "", ""),
                popen_factory=popen,
            )
            run_thread = threading.Thread(target=supervisor.run)
            run_thread.start()
            self.assertTrue(popen_entered.wait(2))

            result = []
            disconnect_thread = threading.Thread(target=lambda: result.append(supervisor.handle_control_command("disconnect")))
            disconnect_thread.start()
            time.sleep(0.05)
            self.assertEqual(result, [])

            release_popen.set()
            disconnect_thread.join(timeout=2)
            run_thread.join(timeout=2)

            from hyu_vpn.status import read_status
            self.assertEqual(result, [(True, None)])
            self.assertFalse(run_thread.is_alive())
            self.assertIsNone(supervisor._child)
            self.assertIn(1, child_waited)
            self.assertEqual(read_status(status_path).state, "disabled")

    def test_status_updates_are_state_locked_and_preserve_nonconflicting_fields(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
            )
            supervisor._write_current_status(state="connecting", automatic=True)
            supervisor.apply_connector_event_line(
                '{"schema_version":1,"event":"hip-succeeded","timestamp":"2026-08-04T12:00:00Z"}'
            )
            supervisor._write_current_status(automatic=False)

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertFalse(status.automatic_reconnect_enabled)
            self.assertEqual(status.last_successful_hip_at.isoformat(), "2026-08-04T12:00:00+00:00")

    def test_automatic_on_after_repair_required_fails_and_keeps_preference_false(self):
        with tempfile.TemporaryDirectory() as td:
            pref_path = Path(td) / "auto.json"
            status_path = Path(td) / "status.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                    helper_path="/helper",
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=lambda argv, timeout: CommandResult(tuple(argv), 1, "", "failed"),
            )

            self.assertEqual(supervisor.handle_control_command("disconnect"), (False, "REPAIR_REQUIRED"))
            self.assertEqual(supervisor.handle_control_command("automatic-on"), (False, "REPAIR_REQUIRED"))
            self.assertFalse(json.loads(pref_path.read_text(encoding="utf-8"))["automatic_reconnect_enabled"])

    def test_disconnect_child_wait_timeout_kills_and_enters_repair_required(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            process = FakeProcess(returncode=None, wait_side_effect=[subprocess.TimeoutExpired(["child"], 0.1), 0])
            helper_calls = []
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(Path(td) / "auto.json"),
                    control_socket_path=str(Path(td) / "control.sock"),
                    helper_path="/helper",
                    stop_timeout=0.1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=lambda argv, timeout: helper_calls.append(tuple(argv)) or CommandResult(tuple(argv), 0, "", ""),
            )
            supervisor._child = process
            killed = []
            with mock.patch("hyu_vpn.supervisor.os.killpg", side_effect=lambda pid, sig: killed.append((pid, sig))):
                self.assertEqual(supervisor.handle_control_command("disconnect"), (False, "REPAIR_REQUIRED"))

            from hyu_vpn.status import read_status
            self.assertEqual(killed, [(4321, signal.SIGKILL)])
            self.assertEqual(read_status(status_path).state, "error")
            self.assertEqual(read_status(status_path).error_code, "REPAIR_REQUIRED")
            self.assertEqual(supervisor.handle_control_command("connect"), (True, None))
            self.assertEqual(helper_calls, [
                ("/usr/bin/sudo", "-n", "/helper", "stop"),
                ("/usr/bin/sudo", "-n", "/helper", "repair"),
            ])

    def test_disconnect_waits_for_helper_child_reap_and_reader_before_ok(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            release = threading.Event()
            waited = []

            class BlockingProcess(FakeProcess):
                stdout = io.StringIO("")

                def __init__(self):
                    super().__init__(returncode=None)

                def wait(self, timeout=None):
                    waited.append(timeout)
                    if not release.wait(1.0 if timeout is None else min(timeout, 1.0)):
                        if timeout is not None:
                            raise subprocess.TimeoutExpired(["child"], timeout)
                    self.returncode = 0
                    return 0

            process = BlockingProcess()
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(Path(td) / "auto.json"),
                    control_socket_path=str(Path(td) / "control.sock"),
                    helper_path="/helper",
                    stop_timeout=0.5,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=lambda argv, timeout: CommandResult(tuple(argv), 0, "", ""),
            )
            supervisor._child = process
            supervisor._start_stdout_reader(process)

            result_holder = []
            thread = threading.Thread(target=lambda: result_holder.append(supervisor.handle_control_command("disconnect")))
            thread.start()
            time.sleep(0.05)
            self.assertEqual(result_holder, [])
            release.set()
            thread.join(timeout=2)

            self.assertEqual(result_holder, [(True, None)])
            from hyu_vpn.status import read_status
            self.assertEqual(read_status(status_path).state, "disabled")
            self.assertIsNone(supervisor._child)
            self.assertIn(0.5, waited)

    def test_stale_generation_events_after_disconnect_or_next_session_are_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                    helper_path="/helper",
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=lambda argv, timeout: CommandResult(tuple(argv), 0, "", ""),
            )
            supervisor._active_generation = 1
            supervisor._write_current_status(state="connecting", automatic=True)
            self.assertEqual(supervisor.handle_control_command("disconnect"), (True, None))
            supervisor.apply_connector_event_line(
                '{"schema_version":1,"event":"connected","timestamp":"2026-08-04T12:01:00Z","tunnel_interface":"utun7"}',
                generation=1,
            )
            supervisor._write_current_status(state="connecting", automatic=True)
            supervisor._active_generation = 2
            supervisor.apply_connector_event_line(
                '{"schema_version":1,"event":"connected","timestamp":"2026-08-04T12:02:00Z","tunnel_interface":"utun7"}',
                generation=1,
            )
            supervisor.apply_connector_event_line(
                '{"schema_version":1,"event":"connected","timestamp":"2026-08-04T12:03:00Z","tunnel_interface":"utun7"}',
                generation=2,
            )

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(status.state, "connected")
            self.assertEqual(status.connected_at.isoformat(), "2026-08-04T12:03:00+00:00")

    def test_auto_off_idles_until_control_wake_connects(self):
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "control.sock"
            pref_path = Path(td) / "auto.json"
            status_path = Path(td) / "status.json"
            from hyu_vpn.control import AutoReconnectPreference, send_control_command

            AutoReconnectPreference(pref_path).write(False)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(socket_path),
                    conflict_poll_interval=30,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
            )
            wait_entered = threading.Event()
            original_control_event = supervisor._control_event

            class ObservedControlEvent:
                def set(self):
                    original_control_event.set()

                def wait(self, timeout=None):
                    wait_entered.set()
                    return original_control_event.wait(timeout)

                def clear(self):
                    original_control_event.clear()

            supervisor._control_event = ObservedControlEvent()
            supervisor._start_control_server()
            try:
                wait_thread = threading.Thread(target=lambda: supervisor._wait_for_control_or_stop(30))
                wait_thread.start()

                self.assertTrue(wait_entered.wait(2))
                self.assertFalse(AutoReconnectPreference(pref_path).read(default=False))
                self.assertEqual(send_control_command(socket_path, "connect"), {"schema_version": 1, "ok": True, "error_code": None})
                wait_thread.join(timeout=2)

                self.assertFalse(wait_thread.is_alive())
                self.assertTrue(AutoReconnectPreference(pref_path).read(default=False))
            finally:
                supervisor._control_event = original_control_event
                supervisor._stop_control_server()

    def test_disconnect_during_child_exit_disables_auto_and_prevents_immediate_reconnect(self):
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "control.sock"
            pref_path = Path(td) / "auto.json"
            status_path = Path(td) / "status.json"
            release = threading.Event()
            starts = []

            class BlockingProcess(FakeProcess):
                stdout = io.StringIO("")

                def __init__(self):
                    super().__init__(returncode=None)

                def wait(self, timeout=None):
                    release.wait(2 if timeout is None else min(timeout, 2))
                    self.returncode = 0
                    return 0

            process = BlockingProcess()
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(socket_path),
                    helper_path="/helper",
                    max_iterations=1,
                    stop_timeout=2,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=lambda argv, timeout: CommandResult(tuple(argv), 0, "", ""),
                popen_factory=lambda *_args, **_kwargs: starts.append(True) or process,
            )
            run_thread = threading.Thread(target=supervisor.run)
            run_thread.start()
            while not socket_path.exists():
                time.sleep(0.01)

            from hyu_vpn.control import send_control_command
            result_holder = []
            client_thread = threading.Thread(target=lambda: result_holder.append(send_control_command(socket_path, "disconnect", timeout=5)))
            client_thread.start()
            time.sleep(0.05)
            self.assertEqual(result_holder, [])
            release.set()
            client_thread.join(timeout=2)
            run_thread.join(timeout=2)

            from hyu_vpn.status import read_status
            self.assertFalse(run_thread.is_alive())
            self.assertEqual(starts, [True])
            self.assertEqual(result_holder, [{"schema_version": 1, "ok": True, "error_code": None}])
            status = read_status(status_path)
            self.assertEqual(status.state, "disabled")
            self.assertFalse(status.automatic_reconnect_enabled)

    def test_state_transitions_clear_stale_session_fields(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(Path(td) / "control.sock"),
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
            )
            supervisor.apply_connector_event_line(
                '{"schema_version":1,"event":"hip-succeeded","timestamp":"2026-08-04T12:00:00Z"}'
            )
            supervisor.apply_connector_event_line(
                '{"schema_version":1,"event":"session-expiry","timestamp":"2026-08-04T12:59:30Z"}'
            )
            supervisor.apply_connector_event_line(
                '{"schema_version":1,"event":"connected","timestamp":"2026-08-04T12:01:00Z","tunnel_interface":"utun7"}'
            )

            AutoReconnectPreference(pref_path).write(False)
            supervisor._write_current_status(automatic=False)
            supervisor.handle_control_command("connect")

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(status.state, "connecting")
            self.assertIsNone(status.connected_at)
            self.assertIsNone(status.session_expires_at)
            self.assertIsNone(status.last_successful_hip_at)
            self.assertIsNone(status.tunnel_interface)
            self.assertIsNone(status.next_retry_at)

    def test_run_exposes_mode_0600_socket_and_applies_control_command(self):
        with tempfile.TemporaryDirectory() as td:
            socket_path = Path(td) / "control.sock"
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"

            class ControlClientProcess(FakeProcess):
                def wait(self, timeout=None):
                    from hyu_vpn.control import send_control_command

                    self.socket_mode = stat.S_IMODE(socket_path.stat().st_mode)
                    self.response = send_control_command(socket_path, "automatic-off")
                    return super().wait(timeout=timeout)

            process = ControlClientProcess(returncode=0)
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self,
                    lock_path=str(Path(td) / "lock"),
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    control_socket_path=str(socket_path),
                    max_iterations=1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                popen_factory=lambda *_args, **_kwargs: process,
            )

            self.assertEqual(supervisor.run(), 0)

            from hyu_vpn.status import read_status
            self.assertEqual(process.socket_mode, 0o600)
            self.assertEqual(process.response, {"schema_version": 1, "ok": True, "error_code": None})
            self.assertFalse(json.loads(pref_path.read_text(encoding="utf-8"))["automatic_reconnect_enabled"])
            self.assertFalse(read_status(status_path).automatic_reconnect_enabled)
            self.assertFalse(socket_path.exists())

    def test_disconnect_command_disables_auto_reconnect_stops_helper_and_writes_disabled_status(self):
        with tempfile.TemporaryDirectory() as td:
            calls = []
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            def runner(argv, timeout):
                calls.append((tuple(argv), timeout))
                return CommandResult(tuple(argv), 0, "", "")

            supervisor = Supervisor(
                isolated_supervisor_config(self, lock_path=str(Path(td) / "lock"), status_path=str(status_path), preference_path=str(pref_path), helper_path="/helper"),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=runner,
            )

            self.assertEqual(supervisor.handle_control_command("disconnect"), (True, None))

            from hyu_vpn.status import read_status
            self.assertFalse(json.loads(pref_path.read_text(encoding="utf-8"))["automatic_reconnect_enabled"])
            self.assertEqual(read_status(status_path).state, "disabled")
            self.assertEqual(calls, [(("/usr/bin/sudo", "-n", "/helper", "stop"), 5.0)])

    def test_disconnect_helper_failure_enters_repair_required_and_blocks_reconnect(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            def runner(argv, timeout):
                return CommandResult(tuple(argv), 1, "SECRET", "failed")
            supervisor = Supervisor(
                isolated_supervisor_config(self, lock_path=str(Path(td) / "lock"), status_path=str(status_path), preference_path=str(Path(td) / "auto.json"), helper_path="/helper"),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=runner,
            )

            self.assertEqual(supervisor.handle_control_command("disconnect"), (False, "REPAIR_REQUIRED"))
            self.assertEqual(supervisor.handle_control_command("reconnect"), (False, "REPAIR_REQUIRED"))

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(status.state, "error")
            self.assertEqual(status.error_code, "REPAIR_REQUIRED")
            self.assertNotIn("SECRET", status_path.read_text(encoding="utf-8"))

    def test_explicit_connect_repairs_idle_sticky_state_before_starting(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            calls = []

            def runner(argv, timeout):
                calls.append((tuple(argv), timeout))
                return CommandResult(tuple(argv), 0, "", "")

            supervisor = Supervisor(
                isolated_supervisor_config(
                    self,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    helper_path="/helper",
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=runner,
            )
            supervisor._repair_required = True
            supervisor._connector_failure_code = "NETWORK_SCRIPT_POSTCONDITION_FAILED"
            supervisor._write_current_status(state="error", automatic=False, error_code="NETWORK_SCRIPT_POSTCONDITION_FAILED")

            self.assertEqual(supervisor.handle_control_command("connect"), (True, None))

            from hyu_vpn.status import read_status
            self.assertEqual(calls, [(('/usr/bin/sudo', '-n', '/helper', 'repair'), 5.0)])
            self.assertFalse(supervisor._repair_required)
            self.assertIsNone(supervisor._connector_failure_code)
            self.assertEqual(read_status(status_path).state, "connecting")
            self.assertTrue(read_status(status_path).automatic_reconnect_enabled)

    def test_enable_and_reconnect_commands_repair_idle_sticky_state_once(self):
        for command, expected_state in (("automatic-on", "disabled"), ("reconnect", "connecting")):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as td:
                status_path = Path(td) / "status.json"
                pref_path = Path(td) / "auto.json"
                calls = []

                def runner(argv, timeout):
                    calls.append((tuple(argv), timeout))
                    return CommandResult(tuple(argv), 0, "", "")

                supervisor = Supervisor(
                    isolated_supervisor_config(
                        self,
                        status_path=str(status_path),
                        preference_path=str(pref_path),
                        helper_path="/helper",
                    ),
                    conflict_detector=mock.Mock(conflict_active=lambda: False),
                    command_runner=runner,
                )
                supervisor._repair_required = True
                supervisor._connector_failure_code = "NETWORK_SCRIPT_POSTCONDITION_FAILED"
                supervisor._write_current_status(state="error", automatic=False, error_code="NETWORK_SCRIPT_POSTCONDITION_FAILED")

                self.assertEqual(supervisor.handle_control_command(command), (True, None))

                from hyu_vpn.status import read_status
                status = read_status(status_path)
                self.assertEqual(calls, [(("/usr/bin/sudo", "-n", "/helper", "repair"), 5.0)])
                self.assertFalse(supervisor._repair_required)
                self.assertIsNone(supervisor._connector_failure_code)
                self.assertEqual(status.state, expected_state)
                self.assertTrue(status.automatic_reconnect_enabled)

    def test_second_disconnect_repairs_inactive_repair_required_state_and_clears_sticky_error(self):
        with tempfile.TemporaryDirectory() as td:
            calls = []
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"

            def runner(argv, timeout):
                calls.append(tuple(argv))
                if argv[-1] == "stop":
                    return CommandResult(tuple(argv), 1, "", "stop failed")
                if argv[-1] == "repair":
                    return CommandResult(tuple(argv), 0, "", "")
                raise AssertionError(argv)

            supervisor = Supervisor(
                isolated_supervisor_config(self, lock_path=str(Path(td) / "lock"), status_path=str(status_path), preference_path=str(pref_path), helper_path="/helper"),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=runner,
            )

            self.assertEqual(supervisor.handle_control_command("disconnect"), (False, "REPAIR_REQUIRED"))
            self.assertEqual(supervisor.handle_control_command("disconnect"), (True, None))

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(calls, [("/usr/bin/sudo", "-n", "/helper", "stop"), ("/usr/bin/sudo", "-n", "/helper", "repair")])
            self.assertEqual(status.state, "disabled")
            self.assertIsNone(status.error_code)
            self.assertFalse(status.automatic_reconnect_enabled)

    def test_second_disconnect_keeps_repair_required_when_inactive_repair_fails(self):
        with tempfile.TemporaryDirectory() as td:
            calls = []
            status_path = Path(td) / "status.json"

            def runner(argv, timeout):
                calls.append(tuple(argv))
                return CommandResult(tuple(argv), 1, "", "failed")

            supervisor = Supervisor(
                isolated_supervisor_config(self, lock_path=str(Path(td) / "lock"), status_path=str(status_path), preference_path=str(Path(td) / "auto.json"), helper_path="/helper"),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                command_runner=runner,
            )

            self.assertEqual(supervisor.handle_control_command("disconnect"), (False, "REPAIR_REQUIRED"))
            self.assertEqual(supervisor.handle_control_command("disconnect"), (False, "REPAIR_REQUIRED"))

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(calls, [("/usr/bin/sudo", "-n", "/helper", "stop"), ("/usr/bin/sudo", "-n", "/helper", "repair")])
            self.assertEqual(status.state, "error")
            self.assertEqual(status.error_code, "REPAIR_REQUIRED")

    def test_connector_events_update_status_without_persisting_raw_or_secret_output(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            supervisor = Supervisor(
                isolated_supervisor_config(self, lock_path=str(Path(td) / "lock"), status_path=str(status_path), preference_path=str(Path(td) / "auto.json")),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
            )

            supervisor.apply_connector_event_line('{"schema_version":1,"event":"hip-succeeded","timestamp":"2026-08-04T12:00:00Z"}')
            supervisor.apply_connector_event_line('{"schema_version":1,"event":"session-expiry","timestamp":"2026-08-04T12:59:30Z"}')
            supervisor.apply_connector_event_line('{"schema_version":1,"event":"connected","timestamp":"2026-08-04T12:01:00Z","tunnel_interface":"utun7"}')
            supervisor.apply_connector_event_line('{"schema_version":1,"event":"connected","timestamp":"2026-08-04T12:01:00Z","password":"CANARY"}')
            supervisor.apply_connector_event_line('x' * 2048)

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            raw = status_path.read_text(encoding="utf-8")
            self.assertEqual(status.state, "connected")
            self.assertEqual(status.tunnel_interface, "utun7")
            self.assertEqual(status.last_successful_hip_at.isoformat(), "2026-08-04T12:00:00+00:00")
            self.assertEqual(status.session_expires_at.isoformat(), "2026-08-04T12:59:30+00:00")
            self.assertNotIn("CANARY", raw)
            self.assertNotIn("xxxx", raw)

    def test_network_script_error_disables_retry_and_cannot_be_overwritten_by_connected(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self, status_path=str(status_path), preference_path=str(pref_path)),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
            )

            supervisor.apply_connector_event_line('{"schema_version":1,"event":"network-script-state-mismatch","timestamp":"2026-08-05T01:00:00Z"}')
            supervisor.apply_connector_event_line('{"schema_version":1,"event":"connected","timestamp":"2026-08-05T01:00:01Z","tunnel_interface":"utun7"}')

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(status.state, "error")
            self.assertEqual(status.error_code, "NETWORK_SCRIPT_STATE_MISMATCH")
            self.assertFalse(status.automatic_reconnect_enabled)
            self.assertFalse(json.loads(pref_path.read_text(encoding="utf-8"))["automatic_reconnect_enabled"])

    def test_network_script_error_from_child_remains_error_after_child_exit(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            release_reader = threading.Event()

            class DelayedEventStream:
                def __init__(self):
                    self._emitted = False

                def readline(self, _size=-1):
                    if self._emitted:
                        return ""
                    release_reader.wait(1)
                    self._emitted = True
                    return '{"schema_version":1,"event":"network-script-bad-configuration","timestamp":"2026-08-05T01:00:00Z"}\n'

                def close(self):
                    return None

            class FastExitProcess(FakeProcess):
                def __init__(self):
                    super().__init__(returncode=1)
                    self.stdout = DelayedEventStream()

                def wait(self, timeout=None):
                    threading.Timer(0.05, release_reader.set).start()
                    return 1

            process = FastExitProcess()
            supervisor = Supervisor(
                isolated_supervisor_config(
                    self,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    max_iterations=1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                popen_factory=lambda *_args, **_kwargs: process,
                command_runner=lambda argv, _timeout: CommandResult(tuple(argv), 1, "", ""),
            )

            self.assertEqual(supervisor.run(), 1)

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(status.state, "error")
            self.assertEqual(status.error_code, "NETWORK_SCRIPT_BAD_CONFIGURATION")
            self.assertFalse(status.automatic_reconnect_enabled)

    def test_network_script_error_repairs_after_child_exit_without_overwriting_diagnostic(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            process = FakeProcess(returncode=1)
            process.stdout = io.StringIO('{"schema_version":1,"event":"network-script-postcondition-failed","timestamp":"2026-08-05T01:00:00Z"}\n')
            commands = []

            def runner(argv, timeout):
                commands.append((tuple(argv), timeout))
                return CommandResult(tuple(argv), 0, "", "")

            supervisor = Supervisor(
                isolated_supervisor_config(
                    self,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    helper_path="/helper",
                    max_iterations=1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                popen_factory=lambda *_args, **_kwargs: process,
                command_runner=runner,
            )

            self.assertEqual(supervisor.run(), 1)

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(commands, [(("/usr/bin/sudo", "-n", "/helper", "repair"), 5.0)])
            self.assertEqual(status.state, "error")
            self.assertEqual(status.error_code, "NETWORK_SCRIPT_POSTCONDITION_FAILED")
            self.assertFalse(status.automatic_reconnect_enabled)

    def test_state_mismatch_successful_repair_resumes_automatic_reconnect(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            process = FakeProcess(returncode=1)
            process.stdout = io.StringIO('{"schema_version":1,"event":"network-script-state-mismatch","timestamp":"2026-08-05T01:00:00Z"}\n')
            commands = []

            def runner(argv, timeout):
                commands.append((tuple(argv), timeout))
                return CommandResult(tuple(argv), 0, "", "")

            supervisor = Supervisor(
                isolated_supervisor_config(
                    self,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    helper_path="/helper",
                    max_iterations=1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                popen_factory=lambda *_args, **_kwargs: process,
                command_runner=runner,
            )

            self.assertEqual(supervisor.run(), 1)

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(commands, [(("/usr/bin/sudo", "-n", "/helper", "repair"), 5.0)])
            self.assertEqual(status.state, "waiting-for-network")
            self.assertIsNone(status.error_code)
            self.assertTrue(status.automatic_reconnect_enabled)
            self.assertTrue(json.loads(pref_path.read_text(encoding="utf-8"))["automatic_reconnect_enabled"])

    def test_manual_disconnect_waits_for_automatic_repair_and_wins_final_state(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            process = FakeProcess(returncode=1)
            process.stdout = io.StringIO(
                '{"schema_version":1,"event":"network-script-state-mismatch","timestamp":"2026-08-05T01:00:00Z"}\n'
            )
            repair_started = threading.Event()
            release_repair = threading.Event()
            stop_started = threading.Event()

            def runner(argv, _timeout):
                if argv[-1] == "repair":
                    repair_started.set()
                    release_repair.wait(1)
                    return CommandResult(tuple(argv), 0, "", "")
                if argv[-1] == "stop":
                    stop_started.set()
                    return CommandResult(tuple(argv), 0, "", "")
                raise AssertionError(argv)

            supervisor = Supervisor(
                isolated_supervisor_config(
                    self,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    helper_path="/helper",
                    max_iterations=1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                popen_factory=lambda *_args, **_kwargs: process,
                command_runner=runner,
            )
            run_thread = threading.Thread(target=supervisor.run)
            run_thread.start()
            self.assertTrue(repair_started.wait(1))

            disconnect_result = []
            disconnect_thread = threading.Thread(
                target=lambda: disconnect_result.append(supervisor.handle_control_command("disconnect"))
            )
            disconnect_thread.start()
            stop_raced_with_repair = stop_started.wait(0.1)

            release_repair.set()
            run_thread.join(2)
            disconnect_thread.join(2)

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertFalse(run_thread.is_alive())
            self.assertFalse(disconnect_thread.is_alive())
            self.assertFalse(stop_raced_with_repair, "helper stop raced with helper repair")
            self.assertEqual(disconnect_result, [(True, None)])
            self.assertEqual(status.state, "disabled")
            self.assertFalse(status.automatic_reconnect_enabled)
            self.assertFalse(json.loads(pref_path.read_text(encoding="utf-8"))["automatic_reconnect_enabled"])

    def test_network_script_error_enters_repair_required_when_automatic_repair_fails(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            process = FakeProcess(returncode=1)
            process.stdout = io.StringIO('{"schema_version":1,"event":"network-script-upstream-failed","timestamp":"2026-08-05T01:00:00Z"}\n')
            commands = []

            def runner(argv, timeout):
                commands.append(tuple(argv))
                return CommandResult(tuple(argv), 1, "", "")

            supervisor = Supervisor(
                isolated_supervisor_config(
                    self,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    helper_path="/helper",
                    max_iterations=1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                popen_factory=lambda *_args, **_kwargs: process,
                command_runner=runner,
            )

            self.assertEqual(supervisor.run(), 1)

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(commands, [("/usr/bin/sudo", "-n", "/helper", "repair")])
            self.assertEqual(status.state, "error")
            self.assertEqual(status.error_code, "NETWORK_SCRIPT_UPSTREAM_FAILED")
            self.assertFalse(status.automatic_reconnect_enabled)
            self.assertIsNone(status.next_retry_at)
            self.assertEqual(supervisor.handle_control_command("connect"), (False, "REPAIR_REQUIRED"))

    def test_explicit_connect_after_fatal_event_cannot_skip_post_child_repair(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            fatal_processed = threading.Event()
            release_eof = threading.Event()
            commands = []

            class ControlledFailureStream:
                def __init__(self):
                    self.emitted = False

                def readline(self, _size=-1):
                    if not self.emitted:
                        self.emitted = True
                        return '{"schema_version":1,"event":"network-script-postcondition-failed","timestamp":"2026-08-05T01:00:00Z"}\n'
                    release_eof.wait(2)
                    return ""

                def close(self):
                    release_eof.set()

            process = FakeProcess(returncode=1)
            process.stdout = ControlledFailureStream()

            def runner(argv, timeout):
                commands.append(tuple(argv))
                return CommandResult(tuple(argv), 0, "", "")

            supervisor = Supervisor(
                isolated_supervisor_config(
                    self,
                    status_path=str(status_path),
                    preference_path=str(pref_path),
                    helper_path="/helper",
                    max_iterations=1,
                ),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
                popen_factory=lambda *_args, **_kwargs: process,
                command_runner=runner,
            )
            original_apply = supervisor.apply_connector_event_line

            def observed_apply(line, *, generation=None):
                original_apply(line, generation=generation)
                if "network-script-postcondition-failed" in line:
                    fatal_processed.set()

            supervisor.apply_connector_event_line = observed_apply
            result = []
            thread = threading.Thread(target=lambda: result.append(supervisor.run()))
            thread.start()
            self.assertTrue(fatal_processed.wait(2), "fatal connector event not processed")

            self.assertEqual(supervisor.handle_control_command("connect"), (True, None))
            release_eof.set()
            thread.join(3)

            self.assertFalse(thread.is_alive(), "supervisor did not finish")
            self.assertEqual(result, [1])
            self.assertEqual(commands, [("/usr/bin/sudo", "-n", "/helper", "repair")])

    def test_stale_network_script_error_is_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            status_path = Path(td) / "status.json"
            pref_path = Path(td) / "auto.json"
            enable_auto_reconnect(pref_path)
            supervisor = Supervisor(
                isolated_supervisor_config(self, status_path=str(status_path), preference_path=str(pref_path)),
                conflict_detector=mock.Mock(conflict_active=lambda: False),
            )
            current_generation = supervisor._begin_new_generation()
            supervisor._write_current_status(state="connecting", automatic=True)

            supervisor.apply_connector_event_line(
                '{"schema_version":1,"event":"network-script-bad-configuration","timestamp":"2026-08-05T01:00:00Z"}',
                generation=current_generation - 1,
            )

            from hyu_vpn.status import read_status
            status = read_status(status_path)
            self.assertEqual(status.state, "connecting")
            self.assertTrue(status.automatic_reconnect_enabled)
            self.assertTrue(json.loads(pref_path.read_text(encoding="utf-8"))["automatic_reconnect_enabled"])


if __name__ == "__main__":
    unittest.main()
