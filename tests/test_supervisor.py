import fcntl
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.supervisor import CommandResult, NativeConflictDetector, ReconnectPolicy, Supervisor, SupervisorConfig


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


class SupervisorLoopTests(unittest.TestCase):
    def test_polls_native_conflict_with_sleep_and_starts_only_after_clear(self):
        clock = FakeClock()
        conflicts = iter([True, True, False])
        started = []
        def popen(argv, **kwargs):
            started.append((argv, kwargs))
            return FakeProcess(returncode=0)

        supervisor = Supervisor(
            SupervisorConfig(lock_path=str(Path(tempfile.mkdtemp()) / "state" / "supervisor.lock"), conflict_poll_interval=7, max_iterations=1),
            conflict_detector=mock.Mock(conflict_active=lambda: next(conflicts)),
            popen_factory=popen,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )

        self.assertEqual(supervisor.run(), 0)
        self.assertEqual(clock.sleeps, [7, 7])
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0][0], [str(Path(__file__).resolve().parents[1] / "bin" / "hyu-vpn-connect")])
        self.assertTrue(started[0][1]["start_new_session"])

    def test_failed_children_back_off_without_spin_and_long_runtime_resets(self):
        clock = FakeClock()
        processes = [FakeProcess(returncode=1), FakeProcess(returncode=1), FakeProcess(returncode=1)]
        def popen(argv, **kwargs):
            if len(processes) == 1:
                clock.now += 300
            return processes.pop(0)

        supervisor = Supervisor(
            SupervisorConfig(lock_path=str(Path(tempfile.mkdtemp()) / "supervisor.lock"), max_iterations=3),
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
            SupervisorConfig(lock_path=str(Path(tempfile.mkdtemp()) / "supervisor.lock"), max_iterations=2),
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
            SupervisorConfig(lock_path=str(Path(tempfile.mkdtemp()) / "supervisor.lock"), max_iterations=3),
            conflict_detector=mock.Mock(conflict_active=lambda: False),
            popen_factory=fail_launch,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )

        self.assertEqual(supervisor.run(), 1)
        self.assertEqual(len(calls), 3)
        self.assertEqual(clock.sleeps, [10, 20])

    def test_existing_lock_causes_safe_failure_and_lock_file_is_mode_0600(self):
        with tempfile.TemporaryDirectory() as td:
            lock_path = Path(td) / "state" / "supervisor.lock"
            lock_path.parent.mkdir(parents=True)
            lock_file = lock_path.open("w")
            self.addCleanup(lock_file.close)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

            supervisor = Supervisor(SupervisorConfig(lock_path=str(lock_path), max_iterations=1))

            self.assertEqual(supervisor.run(), 75)
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)

    def test_unusable_lock_path_returns_safe_failure_without_starting_child(self):
        with tempfile.TemporaryDirectory() as td:
            blocker = Path(td) / "not-a-directory"
            blocker.write_text("block", encoding="utf-8")
            popen = mock.Mock()
            supervisor = Supervisor(
                SupervisorConfig(lock_path=str(blocker / "supervisor.lock"), max_iterations=1),
                popen_factory=popen,
            )

            self.assertEqual(supervisor.run(), 75)
            popen.assert_not_called()

    def test_signal_stop_forwards_to_child_group_waits_then_kills_on_timeout(self):
        proc = FakeProcess(returncode=None, wait_side_effect=[subprocess.TimeoutExpired(["child"], 0.25), 0])
        sent = []
        supervisor = Supervisor(SupervisorConfig(lock_path=str(Path(tempfile.mkdtemp()) / "supervisor.lock"), stop_timeout=0.25))
        supervisor._child = proc

        with mock.patch("hyu_vpn.supervisor.os.killpg", side_effect=lambda pid, sig: sent.append((pid, sig))):
            supervisor._handle_signal(signal.SIGTERM, None)

        self.assertTrue(supervisor._stop_requested)
        self.assertEqual(sent, [(4321, signal.SIGTERM), (4321, signal.SIGKILL)])
        self.assertEqual(proc.wait_calls, [0.25, 0.25])

    def test_real_sigterm_interrupts_native_conflict_sleep_promptly(self):
        with tempfile.TemporaryDirectory() as td:
            script = (
                "import sys; "
                f"sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / 'src')!r}); "
                "from hyu_vpn.supervisor import Supervisor, SupervisorConfig; "
                "detector=type('Detector', (), {'conflict_active': lambda self: True})(); "
                f"raise SystemExit(Supervisor(SupervisorConfig(lock_path={str(Path(td) / 'lock')!r}, conflict_poll_interval=120), conflict_detector=detector).run())"
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

if __name__ == "__main__":
    unittest.main()
