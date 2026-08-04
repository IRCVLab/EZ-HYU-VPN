"""Reconnect supervisor for HYU OpenConnect."""

from __future__ import annotations

import fcntl
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Callable, Optional, Sequence, TextIO


PROTECTED_ROUTE = "166.104.100.100"
_NATIVE_PROCESS_NAMES = ("PanGPS", "PanGPA", "PanGpHip", "PanGpHipMp", "GlobalProtect")


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class ReconnectPolicy:
    def __init__(self, *, reset_after_seconds: float = 300.0) -> None:
        self.reset_after_seconds = reset_after_seconds
        self.consecutive_failures = 0

    def next_delay(self, consecutive_failures: int) -> int:
        if consecutive_failures <= 0:
            return 0
        return min(120, 10 * (2 ** (consecutive_failures - 1)))

    def record_exit(self, returncode: int, *, runtime_seconds: float) -> int:
        if returncode == 0 or runtime_seconds >= self.reset_after_seconds:
            self.consecutive_failures = 0
        else:
            self.consecutive_failures += 1
        return self.consecutive_failures


class NativeConflictDetector:
    def __init__(
        self,
        *,
        command_runner: Optional[Callable[[list[str], float], CommandResult]] = None,
        timeout: float = 2.0,
        protected_route: str = PROTECTED_ROUTE,
    ) -> None:
        self.command_runner = command_runner or _run_command
        self.timeout = timeout
        self.protected_route = protected_route

    def conflict_active(self) -> bool:
        ps = self.command_runner(["/bin/ps", "-axo", "comm="], self.timeout)
        if ps.returncode != 0 or not _has_native_process(ps.stdout):
            return False
        route = self.command_runner(["/sbin/route", "-n", "get", self.protected_route], self.timeout)
        if route.returncode != 0:
            return False
        return _route_uses_utun(route.stdout)


def _run_command(argv: list[str], timeout: float) -> CommandResult:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return CommandResult(tuple(argv), completed.returncode, completed.stdout, completed.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(tuple(argv), 1, "", exc.__class__.__name__)


def _has_native_process(stdout: str) -> bool:
    return any(name in stdout for name in _NATIVE_PROCESS_NAMES)


def _route_uses_utun(stdout: str) -> bool:
    for line in stdout.splitlines():
        if line.strip().lower().startswith("interface:"):
            return line.split(":", 1)[1].strip().startswith("utun")
    return False


@dataclass(frozen=True)
class SupervisorConfig:
    connect_path: str = str(Path(__file__).resolve().parents[2] / "bin" / "hyu-vpn-connect")
    lock_path: str = str(Path.home() / "Library" / "Application Support" / "hyu-openconnect" / "supervisor.lock")
    stop_timeout: float = 10.0
    conflict_poll_interval: float = 10.0
    max_iterations: Optional[int] = None


class Supervisor:
    def __init__(
        self,
        config: SupervisorConfig = SupervisorConfig(),
        *,
        conflict_detector: Optional[NativeConflictDetector] = None,
        popen_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        stderr: Optional[TextIO] = sys.stderr,
    ) -> None:
        self.config = config
        self.conflict_detector = conflict_detector or NativeConflictDetector()
        self.popen_factory = popen_factory
        self.monotonic = monotonic
        self.sleep = sleep
        self.stderr = stderr
        self.policy = ReconnectPolicy()
        self._stop_requested = False
        self._child: Optional[subprocess.Popen] = None

    def run(self) -> int:
        lock_file = self._acquire_lock()
        if lock_file is None:
            return 75
        old_handlers: dict[int, object] = {}
        iterations = 0
        last_returncode = 0
        try:
            self._install_signal_handlers(old_handlers)
            while not self._stop_requested:
                while not self._stop_requested and self.conflict_detector.conflict_active():
                    self._sleep_stop_aware(self.config.conflict_poll_interval)
                if self._stop_requested:
                    break

                started_at = self.monotonic()
                iterations += 1
                try:
                    self._child = self.popen_factory([self.config.connect_path], start_new_session=True, close_fds=True)
                except (OSError, subprocess.SubprocessError):
                    last_returncode = 1
                    failures = self.policy.record_exit(1, runtime_seconds=0)
                    if self.config.max_iterations is not None and iterations >= self.config.max_iterations:
                        break
                    self._sleep_stop_aware(self.policy.next_delay(failures))
                    continue

                last_returncode = self._wait_for_child()
                runtime = self.monotonic() - started_at
                failures = self.policy.record_exit(last_returncode, runtime_seconds=runtime)
                self._child = None
                if self._stop_requested:
                    break
                if self.config.max_iterations is not None and iterations >= self.config.max_iterations:
                    break
                self._sleep_stop_aware(self.policy.next_delay(max(failures, 1)))
            return last_returncode
        finally:
            self._restore_signal_handlers(old_handlers)
            if self._child is not None and self._child.poll() is None:
                self._stop_child()
            try:
                lock_file.close()
            except OSError:
                pass

    def _acquire_lock(self):
        path = Path(self.config.lock_path)
        fd: Optional[int] = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_CREAT | os.O_RDWR
            fd = os.open(path, flags, 0o600)
            os.chmod(path, 0o600)
            lock_file = os.fdopen(fd, "a+")
            fd = None
        except OSError:
            if fd is not None:
                os.close(fd)
            return None
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            lock_file.close()
            return None
        return lock_file

    def _install_signal_handlers(self, old_handlers: dict[int, object]) -> None:
        for signum in (signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, self._handle_signal)

    def _restore_signal_handlers(self, old_handlers: dict[int, object]) -> None:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)

    def _handle_signal(self, signum: int, _frame: Optional[FrameType]) -> None:
        self._stop_requested = True
        self._stop_child(signum)

    def _wait_for_child(self) -> int:
        if self._child is None:
            return 0
        return self._child.wait() or 0

    def _stop_child(self, signum: int = signal.SIGTERM) -> None:
        child = self._child
        if child is None:
            return
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            return
        try:
            child.wait(timeout=self.config.stop_timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                return
            child.wait(timeout=self.config.stop_timeout)

    def _sleep_stop_aware(self, delay: float) -> None:
        if delay <= 0 or self._stop_requested:
            return
        self.sleep(delay)


def main(argv: Optional[Sequence[str]] = None) -> int:
    if argv:
        sys.stderr.write("hyu-vpn-service does not accept arguments\n")
        return 2
    return Supervisor().run()
