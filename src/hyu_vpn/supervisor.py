"""Reconnect supervisor for HYU OpenConnect."""

from __future__ import annotations

import fcntl
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import FrameType
from typing import Callable, Optional, Sequence, TextIO

from .control import AutoReconnectPreference, ControlServer
from .network import HelperOwnedSessionProvider, NetworkReadiness, OwnedSessionEvidence, route_interface
from .native_client import NativeClientState, production_status_reader
from .connector import NETWORK_SCRIPT_EVENT_KINDS, parse_connector_event_line
from .status import VpnStatus, write_status


PROTECTED_ROUTE = "166.104.100.100"
_NATIVE_PROCESS_NAMES = ("PanGPS", "PanGPA", "PanGpHip", "PanGpHipMp", "GlobalProtect")
_NETWORK_SCRIPT_ERROR_CODES = {
    "network-script-bad-configuration": "NETWORK_SCRIPT_BAD_CONFIGURATION",
    "network-script-state-mismatch": "NETWORK_SCRIPT_STATE_MISMATCH",
    "network-script-security-failure": "NETWORK_SCRIPT_SECURITY_FAILURE",
    "network-script-teardown-incomplete": "NETWORK_SCRIPT_TEARDOWN_INCOMPLETE",
    "network-script-preflight-drift": "NETWORK_SCRIPT_PREFLIGHT_DRIFT",
    "network-script-upstream-failed": "NETWORK_SCRIPT_UPSTREAM_FAILED",
    "network-script-postcondition-failed": "NETWORK_SCRIPT_POSTCONDITION_FAILED",
    "network-script-failed": "NETWORK_SCRIPT_FAILED",
}


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
        owned_session: Optional[OwnedSessionEvidence] = None,
        owned_session_provider: Optional[Callable[[], OwnedSessionEvidence]] = None,
        native_status: Optional[Callable[[], str]] = None,
    ) -> None:
        self.command_runner = command_runner or _run_command
        self.timeout = timeout
        self.protected_route = protected_route
        self.owned_session = owned_session or OwnedSessionEvidence()
        self.owned_session_provider = owned_session_provider
        self.native_status = native_status

    def conflict_active(self) -> bool:
        ps = self.command_runner(["/bin/ps", "-axo", "comm="], self.timeout)
        if ps.returncode != 0 or not _has_native_process(ps.stdout):
            return False
        processes = _native_processes(ps.stdout)
        route = self.command_runner(["/sbin/route", "-n", "get", self.protected_route], self.timeout)
        interface = route_interface(route.stdout) if route.returncode == 0 else None
        owned_session = self.owned_session_provider() if self.owned_session_provider is not None else self.owned_session
        if owned_session.owns_interface(interface):
            return False
        status = self.native_status() if self.native_status is not None else "unknown"
        if self.native_status is None and interface is not None and interface.startswith("utun"):
            status = "connected"
        return NativeClientState(processes=processes, route_interface=interface, status=status).blocks_openconnect()


def _run_command(argv: list[str], timeout: float) -> CommandResult:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return CommandResult(tuple(argv), completed.returncode, completed.stdout, completed.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(tuple(argv), 1, "", exc.__class__.__name__)


def _native_processes(stdout: str) -> set[str]:
    return {
        os.path.basename(line.strip())
        for line in stdout.splitlines()
        if line.strip() and os.path.basename(line.strip()) in _NATIVE_PROCESS_NAMES
    }


def _has_native_process(stdout: str) -> bool:
    return bool(_native_processes(stdout))


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
    status_path: str = str(Path.home() / "Library" / "Application Support" / "hyu-openconnect" / "status.json")
    preference_path: str = str(Path.home() / "Library" / "Application Support" / "hyu-openconnect" / "auto-reconnect.json")
    control_socket_path: str = str(Path.home() / "Library" / "Application Support" / "hyu-openconnect" / "control.sock")
    helper_path: str = "/Library/PrivilegedHelperTools/com.hyu.vpn.helper"
    helper_timeout: float = 5.0


class Supervisor:
    def __init__(
        self,
        config: SupervisorConfig = SupervisorConfig(),
        *,
        conflict_detector: Optional[NativeConflictDetector] = None,
        popen_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Optional[Callable[[float], None]] = None,
        stderr: Optional[TextIO] = sys.stderr,
        readiness: Optional[NetworkReadiness] = None,
        command_runner: Optional[Callable[[list[str], float], CommandResult]] = None,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.config = config
        self.conflict_detector = conflict_detector or NativeConflictDetector()
        self.popen_factory = popen_factory
        self.monotonic = monotonic
        self.sleep = sleep
        self.stderr = stderr
        self.readiness = readiness
        self.command_runner = command_runner or _run_command
        self.now = now
        self.preference = AutoReconnectPreference(self.config.preference_path)
        self._state_lock = threading.RLock()
        self._command_lock = threading.Lock()
        self._repair_required = False
        self._connector_failure_code: Optional[str] = None
        self._connector_repair_pending = False
        self._status = self._base_status("disabled")
        self.policy = ReconnectPolicy()
        self._stop_requested = False
        self._stop_event = threading.Event()
        self._control_event = threading.Event()
        self._child: Optional[subprocess.Popen] = None
        self._stdout_reader: Optional[threading.Thread] = None
        self._control_server: Optional[ControlServer] = None
        self._control_thread: Optional[threading.Thread] = None
        self._state_changed = threading.Condition(self._state_lock)
        self._teardown_lock = threading.Lock()
        self._active_generation: Optional[int] = None
        self._starting_generation: Optional[int] = None
        self._disconnect_in_progress = False
        self._next_generation = 0

    def handle_control_command(self, command: str) -> tuple[bool, Optional[str]]:
        with self._command_lock:
            if self._repair_required and command in {"automatic-on", "connect", "reconnect"}:
                self.preference.write(False)
                self._write_current_status(state="error", automatic=False, error_code="REPAIR_REQUIRED")
                return False, "REPAIR_REQUIRED"
            if command == "automatic-on":
                self._connector_failure_code = None
                self.preference.write(True)
                self._write_current_status(state=self._status.state, automatic=True)
                self._control_event.set()
                return True, None
            if command == "automatic-off":
                self.preference.write(False)
                if self._child is None or self._child.poll() is not None:
                    self._write_current_status(state="disabled", automatic=False)
                else:
                    self._write_current_status(state=self._status.state, automatic=False)
                self._control_event.set()
                return True, None
            if command == "disconnect":
                self.preference.write(False)
                result = self._disconnect_locked()
                self._control_event.set()
                return result
            if command == "reconnect":
                self.preference.write(False)
                ok, error = self._disconnect_locked(disable_auto=False)
                if not ok:
                    return ok, error
                self._connector_failure_code = None
                self.preference.write(True)
                self._write_current_status(state="connecting", automatic=True)
                self._control_event.set()
                return True, None
            if command == "connect":
                if self._repair_required:
                    return False, "REPAIR_REQUIRED"
                self._connector_failure_code = None
                self.preference.write(True)
                if self._child is None or self._child.poll() is not None:
                    self._write_current_status(state="connecting", automatic=True)
                else:
                    self._write_current_status(state=self._status.state, automatic=True)
                self._control_event.set()
                return True, None
            return False, "BAD_REQUEST"

    def _disconnect_locked(self, *, disable_auto: bool = True) -> tuple[bool, Optional[str]]:
        with self._state_changed:
            self._disconnect_in_progress = True
            self._active_generation = None
            self._state_changed.notify_all()
        try:
            self._write_current_status(state="disconnecting", automatic=False if disable_auto else None)
            if not self._wait_for_start_publication(timeout=self.config.stop_timeout):
                self._enter_repair_required(automatic=False if disable_auto else None)
                return False, "REPAIR_REQUIRED"
            if self._repair_required and self._no_user_connector_lifecycle_active():
                self._write_current_status(state="error", error_code="REPAIR_REQUIRED", automatic=False if disable_auto else None)
                return False, "REPAIR_REQUIRED"
            if not self._stop_helper_and_teardown_user_connector(automatic=False if disable_auto else None):
                self._enter_repair_required(automatic=False if disable_auto else None)
                return False, "REPAIR_REQUIRED"
            self._repair_required = False
            self._connector_failure_code = None
            self._connector_repair_pending = False
            self._write_current_status(state="disabled", automatic=False if disable_auto else None)
            return True, None
        finally:
            with self._state_changed:
                self._disconnect_in_progress = False
                self._state_changed.notify_all()

    def _enter_repair_required(self, *, automatic: Optional[bool] = None) -> None:
        self._repair_required = True
        self._invalidate_active_generation()
        self._write_current_status(state="error", error_code="REPAIR_REQUIRED", automatic=automatic)

    def _invalidate_active_generation(self) -> None:
        with self._state_changed:
            self._active_generation = None
            self._state_changed.notify_all()

    def _stop_helper_and_teardown_user_connector(self, *, automatic: Optional[bool] = None, keep_repair: bool = False) -> bool:
        with self._teardown_lock:
            if keep_repair is False and self._repair_required and self._no_user_connector_lifecycle_active():
                self._write_current_status(state="error", error_code="REPAIR_REQUIRED", automatic=automatic)
                return False
            result = self.command_runner(["/usr/bin/sudo", "-n", self.config.helper_path, "stop"], self.config.helper_timeout)
            helper_ok = result.returncode == 0
            reap_ok = self._reap_user_connector_only()
            if keep_repair and self._repair_required:
                self._write_current_status(state="error", error_code="REPAIR_REQUIRED", automatic=automatic)
            return helper_ok and reap_ok

    def _no_user_connector_lifecycle_active(self) -> bool:
        with self._state_lock:
            return self._starting_generation is None and self._child is None and self._stdout_reader is None

    def _reap_user_connector_only(self) -> bool:
        with self._state_lock:
            child = self._child
        if child is not None:
            try:
                child.wait(timeout=self.config.stop_timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=self.config.stop_timeout)
                except subprocess.TimeoutExpired:
                    pass
                with self._state_changed:
                    if self._child is child:
                        self._child = None
                    self._state_changed.notify_all()
                return False
            with self._state_changed:
                if self._child is child:
                    self._child = None
                self._state_changed.notify_all()
        return self._join_stdout_reader()

    def _wait_for_start_publication(self, *, timeout: float) -> bool:
        deadline = self.monotonic() + timeout
        with self._state_changed:
            while self._starting_generation is not None:
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    return False
                self._state_changed.wait(remaining)
            return True

    def _wait_for_child_cleared(self, *, timeout: float) -> bool:
        deadline = self.monotonic() + timeout
        with self._state_changed:
            while self._child is not None:
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    return False
                self._state_changed.wait(remaining)
            return True

    def apply_connector_event_line(self, line: str, *, generation: Optional[int] = None) -> None:
        try:
            event = parse_connector_event_line(line.rstrip("\n"))
        except ValueError:
            return
        with self._state_lock:
            if self._connector_failure_code is not None and event.kind not in NETWORK_SCRIPT_EVENT_KINDS:
                return
            if generation is not None:
                if generation != self._active_generation:
                    return
                if self._status.state in {"disabled", "disconnecting", "error", "backoff"}:
                    return
            if event.kind in NETWORK_SCRIPT_EVENT_KINDS:
                error_code = _NETWORK_SCRIPT_ERROR_CODES[event.kind]
                self.preference.write(False)
                self._connector_failure_code = error_code
                self._connector_repair_pending = True
                self._active_generation = None
                self._write_current_status(state="error", automatic=False, error_code=error_code)
                self._state_changed.notify_all()
            elif event.kind == "hip-succeeded":
                self._write_current_status(last_successful_hip_at=event.timestamp)
            elif event.kind == "session-expiry":
                self._write_current_status(session_expires_at=event.timestamp)
            elif event.kind == "connected":
                self._write_current_status(state="connected", connected_at=event.timestamp)

    def _base_status(self, state: str) -> VpnStatus:
        return VpnStatus(state=state, automatic_reconnect_enabled=self.preference.read(default=False), last_transition_at=self.now())

    _PRESERVE = object()

    def _write_current_status(
        self,
        *,
        state: Optional[str] = None,
        automatic: Optional[bool] = None,
        connected_at=_PRESERVE,
        session_expires_at=_PRESERVE,
        last_successful_hip_at=_PRESERVE,
        tunnel_interface=_PRESERVE,
        next_retry_at=_PRESERVE,
        error_code=_PRESERVE,
    ) -> None:
        with self._state_lock:
            previous = self._status
            new_state = state or previous.state
            transition = state is not None and new_state != previous.state
            if transition and new_state in {"disabled", "error", "connecting"}:
                default_clear = None
            else:
                default_clear = self._PRESERVE
            if transition and new_state == "backoff":
                connected_at = None if connected_at is self._PRESERVE else connected_at
                session_expires_at = None if session_expires_at is self._PRESERVE else session_expires_at
                last_successful_hip_at = None if last_successful_hip_at is self._PRESERVE else last_successful_hip_at
                tunnel_interface = None if tunnel_interface is self._PRESERVE else tunnel_interface
            elif default_clear is None:
                connected_at = None if connected_at is self._PRESERVE else connected_at
                session_expires_at = None if session_expires_at is self._PRESERVE else session_expires_at
                last_successful_hip_at = None if last_successful_hip_at is self._PRESERVE else last_successful_hip_at
                tunnel_interface = None if tunnel_interface is self._PRESERVE else tunnel_interface
                next_retry_at = None if next_retry_at is self._PRESERVE else next_retry_at
            if new_state == "connected":
                next_retry_at = None if next_retry_at is self._PRESERVE else next_retry_at
                error_code = None if error_code is self._PRESERVE else error_code
            elif new_state != "error":
                error_code = None if error_code is self._PRESERVE else error_code
            status = VpnStatus(
                state=new_state,
                automatic_reconnect_enabled=previous.automatic_reconnect_enabled if automatic is None else automatic,
                connected_at=previous.connected_at if connected_at is self._PRESERVE else connected_at,
                session_expires_at=previous.session_expires_at if session_expires_at is self._PRESERVE else session_expires_at,
                last_successful_hip_at=previous.last_successful_hip_at if last_successful_hip_at is self._PRESERVE else last_successful_hip_at,
                tunnel_interface=previous.tunnel_interface if tunnel_interface is self._PRESERVE else tunnel_interface,
                next_retry_at=previous.next_retry_at if next_retry_at is self._PRESERVE else next_retry_at,
                error_code=previous.error_code if error_code is self._PRESERVE else error_code,
                last_transition_at=self.now() if new_state != previous.state else previous.last_transition_at,
                backend_build_version=previous.backend_build_version,
            )
            write_status(self.config.status_path, status)
            self._status = status

    def run(self) -> int:
        lock_file = self._acquire_lock()
        if lock_file is None:
            return 75
        old_handlers: dict[int, object] = {}
        iterations = 0
        last_returncode = 0
        try:
            self._install_signal_handlers(old_handlers)
            self._start_control_server()
            while not self._stop_requested:
                if self._repair_required:
                    self._write_current_status(state="error", error_code="REPAIR_REQUIRED")
                    self._wait_for_control_or_stop(self.config.conflict_poll_interval)
                    continue
                if self._connector_failure_code is not None:
                    self._write_current_status(state="error", automatic=False, error_code=self._connector_failure_code)
                    self._wait_for_control_or_stop(self.config.conflict_poll_interval)
                    continue
                if not self.preference.read(default=False):
                    self._write_current_status(state="disabled", automatic=False)
                    self._wait_for_control_or_stop(self.config.conflict_poll_interval)
                    continue
                while not self._stop_requested and self.conflict_detector.conflict_active():
                    self._write_current_status(state="waiting-for-network", automatic=True)
                    self._wait_for_control_or_stop(self.config.conflict_poll_interval)
                    if not self.preference.read(default=False):
                        break
                if self._stop_requested:
                    break
                if not self.preference.read(default=False):
                    continue
                if self.readiness is not None:
                    self._write_current_status(state="waiting-for-network", automatic=True)
                    if not self.readiness.wait_until_ready(stop_requested=lambda: self._stop_requested):
                        break
                if self._stop_requested or not self.preference.read(default=False):
                    continue

                started_at = self.monotonic()
                iterations += 1
                self._write_current_status(state="connecting", automatic=self.preference.read(default=False))
                try:
                    generation = self._begin_new_generation()
                    child = self.popen_factory(
                        [self.config.connect_path],
                        start_new_session=True,
                        close_fds=True,
                        stdout=subprocess.PIPE,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        bufsize=1,
                    )
                    if not self._publish_started_child(child, generation):
                        with self._state_lock:
                            disconnecting = self._disconnect_in_progress
                        if disconnecting:
                            if not self._wait_for_child_cleared(timeout=self.config.stop_timeout):
                                self._enter_repair_required()
                                last_returncode = 1
                        elif not self._stop_helper_and_teardown_user_connector(keep_repair=True):
                            self._enter_repair_required()
                            last_returncode = 1
                        if self.config.max_iterations is not None and iterations >= self.config.max_iterations:
                            break
                        continue
                    self._start_stdout_reader(child, generation)
                except (OSError, subprocess.SubprocessError):
                    self._finish_failed_start()
                    last_returncode = 1
                    failures = self.policy.record_exit(1, runtime_seconds=0)
                    delay = self.policy.next_delay(failures)
                    if delay > 0:
                        self._write_current_status(state="backoff", next_retry_at=self.now() + timedelta(seconds=delay))
                    if self.config.max_iterations is not None and iterations >= self.config.max_iterations:
                        break
                    self._wait_for_control_or_stop(delay)
                    continue

                last_returncode = self._wait_for_child()
                if not self._join_stdout_reader():
                    last_returncode = 1
                self._invalidate_active_generation()
                runtime = self.monotonic() - started_at
                failures = self.policy.record_exit(last_returncode, runtime_seconds=runtime)
                with self._state_changed:
                    self._child = None
                    self._state_changed.notify_all()
                if self._stop_requested:
                    break
                with self._state_lock:
                    connector_repair_pending = self._connector_repair_pending
                    connector_failure_code = self._connector_failure_code
                if connector_repair_pending:
                    repair = self.command_runner(
                        ["/usr/bin/sudo", "-n", self.config.helper_path, "repair"],
                        self.config.helper_timeout,
                    )
                    with self._state_lock:
                        self._connector_repair_pending = False
                    if repair.returncode != 0:
                        self._enter_repair_required(automatic=False)
                    elif connector_failure_code is not None:
                        self._write_current_status(state="error", automatic=False, error_code=connector_failure_code)
                    if self.config.max_iterations is not None and iterations >= self.config.max_iterations:
                        break
                    if connector_failure_code is not None or repair.returncode != 0:
                        self._wait_for_control_or_stop(self.config.conflict_poll_interval)
                    continue
                if not self.preference.read(default=False):
                    self._write_current_status(state="disabled", automatic=False)
                    if self.config.max_iterations is not None and iterations >= self.config.max_iterations:
                        break
                    self._wait_for_control_or_stop(self.config.conflict_poll_interval)
                    continue
                delay = self.policy.next_delay(max(failures, 1))
                if delay > 0:
                    self._write_current_status(state="backoff", next_retry_at=self.now() + timedelta(seconds=delay))
                if self.config.max_iterations is not None and iterations >= self.config.max_iterations:
                    break
                self._wait_for_control_or_stop(delay)
            return last_returncode
        finally:
            self._restore_signal_handlers(old_handlers)
            self._stop_control_server()
            if self._child is not None and self._child.poll() is None:
                self._stop_child()
            self._join_stdout_reader()
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

    def _start_control_server(self) -> None:
        self._control_server = ControlServer(self.config.control_socket_path, self.handle_control_command)
        self._control_thread = threading.Thread(
            target=self._control_server.serve_forever,
            args=(self._stop_event,),
            name="hyu-vpn-control",
            daemon=True,
        )
        self._control_thread.start()
        self._control_server.wait_until_ready(timeout=2.0)

    def _stop_control_server(self) -> None:
        self._stop_event.set()
        thread = self._control_thread
        if thread is not None:
            thread.join(timeout=1.0)
        self._control_thread = None
        self._control_server = None

    def _install_signal_handlers(self, old_handlers: dict[int, object]) -> None:
        if threading.current_thread() is not threading.main_thread():
            return
        for signum in (signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, self._handle_signal)

    def _restore_signal_handlers(self, old_handlers: dict[int, object]) -> None:
        if not old_handlers:
            return
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)

    def _handle_signal(self, signum: int, _frame: Optional[FrameType]) -> None:
        self._stop_requested = True
        self._stop_event.set()
        self._control_event.set()
        self._stop_child(signum)

    def _finish_failed_start(self) -> None:
        with self._state_changed:
            self._starting_generation = None
            self._active_generation = None
            self._state_changed.notify_all()

    def _begin_new_generation(self) -> int:
        with self._state_changed:
            self._next_generation += 1
            self._active_generation = self._next_generation
            self._starting_generation = self._active_generation
            self._state_changed.notify_all()
            return self._active_generation

    def _publish_started_child(self, child: subprocess.Popen, generation: int) -> bool:
        with self._state_changed:
            self._starting_generation = None
            self._child = child
            accepted = self._active_generation == generation and not self._repair_required and self.preference.read(default=False)
            self._state_changed.notify_all()
            return accepted

    def _start_stdout_reader(self, child: subprocess.Popen, generation: Optional[int] = None) -> None:
        stdout = getattr(child, "stdout", None)
        if stdout is None:
            self._stdout_reader = None
            return

        def drain() -> None:
            try:
                while True:
                    line = stdout.readline(513)
                    if line == "":
                        return
                    if len(line.encode("utf-8", errors="replace")) > 512 and not line.endswith("\n"):
                        self._discard_oversize_stdout_line(stdout)
                        continue
                    self.apply_connector_event_line(line, generation=generation)
            except (OSError, ValueError):
                return
            finally:
                try:
                    stdout.close()
                except OSError:
                    pass

        self._stdout_reader = threading.Thread(target=drain, name="hyu-vpn-connector-events", daemon=True)
        self._stdout_reader.start()

    def _discard_oversize_stdout_line(self, stdout) -> None:
        for _ in range(8):
            chunk = stdout.readline(513)
            if chunk == "" or chunk.endswith("\n"):
                return

    def _join_stdout_reader(self) -> bool:
        reader = self._stdout_reader
        if reader is None:
            return True
        reader.join(timeout=1.0)
        if reader.is_alive():
            self._enter_repair_required()
            return False
        if self._stdout_reader is reader:
            self._stdout_reader = None
        return True

    def _wait_for_child(self) -> int:
        with self._state_lock:
            child = self._child
        if child is None:
            return 0
        return child.wait() or 0

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
        if self.sleep is not None:
            self.sleep(delay)
        else:
            self._stop_event.wait(delay)

    def _wait_for_control_or_stop(self, delay: float) -> None:
        if delay <= 0 or self._stop_requested:
            return
        if self.sleep is not None:
            self.sleep(delay)
            return
        self._control_event.wait(delay)
        self._control_event.clear()


def main(argv: Optional[Sequence[str]] = None) -> int:
    if argv:
        sys.stderr.write("hyu-vpn-service does not accept arguments\n")
        return 2
    helper_provider = HelperOwnedSessionProvider()
    detector = NativeConflictDetector(owned_session_provider=helper_provider.evidence, native_status=production_status_reader().read_state)
    return Supervisor(conflict_detector=detector, readiness=NetworkReadiness()).run()
