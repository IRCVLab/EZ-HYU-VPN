"""Reversible GlobalProtect native client auto-launch and status handling."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional, Protocol, Set


class NativeClientConflict(RuntimeError):
    """Raised when native client state is ambiguous or user-modified."""


@dataclass(frozen=True)
class AutoLaunchMechanism:
    identifier: str
    kind: str
    enabled: bool
    exact_target: str
    running: bool = False


class AutoLaunchStore(Protocol):
    def list_mechanisms(self) -> list[AutoLaunchMechanism]: ...
    def set_enabled(self, identifier: str, enabled: bool) -> None: ...
    def stop_running(self, identifier: str) -> None: ...
    def start_running(self, identifier: str) -> None: ...
    def is_running(self, identifier: str) -> bool: ...


@dataclass(frozen=True)
class _LaunchdTarget:
    label: str
    domain: str
    kind: str
    plist_path: str
    program_path: str


_TARGETS = (
    _LaunchdTarget(
        "com.paloaltonetworks.gp.pangpsd",
        "system",
        "launchd-system",
        "/Library/LaunchDaemons/com.paloaltonetworks.gp.pangpsd.plist",
        "/Applications/GlobalProtect.app/Contents/Resources/PanGPS",
    ),
    _LaunchdTarget(
        "com.paloaltonetworks.gp.pangpa",
        "gui/{uid}",
        "launchd-gui",
        "/Library/LaunchAgents/com.paloaltonetworks.gp.pangpa.plist",
        "/Applications/GlobalProtect.app/Contents/MacOS/GlobalProtect",
    ),
    _LaunchdTarget(
        "com.paloaltonetworks.gp.pangps",
        "gui/{uid}",
        "launchd-gui",
        "/Library/LaunchAgents/com.paloaltonetworks.gp.pangps.plist",
        "/Applications/GlobalProtect.app/Contents/Resources/PanGPS",
    ),
)
_EXACT_AUTO_LAUNCH_TARGETS = {
    (target.label, target.kind, target.plist_path) for target in _TARGETS
}
_KNOWN_GLOBALPROTECT_IDS = {target.label for target in _TARGETS} | {"com.paloaltonetworks.GlobalProtect.client"}
_RECORD_KEYS = {"schema_version", "console_uid", "mechanisms"}
_MECHANISM_KEYS = {"identifier", "kind", "enabled", "exact_target", "running"}


def _is_known_gp(mechanism: AutoLaunchMechanism) -> bool:
    return mechanism.identifier in _KNOWN_GLOBALPROTECT_IDS


def _is_suspicious_gp(mechanism: AutoLaunchMechanism) -> bool:
    haystack = f"{mechanism.identifier} {mechanism.exact_target}".lower()
    return "globalprotect" in haystack or "paloaltonetworks.gp" in haystack


class NativeAutoLaunchManager:
    def __init__(self, *, store: AutoLaunchStore, console_uid: Optional[int] = None) -> None:
        self.store = store
        self.console_uid = console_uid

    def suppress_auto_launch(self, record_path: os.PathLike[str] | str) -> None:
        path = Path(record_path)
        mechanisms = self.store.list_mechanisms()
        targets = [m for m in mechanisms if _is_known_gp(m)]
        ambiguous = [m for m in mechanisms if not _is_known_gp(m) and _is_suspicious_gp(m)]
        if ambiguous:
            raise NativeClientConflict("ambiguous GlobalProtect auto-launch mechanism")
        self._validate_mechanism_list(targets)
        enabled_applied: list[str] = []
        stopped_applied: list[str] = []
        self._write_journal(path, targets, phase="preparing", applied_identifiers=enabled_applied, stopped_identifiers=stopped_applied, pending_identifier=None)
        try:
            for mechanism in targets:
                if mechanism.enabled:
                    self._write_journal(path, targets, phase="disabling", applied_identifiers=enabled_applied, stopped_identifiers=stopped_applied, pending_identifier=mechanism.identifier)
                    self.store.set_enabled(mechanism.identifier, False)
                    enabled_applied.append(mechanism.identifier)
                    self._write_journal(path, targets, phase="disabling", applied_identifiers=enabled_applied, stopped_identifiers=stopped_applied, pending_identifier=None)
                if mechanism.running:
                    self._write_journal(path, targets, phase="stopping", applied_identifiers=enabled_applied, stopped_identifiers=stopped_applied, pending_identifier=mechanism.identifier)
                    self.store.stop_running(mechanism.identifier)
                    if self.store.is_running(mechanism.identifier):
                        raise NativeClientConflict("native auto-launch job still running")
                    stopped_applied.append(mechanism.identifier)
                    self._write_journal(path, targets, phase="stopping", applied_identifiers=enabled_applied, stopped_identifiers=stopped_applied, pending_identifier=None)
        except Exception as exc:
            try:
                data = self._read_record(path)
                self._restore_interrupted_journal(path, data)
            except Exception:
                try:
                    data = self._read_record(path)
                    if data.get("phase") is not None:
                        self._write_journal(
                            path,
                            [AutoLaunchMechanism(**item) for item in data["mechanisms"]],
                            phase="rollback-required",
                            applied_identifiers=list(data["applied_identifiers"]),
                            stopped_identifiers=list(data.get("stopped_identifiers", [])),
                            pending_identifier=data.get("pending_identifier"),
                        )
                    else:
                        self._write_journal(path, targets, phase="rollback-required", applied_identifiers=enabled_applied, stopped_identifiers=stopped_applied, pending_identifier=None)
                except Exception:
                    self._write_journal(path, targets, phase="rollback-required", applied_identifiers=enabled_applied, stopped_identifiers=stopped_applied, pending_identifier=None)
            if isinstance(exc, NativeClientConflict):
                raise exc
            raise NativeClientConflict("native auto-launch suppression failed") from None
        record = {
            "schema_version": 1,
            "console_uid": self.console_uid,
            "mechanisms": [asdict(m) for m in targets],
        }
        self._write_record(path, record)

    def restore_auto_launch(self, record_path: os.PathLike[str] | str) -> None:
        path = Path(record_path)
        data = self._read_record(path)
        if data.get("phase") is not None:
            self._restore_interrupted_journal(path, data)
            return
        recorded = [AutoLaunchMechanism(**item) for item in data["mechanisms"]]
        current = {m.identifier: m for m in self.store.list_mechanisms()}
        changes: list[tuple[str, bool]] = []
        starts: list[str] = []
        for mechanism in recorded:
            now = current.get(mechanism.identifier)
            if now is None or now.kind != mechanism.kind or now.exact_target != mechanism.exact_target:
                raise NativeClientConflict("recorded native auto-launch target changed")
            expected_suppressed = False if mechanism.enabled else mechanism.enabled
            if now.enabled != expected_suppressed:
                raise NativeClientConflict("native auto-launch state was modified by user")
            if now.running:
                raise NativeClientConflict("native auto-launch state was modified by user")
            if mechanism.enabled:
                changes.append((mechanism.identifier, True))
            if mechanism.running:
                starts.append(mechanism.identifier)
        for identifier, enabled in changes:
            self.store.set_enabled(identifier, enabled)
        by_record_id = {m.identifier: m for m in recorded}
        for identifier in starts:
            mechanism = by_record_id[identifier]
            temporarily_enabled = False
            if not mechanism.enabled:
                self.store.set_enabled(identifier, True)
                temporarily_enabled = True
            try:
                self.store.start_running(identifier)
            except Exception:
                if temporarily_enabled:
                    self.store.set_enabled(identifier, False)
                raise
            if temporarily_enabled:
                self.store.set_enabled(identifier, False)
        self._remove_record(path)

    def _restore_interrupted_journal(self, path: Path, data: dict) -> None:
        recorded = [AutoLaunchMechanism(**item) for item in data["mechanisms"]]
        enabled_applied = list(data["applied_identifiers"])
        stopped_applied = list(data.get("stopped_identifiers", []))
        pending = data.get("pending_identifier")
        phase = data["phase"]
        if phase == "preparing":
            self._remove_record(path)
            return
        by_id = {m.identifier: m for m in recorded}
        current = {m.identifier: m for m in self.store.list_mechanisms()}
        if pending is not None:
            mechanism = by_id[pending]
            now = current.get(pending)
            if now is None or now.kind != mechanism.kind or now.exact_target != mechanism.exact_target:
                raise NativeClientConflict("recorded native auto-launch target changed")
            if phase in {"disabling", "rollback-required"} and mechanism.enabled and not now.enabled and pending not in enabled_applied:
                enabled_applied.append(pending)
            if phase in {"stopping", "rollback-required"} and mechanism.running and not self.store.is_running(pending) and pending not in stopped_applied:
                stopped_applied.append(pending)
        if not enabled_applied and not stopped_applied:
            self._remove_record(path)
            return
        remaining_enabled = list(enabled_applied)
        remaining_stopped = list(stopped_applied)
        for identifier in set(enabled_applied + stopped_applied):
            mechanism = by_id[identifier]
            now = current.get(identifier)
            if now is None or now.kind != mechanism.kind or now.exact_target != mechanism.exact_target:
                raise NativeClientConflict("recorded native auto-launch target changed")
        self._write_journal(path, recorded, phase="rolling-back", applied_identifiers=remaining_enabled, stopped_identifiers=remaining_stopped, pending_identifier=None)
        try:
            for identifier in reversed(enabled_applied):
                now = current[identifier]
                if not now.enabled:
                    self.store.set_enabled(identifier, True)
                if identifier in remaining_enabled:
                    remaining_enabled.remove(identifier)
                self._write_journal(path, recorded, phase="rolling-back", applied_identifiers=remaining_enabled, stopped_identifiers=remaining_stopped, pending_identifier=None)
            for identifier in reversed(stopped_applied):
                mechanism = by_id[identifier]
                temporarily_enabled = False
                if not self.store.is_running(identifier):
                    if not mechanism.enabled:
                        self.store.set_enabled(identifier, True)
                        temporarily_enabled = True
                    try:
                        self.store.start_running(identifier)
                    except Exception:
                        if temporarily_enabled:
                            self.store.set_enabled(identifier, False)
                        raise
                    if temporarily_enabled:
                        self.store.set_enabled(identifier, False)
                if identifier in remaining_stopped:
                    remaining_stopped.remove(identifier)
                self._write_journal(path, recorded, phase="rolling-back", applied_identifiers=remaining_enabled, stopped_identifiers=remaining_stopped, pending_identifier=None)
        except Exception as exc:
            self._write_journal(path, recorded, phase="rollback-required", applied_identifiers=remaining_enabled, stopped_identifiers=remaining_stopped, pending_identifier=None)
            if isinstance(exc, NativeClientConflict):
                raise exc
            raise NativeClientConflict("native auto-launch rollback failed") from None
        self._remove_record(path)

    def _write_journal(self, path: Path, mechanisms: list[AutoLaunchMechanism], *, phase: str, applied_identifiers: list[str], stopped_identifiers: list[str], pending_identifier: Optional[str]) -> None:
        self._write_record(path, {
            "schema_version": 1,
            "console_uid": self.console_uid,
            "phase": phase,
            "pending_identifier": pending_identifier,
            "mechanisms": [asdict(m) for m in mechanisms],
            "applied_identifiers": list(applied_identifiers),
            "stopped_identifiers": list(stopped_identifiers),
        })

    def _remove_record(self, path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            raise NativeClientConflict("could not remove native suppression record") from None

    def _read_record(self, path: Path) -> dict:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise NativeClientConflict("missing or corrupt native suppression record") from None
        if not isinstance(data, dict):
            raise NativeClientConflict("invalid native suppression record schema")
        phase = data.get("phase")
        if phase is None:
            if set(data) != _RECORD_KEYS:
                raise NativeClientConflict("invalid native suppression record schema")
        elif phase in {"preparing", "disabling", "stopping", "rolling-back", "rollback-required"}:
            journal_keys = set(data)
            if journal_keys == {"schema_version", "console_uid", "phase", "pending_identifier", "mechanisms", "applied_identifiers"}:
                data["stopped_identifiers"] = []
            elif journal_keys != {"schema_version", "console_uid", "phase", "pending_identifier", "mechanisms", "applied_identifiers", "stopped_identifiers"}:
                raise NativeClientConflict("invalid native rollback journal schema")
        else:
            raise NativeClientConflict("native suppression journal is not restorable")
        if data.get("schema_version") != 1:
            raise NativeClientConflict("unsupported native suppression record schema")
        record_uid = data.get("console_uid")
        if record_uid is not None and (not isinstance(record_uid, int) or record_uid < 0):
            raise NativeClientConflict("invalid native suppression record uid")
        if self.console_uid is not None and record_uid != self.console_uid:
            raise NativeClientConflict("native suppression record belongs to a different console uid")
        mechanisms = data.get("mechanisms")
        if not isinstance(mechanisms, list):
            raise NativeClientConflict("invalid native suppression record mechanisms")
        parsed: list[AutoLaunchMechanism] = []
        normalized_mechanisms: list[dict] = []
        legacy_keys = {"identifier", "kind", "enabled", "exact_target"}
        for item in mechanisms:
            if not isinstance(item, dict) or (set(item) != _MECHANISM_KEYS and set(item) != legacy_keys):
                raise NativeClientConflict("invalid native suppression record mechanism")
            normalized = dict(item)
            normalized.setdefault("running", False)
            try:
                mechanism = AutoLaunchMechanism(**normalized)
            except TypeError:
                raise NativeClientConflict("invalid native suppression record mechanism") from None
            if not _valid_mechanism(mechanism):
                raise NativeClientConflict("invalid native suppression record mechanism")
            parsed.append(mechanism)
            normalized_mechanisms.append(normalized)
        data["mechanisms"] = normalized_mechanisms
        if phase is not None:
            applied = data.get("applied_identifiers")
            stopped = data.get("stopped_identifiers")
            ids = {m.identifier for m in parsed}
            if not isinstance(applied, list) or any(not isinstance(i, str) or i not in ids for i in applied):
                raise NativeClientConflict("invalid native rollback journal applied targets")
            if not isinstance(stopped, list) or any(not isinstance(i, str) or i not in ids for i in stopped):
                raise NativeClientConflict("invalid native rollback journal stopped targets")
            if len(applied) != len(set(applied)):
                raise NativeClientConflict("invalid native rollback journal applied targets")
            if len(stopped) != len(set(stopped)):
                raise NativeClientConflict("invalid native rollback journal stopped targets")
            pending = data.get("pending_identifier")
            if pending is not None and (not isinstance(pending, str) or pending not in ids):
                raise NativeClientConflict("invalid native rollback journal pending target")
            if pending is not None and pending in stopped:
                raise NativeClientConflict("invalid native rollback journal pending target")
            if pending is not None and pending in applied and phase not in {"stopping", "rollback-required"}:
                raise NativeClientConflict("invalid native rollback journal pending target")
            if phase == "preparing" and (applied or stopped or pending is not None):
                raise NativeClientConflict("invalid native preparing journal applied targets")
            if phase == "rolling-back" and pending is not None:
                raise NativeClientConflict("invalid native rollback journal pending target")
        return data

    def _validate_mechanism_list(self, mechanisms: list[AutoLaunchMechanism]) -> None:
        for mechanism in mechanisms:
            if not _valid_mechanism(mechanism):
                raise NativeClientConflict("invalid GlobalProtect auto-launch target")

    def _write_record(self, path: Path, record: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(record, fh, indent=2, sort_keys=True)
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            os.chmod(path, 0o600)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise NativeClientConflict("could not write native suppression record") from None


def _valid_mechanism(mechanism: AutoLaunchMechanism) -> bool:
    return (
        isinstance(mechanism.identifier, str)
        and isinstance(mechanism.kind, str)
        and isinstance(mechanism.enabled, bool)
        and isinstance(mechanism.exact_target, str)
        and isinstance(mechanism.running, bool)
        and (mechanism.identifier, mechanism.kind, mechanism.exact_target) in _EXACT_AUTO_LAUNCH_TARGETS
    )


class _RealFS:
    def is_file(self, path: Path) -> bool:
        return path.is_file()

    def is_symlink(self, path: Path) -> bool:
        return path.is_symlink()

    def stat(self, path: Path):
        return path.stat()

    def read_plist(self, path: Path) -> dict:
        import plistlib
        with path.open("rb") as fh:
            return plistlib.load(fh)

    def read_text(self, path: Path) -> str:
        return path.read_text(encoding="utf-8", errors="replace")

    def open_binary(self, path: Path):
        return path.open("rb")


class MacOSLaunchctlAutoLaunchStore:
    def __init__(self, *, console_uid: int, fs: object = None, runner=None, timeout: float = 2.0) -> None:
        self.console_uid = console_uid
        self.fs = fs or _RealFS()
        self.runner = runner or _run_subprocess
        self.timeout = timeout

    def list_mechanisms(self) -> list[AutoLaunchMechanism]:
        disabled_by_domain = {
            "system": self._print_disabled("system"),
            f"gui/{self.console_uid}": self._print_disabled(f"gui/{self.console_uid}"),
        }
        mechanisms = []
        for target in _TARGETS:
            domain = self._domain(target)
            path = Path(target.plist_path)
            if not self.fs.is_file(path):
                continue
            self._validate_plist(path, target)
            disabled = disabled_by_domain.get(domain, {}).get(target.label, False)
            mechanisms.append(AutoLaunchMechanism(target.label, target.kind, not disabled, target.plist_path, self._is_running(target)))
        return mechanisms

    def set_enabled(self, identifier: str, enabled: bool) -> None:
        target = self._target_for(identifier)
        verb = "enable" if enabled else "disable"
        argv = ["/bin/launchctl", verb, f"{self._domain(target)}/{target.label}"]
        result = self.runner(argv, self.timeout)
        if getattr(result, "returncode", 1) != 0:
            raise NativeClientConflict("launchctl state change failed")

    def stop_running(self, identifier: str) -> None:
        target = self._target_for(identifier)
        result = self.runner(["/bin/launchctl", "bootout", f"{self._domain(target)}/{target.label}"], self.timeout)
        if getattr(result, "returncode", 0) not in {0, 3, 36}:
            raise NativeClientConflict("launchctl bootout failed")

    def start_running(self, identifier: str) -> None:
        target = self._target_for(identifier)
        result = self.runner(["/bin/launchctl", "bootstrap", self._domain(target), target.plist_path], self.timeout)
        if getattr(result, "returncode", 1) != 0:
            raise NativeClientConflict("launchctl bootstrap failed")

    def is_running(self, identifier: str) -> bool:
        target = self._target_for(identifier)
        return self._is_running(target)

    def _is_running(self, target: _LaunchdTarget) -> bool:
        result = self.runner(["/bin/launchctl", "print", f"{self._domain(target)}/{target.label}"], self.timeout)
        if getattr(result, "returncode", 1) != 0:
            return False
        return "state = running" in getattr(result, "stdout", "") or "state = waiting" in getattr(result, "stdout", "")

    def _print_disabled(self, domain: str) -> dict[str, bool]:
        result = self.runner(["/bin/launchctl", "print-disabled", domain], self.timeout)
        if getattr(result, "returncode", 1) != 0:
            raise NativeClientConflict("launchctl print-disabled failed")
        states: dict[str, bool] = {}
        for line in getattr(result, "stdout", "").splitlines():
            match = re.search(r'"([^"]+)"\s*=>\s*(true|false)', line)
            if match:
                states[match.group(1)] = match.group(2) == "true"
        return states

    def _domain(self, target: _LaunchdTarget) -> str:
        return target.domain.format(uid=self.console_uid)

    def _target_for(self, identifier: str) -> _LaunchdTarget:
        for target in _TARGETS:
            if target.label == identifier:
                return target
        raise NativeClientConflict("unknown GlobalProtect auto-launch target")

    def _validate_plist(self, path: Path, target: _LaunchdTarget) -> None:
        if self.fs.is_symlink(path):
            raise NativeClientConflict("refusing symlinked GlobalProtect plist")
        st = self.fs.stat(path)
        if getattr(st, "st_uid", None) != 0 or (getattr(st, "st_mode", 0) & 0o777) not in {0o644, 0o600}:
            raise NativeClientConflict("unsafe GlobalProtect plist ownership or mode")
        data = self.fs.read_plist(path)
        if data.get("Label") != target.label:
            raise NativeClientConflict("unexpected GlobalProtect plist label")
        program = data.get("Program")
        args = data.get("ProgramArguments")
        arg0 = args[0] if isinstance(args, list) and args else None
        if program is None and arg0 is None:
            raise NativeClientConflict("unexpected GlobalProtect plist program")
        if program is not None and program != target.program_path:
            raise NativeClientConflict("unexpected GlobalProtect plist program")
        if arg0 is not None and arg0 != target.program_path:
            raise NativeClientConflict("unexpected GlobalProtect plist program")
        if program is not None and arg0 is not None and program != arg0:
            raise NativeClientConflict("unexpected GlobalProtect plist program")


def _run_subprocess(argv: list[str], timeout: float):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return type("Result", (), {"returncode": 1, "stdout": "", "stderr": exc.__class__.__name__})()


def production_auto_launch_manager(*, console_uid: int, fs: object = None, runner=None) -> NativeAutoLaunchManager:
    return NativeAutoLaunchManager(store=MacOSLaunchctlAutoLaunchStore(console_uid=console_uid, fs=fs, runner=runner), console_uid=console_uid)


def suppress_globalprotect_auto_launch(record_path: os.PathLike[str] | str, *, console_uid: int, fs: object = None, runner=None) -> None:
    production_auto_launch_manager(console_uid=console_uid, fs=fs, runner=runner).suppress_auto_launch(record_path)


def restore_globalprotect_auto_launch(record_path: os.PathLike[str] | str, *, console_uid: int, fs: object = None, runner=None) -> None:
    production_auto_launch_manager(console_uid=console_uid, fs=fs, runner=runner).restore_auto_launch(record_path)


class GlobalProtectStatusReader:
    _STATE_RE = re.compile(r"<state>\s*(Connected|Connecting|Disconnected)\s*</state>|\bSTATE_TUNNEL_(CONNECTED|CONNECTING|DISCONNECTED)\b", re.IGNORECASE)

    def __init__(self, *, path: Path, fs: object = None, clock=time.time, max_age: float = 120.0, max_bytes: int = 65536) -> None:
        self.path = path
        self.fs = fs or _RealFS()
        self.clock = clock
        self.max_age = max_age
        self.max_bytes = max_bytes

    def read_state(self) -> str:
        try:
            st = self.fs.stat(self.path)
            if self.clock() - getattr(st, "st_mtime", 0) > self.max_age:
                return "unknown"
            raw = self._read_tail_bytes()
            text = raw.decode("utf-8", errors="replace")
        except OSError:
            return "unknown"
        latest = None
        for match in self._STATE_RE.finditer(text):
            token = match.group(1) or match.group(2) or ""
            latest = token.lower()
        return latest if latest in {"connected", "connecting", "disconnected"} else "unknown"

    def _read_tail_bytes(self) -> bytes:
        with self.fs.open_binary(self.path) as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            start = max(0, size - self.max_bytes)
            fh.seek(start, os.SEEK_SET)
            return fh.read(self.max_bytes)


def production_status_reader() -> GlobalProtectStatusReader:
    return GlobalProtectStatusReader(path=Path.home() / "Library" / "Logs" / "PaloAltoNetworks" / "GlobalProtect" / "PanGPA.log")


NATIVE_SUPPRESSION_RECORD_PATH = Path("/private/var/db/hyu-vpn/native-suppression.json")
_NATIVE_CLIENT_CLI_COMMANDS = {"suppress-auto-launch", "restore-auto-launch"}


def _active_console_uid_from_dev_console() -> int:
    try:
        return int(os.stat("/dev/console").st_uid)
    except (OSError, TypeError, ValueError):
        raise NativeClientConflict("could not determine active console uid") from None


def _native_cli_emit(sink, payload: dict) -> None:
    sink(json.dumps(payload, sort_keys=True))


def _print_stderr(message: str) -> None:
    print(message, file=sys.stderr)


def native_client_cli_main(
    argv: Optional[list[str]] = None,
    *,
    env: Optional[dict[str, str]] = None,
    geteuid=os.geteuid,
    active_console_uid=_active_console_uid_from_dev_console,
    suppress=suppress_globalprotect_auto_launch,
    restore=restore_globalprotect_auto_launch,
    stdout=print,
    stderr=_print_stderr,
) -> int:
    args = list(argv if argv is not None else [])
    if len(args) != 1 or args[0] not in _NATIVE_CLIENT_CLI_COMMANDS:
        _native_cli_emit(stderr, {"schema_version": 1, "ok": False, "error_code": "BAD_REQUEST"})
        return 2
    operation = args[0]
    if geteuid() != 0:
        _native_cli_emit(stderr, {"schema_version": 1, "ok": False, "error_code": "ROOT_REQUIRED"})
        return 77
    environ = os.environ if env is None else env
    raw_sudo_uid = environ.get("SUDO_UID")
    try:
        sudo_uid = int(raw_sudo_uid) if raw_sudo_uid is not None else 0
    except (TypeError, ValueError):
        _native_cli_emit(stderr, {"schema_version": 1, "ok": False, "error_code": "SUDO_UID_REQUIRED"})
        return 77
    if sudo_uid <= 0:
        _native_cli_emit(stderr, {"schema_version": 1, "ok": False, "error_code": "SUDO_UID_REQUIRED"})
        return 77
    try:
        console_uid = int(active_console_uid())
    except Exception:
        _native_cli_emit(stderr, {"schema_version": 1, "ok": False, "error_code": "CONSOLE_UID_MISMATCH"})
        return 77
    if console_uid != sudo_uid:
        _native_cli_emit(stderr, {"schema_version": 1, "ok": False, "error_code": "CONSOLE_UID_MISMATCH"})
        return 77
    try:
        if operation == "suppress-auto-launch":
            suppress(NATIVE_SUPPRESSION_RECORD_PATH, console_uid=console_uid)
        else:
            restore(NATIVE_SUPPRESSION_RECORD_PATH, console_uid=console_uid)
    except NativeClientConflict:
        _native_cli_emit(stderr, {"schema_version": 1, "ok": False, "error_code": "NATIVE_CLIENT_CONFLICT"})
        return 1
    except Exception:
        _native_cli_emit(stderr, {"schema_version": 1, "ok": False, "error_code": "NATIVE_CLIENT_FAILED"})
        return 1
    _native_cli_emit(stdout, {"schema_version": 1, "ok": True, "operation": operation})
    return 0


@dataclass(frozen=True)
class NativeClientState:
    processes: Set[str]
    route_interface: Optional[str]
    status: str
    hyu_enabled: bool = True

    def blocks_openconnect(self) -> bool:
        if not self.hyu_enabled:
            return False
        normalized = self.status.lower()
        if normalized == "disconnected":
            return False
        if normalized == "connecting":
            return bool(self.processes & {"PanGPS", "PanGPA", "GlobalProtect"})
        if normalized == "connected":
            if self.route_interface is not None and self.route_interface.startswith("utun"):
                return True
            return bool(self.processes & {"PanGPS", "PanGPA", "GlobalProtect"})
        if self.route_interface is not None and self.route_interface.startswith("utun"):
            return True
        return False
