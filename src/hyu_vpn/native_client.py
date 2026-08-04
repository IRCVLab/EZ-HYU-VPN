"""Reversible GlobalProtect native client auto-launch and status handling."""

from __future__ import annotations

import json
import os
import re
import subprocess
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


class AutoLaunchStore(Protocol):
    def list_mechanisms(self) -> list[AutoLaunchMechanism]: ...
    def set_enabled(self, identifier: str, enabled: bool) -> None: ...


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
_KNOWN_GLOBALPROTECT_IDS = {target.label for target in _TARGETS} | {"com.paloaltonetworks.GlobalProtect.client"}
_RECORD_KEYS = {"schema_version", "console_uid", "mechanisms"}
_MECHANISM_KEYS = {"identifier", "kind", "enabled", "exact_target"}


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
        mechanisms = self.store.list_mechanisms()
        targets = [m for m in mechanisms if _is_known_gp(m)]
        ambiguous = [m for m in mechanisms if not _is_known_gp(m) and _is_suspicious_gp(m)]
        if ambiguous:
            raise NativeClientConflict("ambiguous GlobalProtect auto-launch mechanism")
        record = {
            "schema_version": 1,
            "console_uid": self.console_uid,
            "mechanisms": [asdict(m) for m in targets],
        }
        self._write_record(Path(record_path), record)
        for mechanism in targets:
            if mechanism.enabled:
                self.store.set_enabled(mechanism.identifier, False)

    def restore_auto_launch(self, record_path: os.PathLike[str] | str) -> None:
        data = self._read_record(Path(record_path))
        recorded = [AutoLaunchMechanism(**item) for item in data["mechanisms"]]
        current = {m.identifier: m for m in self.store.list_mechanisms()}
        changes: list[tuple[str, bool]] = []
        for mechanism in recorded:
            now = current.get(mechanism.identifier)
            if now is None or now.kind != mechanism.kind or now.exact_target != mechanism.exact_target:
                raise NativeClientConflict("recorded native auto-launch target changed")
            expected_suppressed = False if mechanism.enabled else mechanism.enabled
            if now.enabled != expected_suppressed:
                raise NativeClientConflict("native auto-launch state was modified by user")
            if mechanism.enabled:
                changes.append((mechanism.identifier, True))
        for identifier, enabled in changes:
            self.store.set_enabled(identifier, enabled)

    def _read_record(self, path: Path) -> dict:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise NativeClientConflict("missing or corrupt native suppression record") from None
        if not isinstance(data, dict) or set(data) != _RECORD_KEYS:
            raise NativeClientConflict("invalid native suppression record schema")
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
        for item in mechanisms:
            if not isinstance(item, dict) or set(item) != _MECHANISM_KEYS:
                raise NativeClientConflict("invalid native suppression record mechanism")
            try:
                mechanism = AutoLaunchMechanism(**item)
            except TypeError:
                raise NativeClientConflict("invalid native suppression record mechanism") from None
            if not _valid_mechanism(mechanism):
                raise NativeClientConflict("invalid native suppression record mechanism")
        return data

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
        and mechanism.identifier in _KNOWN_GLOBALPROTECT_IDS
        and isinstance(mechanism.kind, str)
        and mechanism.kind in {"launchd-system", "launchd-gui", "launchd", "login-item"}
        and isinstance(mechanism.enabled, bool)
        and isinstance(mechanism.exact_target, str)
        and mechanism.exact_target.startswith("/")
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
            mechanisms.append(AutoLaunchMechanism(target.label, target.kind, not disabled, target.plist_path))
        return mechanisms

    def set_enabled(self, identifier: str, enabled: bool) -> None:
        target = self._target_for(identifier)
        verb = "enable" if enabled else "disable"
        argv = ["/bin/launchctl", verb, f"{self._domain(target)}/{target.label}"]
        result = self.runner(argv, self.timeout)
        if getattr(result, "returncode", 1) != 0:
            raise NativeClientConflict("launchctl state change failed")

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
