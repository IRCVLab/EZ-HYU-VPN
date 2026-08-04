"""Reversible GlobalProtect native client auto-launch suppression."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional, Protocol, Set


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


_KNOWN_GLOBALPROTECT_IDS = {
    "com.paloaltonetworks.gp.pangps",
    "com.paloaltonetworks.GlobalProtect.client",
}


def _is_known_gp(mechanism: AutoLaunchMechanism) -> bool:
    return mechanism.identifier in _KNOWN_GLOBALPROTECT_IDS


def _is_suspicious_gp(mechanism: AutoLaunchMechanism) -> bool:
    haystack = f"{mechanism.identifier} {mechanism.exact_target}".lower()
    return "globalprotect" in haystack or "paloaltonetworks.gp" in haystack


class NativeAutoLaunchManager:
    def __init__(self, *, store: AutoLaunchStore) -> None:
        self.store = store

    def suppress_auto_launch(self, record_path: os.PathLike[str] | str) -> None:
        mechanisms = self.store.list_mechanisms()
        targets = [m for m in mechanisms if _is_known_gp(m)]
        ambiguous = [m for m in mechanisms if not _is_known_gp(m) and _is_suspicious_gp(m)]
        if ambiguous:
            raise NativeClientConflict("ambiguous GlobalProtect auto-launch mechanism")
        record = {"mechanisms": [asdict(m) for m in targets]}
        self._write_record(Path(record_path), record)
        for mechanism in targets:
            if mechanism.enabled:
                self.store.set_enabled(mechanism.identifier, False)

    def restore_auto_launch(self, record_path: os.PathLike[str] | str) -> None:
        path = Path(record_path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise NativeClientConflict("missing or corrupt native suppression record") from None
        recorded = [AutoLaunchMechanism(**item) for item in data.get("mechanisms", [])]
        current = {m.identifier: m for m in self.store.list_mechanisms()}
        for mechanism in recorded:
            now = current.get(mechanism.identifier)
            if now is None or now.kind != mechanism.kind or now.exact_target != mechanism.exact_target:
                raise NativeClientConflict("recorded native auto-launch target changed")
            expected_suppressed = False if mechanism.enabled else mechanism.enabled
            if now.enabled != expected_suppressed:
                raise NativeClientConflict("native auto-launch state was modified by user")
        for mechanism in recorded:
            if mechanism.enabled:
                self.store.set_enabled(mechanism.identifier, True)

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


@dataclass(frozen=True)
class NativeClientState:
    processes: Set[str]
    route_interface: Optional[str]
    status: str
    hyu_enabled: bool = True

    def blocks_openconnect(self) -> bool:
        if not self.hyu_enabled:
            return False
        if self.status in {"connected", "connecting"}:
            if self.route_interface is not None and self.route_interface.startswith("utun"):
                return True
            return bool(self.processes & {"PanGPS", "PanGPA", "GlobalProtect"})
        return False
