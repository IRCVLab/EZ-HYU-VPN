"""Sanitized VPN status protocol and OpenConnect expiry parsing."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping, Optional

ALLOWED_STATUS_FIELDS = (
    "schema_version",
    "state",
    "automatic_reconnect_enabled",
    "connected_at",
    "session_expires_at",
    "last_successful_hip_at",
    "tunnel_interface",
    "next_retry_at",
    "error_code",
    "last_transition_at",
    "backend_build_version",
)
STATUS_SCHEMA_VERSION = 1
VALID_STATES = ("disabled", "waiting-for-network", "connecting", "connected", "disconnecting", "backoff", "error")
MAX_STATUS_BYTES = 4096
MAX_STATUS_READ_BYTES = 1024 * 1024
SESSION_EXPIRY_LINE = "Session authentication will expire at Tue, 04 Aug 2026 21:59:30 KST"

_SECRET_FIELD_NAMES = frozenset(("username", "password", "otp", "cookie", "authcookie", "seed", "portal"))
_SECRET_TEXT_RE = re.compile(r"(?i)(password|otp|cookie|authcookie|seed|username|portal)\s*[:=]")
_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_TUNNEL_INTERFACE_RE = re.compile(r"^utun[0-9]{1,8}$")
_BUILD_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$")
_EXPIRY_RE = re.compile(
    r"Session authentication will expire at "
    r"(?P<stamp>[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2}) KST"
)
_KST = timezone(timedelta(hours=9), "KST")


class StatusProtocolError(ValueError):
    """Raised when a status document violates the sanitized protocol."""


@dataclass(frozen=True)
class VpnStatus:
    """Immutable, secret-free status value for UI consumers."""

    state: str
    automatic_reconnect_enabled: bool
    last_transition_at: datetime
    connected_at: Optional[datetime] = None
    session_expires_at: Optional[datetime] = None
    last_successful_hip_at: Optional[datetime] = None
    tunnel_interface: Optional[str] = None
    next_retry_at: Optional[datetime] = None
    error_code: Optional[str] = None
    backend_build_version: Optional[str] = None
    schema_version: int = STATUS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != STATUS_SCHEMA_VERSION:
            raise StatusProtocolError("unsupported schema_version")
        if self.state not in VALID_STATES:
            raise StatusProtocolError(f"invalid state: {self.state}")
        if not isinstance(self.automatic_reconnect_enabled, bool):
            raise StatusProtocolError("automatic_reconnect_enabled must be a bool")
        _require_datetime("last_transition_at", self.last_transition_at)
        for name in ("connected_at", "session_expires_at", "last_successful_hip_at", "next_retry_at"):
            value = getattr(self, name)
            if value is not None:
                _require_datetime(name, value)
        _validate_tunnel_interface(self.tunnel_interface)
        _validate_error_code(self.error_code)
        _validate_backend_build_version(self.backend_build_version)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "state": self.state,
            "automatic_reconnect_enabled": self.automatic_reconnect_enabled,
            "connected_at": _format_optional_instant(self.connected_at),
            "session_expires_at": _format_optional_instant(self.session_expires_at),
            "last_successful_hip_at": _format_optional_instant(self.last_successful_hip_at),
            "tunnel_interface": self.tunnel_interface,
            "next_retry_at": _format_optional_instant(self.next_retry_at),
            "error_code": self.error_code,
            "last_transition_at": _format_instant(self.last_transition_at),
            "backend_build_version": self.backend_build_version,
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, object]) -> "VpnStatus":
        if not isinstance(document, Mapping):
            raise StatusProtocolError("status document must be an object")
        keys = set(document.keys())
        for key in sorted(keys - set(ALLOWED_STATUS_FIELDS)):
            if key.lower() in _SECRET_FIELD_NAMES:
                raise StatusProtocolError(f"secret-bearing field is not allowed: {key}")
            raise StatusProtocolError(f"unknown status field: {key}")
        missing = set(ALLOWED_STATUS_FIELDS) - keys
        if missing:
            raise StatusProtocolError(f"missing status field: {sorted(missing)[0]}")
        return cls(
            schema_version=_int_value("schema_version", document["schema_version"]),
            state=_string_value("state", document["state"]),
            automatic_reconnect_enabled=_bool_value(
                "automatic_reconnect_enabled", document["automatic_reconnect_enabled"]
            ),
            connected_at=_parse_optional_instant("connected_at", document["connected_at"]),
            session_expires_at=_parse_optional_instant("session_expires_at", document["session_expires_at"]),
            last_successful_hip_at=_parse_optional_instant(
                "last_successful_hip_at", document["last_successful_hip_at"]
            ),
            tunnel_interface=_optional_string_value("tunnel_interface", document["tunnel_interface"]),
            next_retry_at=_parse_optional_instant("next_retry_at", document["next_retry_at"]),
            error_code=_optional_string_value("error_code", document["error_code"]),
            last_transition_at=_parse_instant("last_transition_at", document["last_transition_at"]),
            backend_build_version=_optional_string_value(
                "backend_build_version", document["backend_build_version"]
            ),
        )


def read_status(path: Path | str, *, max_bytes: int = MAX_STATUS_BYTES) -> VpnStatus:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0 or max_bytes > MAX_STATUS_READ_BYTES:
        raise StatusProtocolError("max_bytes must be a positive bounded integer")
    status_path = Path(path)
    try:
        with status_path.open("rb") as handle:
            raw_bytes = handle.read(max_bytes + 1)
    except OSError as exc:
        raise StatusProtocolError("unable to read status document") from exc
    if len(raw_bytes) > max_bytes:
        raise StatusProtocolError("oversized status document")
    try:
        raw = raw_bytes.decode("utf-8")
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StatusProtocolError("malformed status document") from exc
    try:
        return VpnStatus.from_dict(document)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, StatusProtocolError):
            raise
        raise StatusProtocolError("malformed status document") from exc


def write_status(path: Path | str, status: VpnStatus) -> None:
    status_path = Path(path)
    directory = status_path.parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    payload = json.dumps(status.to_dict(), sort_keys=False, separators=(",", ":")) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=f".{status_path.name}.", suffix=".tmp", dir=str(directory))
    temp_path = Path(temp_name)
    try:
        try:
            os.chmod(temp_path, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, status_path)
            os.chmod(status_path, 0o600)
            _fsync_directory(directory)
        finally:
            if fd != -1:
                os.close(fd)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


class OpenConnectExpiryParser:
    """Bounded parser for OpenConnect session-expiry status lines."""

    def __init__(
        self,
        *,
        max_buffer_bytes: int = 2048,
        now: Optional[Callable[[], datetime]] = None,
    ) -> None:
        self.max_buffer_bytes = max_buffer_bytes
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.buffer = ""
        self._last_expiry: Optional[datetime] = None

    def feed(self, chunk: bytes | str) -> Optional[datetime]:
        text = chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else chunk
        self.buffer = _bound_utf8(_sanitize_parser_text(self.buffer + text), self.max_buffer_bytes)
        match = None
        for match in _EXPIRY_RE.finditer(self.buffer):
            pass
        if match is None:
            return None
        expiry = _parse_kst_expiry(match.group("stamp"))
        self.buffer = _bound_utf8(self.buffer[match.end() :], self.max_buffer_bytes)
        if expiry == self._last_expiry:
            return None
        self._last_expiry = expiry
        return expiry


@dataclass(frozen=True)
class ExpiryCountdown:
    expires_at: Optional[datetime]
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)

    def remaining_seconds(self) -> Optional[int]:
        if self.expires_at is None:
            return None
        expires = _as_utc(self.expires_at)
        current = _as_utc(self.now())
        return max(0, int((expires - current).total_seconds()))


def _require_datetime(name: str, value: datetime) -> None:
    if not isinstance(value, datetime):
        raise StatusProtocolError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise StatusProtocolError(f"{name} must be timezone-aware")


def _as_utc(value: datetime) -> datetime:
    _require_datetime("timestamp", value)
    return value.astimezone(timezone.utc)


def _format_instant(value: datetime) -> str:
    return _as_utc(value).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _format_optional_instant(value: Optional[datetime]) -> Optional[str]:
    return None if value is None else _format_instant(value)


def _parse_instant(name: str, value: object) -> datetime:
    if not isinstance(value, str):
        raise StatusProtocolError(f"{name} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise StatusProtocolError(f"{name} must be an ISO-8601 timestamp") from exc
    _require_datetime(name, parsed)
    return parsed.astimezone(timezone.utc).replace(microsecond=0)


def _parse_optional_instant(name: str, value: object) -> Optional[datetime]:
    if value is None:
        return None
    return _parse_instant(name, value)


def _int_value(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StatusProtocolError(f"{name} must be an integer")
    return value


def _bool_value(name: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise StatusProtocolError(f"{name} must be a bool")
    return value


def _string_value(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise StatusProtocolError(f"{name} must be a string")
    return value


def _optional_string_value(name: str, value: object) -> Optional[str]:
    if value is None:
        return None
    return _string_value(name, value)


def _validate_error_code(value: Optional[str]) -> None:
    if value is not None and _TOKEN_RE.fullmatch(value) is None:
        raise StatusProtocolError("error_code must be null or a bounded normalized token")


def _validate_tunnel_interface(value: Optional[str]) -> None:
    if value is not None and _TUNNEL_INTERFACE_RE.fullmatch(value) is None:
        raise StatusProtocolError("tunnel_interface must be null or a safe utun token")


def _validate_backend_build_version(value: Optional[str]) -> None:
    if value is not None and _BUILD_VERSION_RE.fullmatch(value) is None:
        raise StatusProtocolError("backend_build_version must be null or a bounded safe version token")


def _fsync_directory(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _sanitize_parser_text(text: str) -> str:
    clean_lines = []
    for line in text.replace("\r", "\n").split("\n"):
        if _SECRET_TEXT_RE.search(line):
            continue
        clean_lines.append(line)
    trailing_newline = "\n" if text.endswith(("\n", "\r")) else ""
    return "\n".join(clean_lines) + trailing_newline


def _bound_utf8(text: str, max_bytes: int) -> str:
    data = text.encode("utf-8")
    if len(data) <= max_bytes:
        return text
    return data[-max_bytes:].decode("utf-8", "ignore")


def _parse_kst_expiry(stamp: str) -> datetime:
    try:
        local = datetime.strptime(stamp, "%a, %d %b %Y %H:%M:%S").replace(tzinfo=_KST)
    except ValueError as exc:
        raise StatusProtocolError("malformed expiry timestamp") from exc
    return local.astimezone(timezone.utc)
