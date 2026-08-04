"""Shell-free local control channel for HYU VPN supervisor."""

from __future__ import annotations

import json
import os
import socket
import stat
import tempfile
import threading
from pathlib import Path
from typing import Callable, Optional

VALID_COMMANDS = {"connect", "disconnect", "reconnect", "automatic-on", "automatic-off"}
VALID_ERROR_CODES = {None, "BAD_REQUEST", "INTERNAL_ERROR", "REPAIR_REQUIRED", "CONTROL_UNAVAILABLE"}
MAX_CONTROL_BYTES = 1024
MAX_TIMEOUT_SECONDS = 30.0
PREFERENCE_SCHEMA_VERSION = 1


class ControlProtocolError(ValueError):
    """Raised when a control request/preference violates the fixed schema."""


def parse_control_request(payload: bytes) -> str:
    if not isinstance(payload, (bytes, bytearray)) or len(payload) > MAX_CONTROL_BYTES:
        raise ControlProtocolError("invalid control request")
    try:
        text = bytes(payload).decode("utf-8")
        document = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlProtocolError("invalid control request") from exc
    if not isinstance(document, dict) or set(document) != {"schema_version", "command"}:
        raise ControlProtocolError("invalid control request schema")
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise ControlProtocolError("invalid control schema version")
    if not isinstance(document.get("command"), str) or document["command"] not in VALID_COMMANDS:
        raise ControlProtocolError("invalid control command")
    return document["command"]


def _response(ok: bool, error_code: Optional[str]) -> bytes:
    if type(ok) is not bool or error_code not in VALID_ERROR_CODES:
        raise ControlProtocolError("invalid control response")
    payload = json.dumps(
        {"schema_version": 1, "ok": ok, "error_code": error_code},
        separators=(",", ":"),
        sort_keys=True,
    )
    return (payload + "\n").encode("utf-8")


class AutoReconnectPreference:
    def __init__(self, path: os.PathLike[str] | str, *, owner_uid: Optional[int] = None) -> None:
        self.path = Path(path)
        self.owner_uid = os.getuid() if owner_uid is None else owner_uid

    def read(self, *, default: bool = True) -> bool:
        if self.path.is_symlink():
            raise ControlProtocolError("unsafe auto-reconnect preference file")
        if not self.path.exists():
            return default
        self._validate_existing_file()
        try:
            raw = self.path.read_bytes()
            if len(raw) > 1024:
                raise ControlProtocolError("oversized auto-reconnect preference")
            document = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ControlProtocolError("invalid auto-reconnect preference") from exc
        if not isinstance(document, dict) or set(document) != {"schema_version", "automatic_reconnect_enabled"}:
            raise ControlProtocolError("invalid auto-reconnect preference schema")
        if type(document.get("schema_version")) is not int or document["schema_version"] != PREFERENCE_SCHEMA_VERSION:
            raise ControlProtocolError("invalid auto-reconnect preference schema")
        if type(document.get("automatic_reconnect_enabled")) is not bool:
            raise ControlProtocolError("invalid auto-reconnect preference schema")
        return document["automatic_reconnect_enabled"]

    def write(self, enabled: bool) -> None:
        if type(enabled) is not bool:
            raise ControlProtocolError("automatic reconnect must be bool")
        self._prepare_parent()
        if self.path.exists() or self.path.is_symlink():
            self._validate_existing_file()
        payload = (
            json.dumps(
                {"schema_version": PREFERENCE_SCHEMA_VERSION, "automatic_reconnect_enabled": enabled},
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        fd, tmp = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=str(self.path.parent))
        tmp_path = Path(tmp)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self.path)
            os.chmod(self.path, 0o600)
            _fsync_dir(self.path.parent)
        finally:
            if fd != -1:
                os.close(fd)
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass

    def _prepare_parent(self) -> None:
        parent = self.path.parent
        if parent.exists() or parent.is_symlink():
            parent_stat = parent.lstat()
            if parent.is_symlink() or not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != self.owner_uid:
                raise ControlProtocolError("unsafe auto-reconnect preference directory")
            os.chmod(parent, 0o700)
        else:
            parent.mkdir(parents=True, mode=0o700)
            os.chmod(parent, 0o700)

    def _validate_existing_file(self) -> None:
        st = self.path.lstat()
        if self.path.is_symlink() or not stat.S_ISREG(st.st_mode):
            raise ControlProtocolError("unsafe auto-reconnect preference file")
        if st.st_uid != self.owner_uid or stat.S_IMODE(st.st_mode) != 0o600:
            raise ControlProtocolError("unsafe auto-reconnect preference file")


class ControlServer:
    def __init__(
        self,
        socket_path: os.PathLike[str] | str,
        handler: Callable[[str], tuple[bool, Optional[str]]],
        *,
        owner_uid: Optional[int] = None,
    ) -> None:
        self.socket_path = Path(socket_path)
        self.handler = handler
        self.owner_uid = os.getuid() if owner_uid is None else owner_uid
        self._ready = threading.Event()

    def wait_until_ready(self, *, timeout: float) -> None:
        if not _valid_timeout(timeout) or not self._ready.wait(timeout):
            raise TimeoutError("control socket did not become ready")

    def serve_once(self) -> None:
        self._serve(once=True)

    def serve_forever(self, stop_event: threading.Event) -> None:
        self._serve(once=False, stop_event=stop_event)

    def _serve(self, *, once: bool, stop_event: Optional[threading.Event] = None) -> None:
        self._prepare_socket_path()
        bound_identity: Optional[tuple[int, int]] = None
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(self.socket_path))
                bound_stat = self.socket_path.lstat()
                if not stat.S_ISSOCK(bound_stat.st_mode):
                    raise ControlProtocolError("unsafe bound control socket")
                bound_identity = (bound_stat.st_dev, bound_stat.st_ino)
                os.chmod(self.socket_path, 0o600)
                os.chown(self.socket_path, self.owner_uid, -1)
                self._validate_bound_socket(bound_identity)
                server.listen(1)
                server.settimeout(0.2)
                self._ready.set()
                while stop_event is None or not stop_event.is_set():
                    try:
                        conn, _ = server.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        conn.settimeout(0.5)
                        ok, error_code = self._handle_connection(conn)
                        try:
                            conn.sendall(_response(ok, error_code))
                        except OSError:
                            pass
                    if once:
                        return
        finally:
            self._unlink_owned_socket(bound_identity)

    def _handle_connection(self, conn: socket.socket) -> tuple[bool, Optional[str]]:
        try:
            self._validate_peer(conn)
            command = parse_control_request(_recv_bounded_json_line(conn))
            return self.handler(command)
        except ControlProtocolError:
            return False, "BAD_REQUEST"
        except Exception:
            return False, "INTERNAL_ERROR"

    def _prepare_socket_path(self) -> None:
        parent = self.socket_path.parent
        if parent.exists() or parent.is_symlink():
            parent_stat = parent.lstat()
            if parent.is_symlink() or not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != self.owner_uid:
                raise ControlProtocolError("unsafe control socket directory")
            os.chmod(parent, 0o700)
        else:
            parent.mkdir(parents=True, mode=0o700)
            os.chmod(parent, 0o700)
        if self.socket_path.exists() or self.socket_path.is_symlink():
            st = self.socket_path.lstat()
            if self.socket_path.is_symlink() or not stat.S_ISSOCK(st.st_mode) or st.st_uid != self.owner_uid:
                raise ControlProtocolError("unsafe existing control socket")
            self.socket_path.unlink()

    def _validate_bound_socket(self, expected_identity: tuple[int, int]) -> None:
        st = self.socket_path.lstat()
        if (
            not stat.S_ISSOCK(st.st_mode)
            or st.st_uid != self.owner_uid
            or stat.S_IMODE(st.st_mode) != 0o600
            or (st.st_dev, st.st_ino) != expected_identity
        ):
            raise ControlProtocolError("unsafe bound control socket")

    def _validate_peer(self, conn: socket.socket) -> None:
        getpeereid = getattr(conn, "getpeereid", None)
        if getpeereid is not None:
            uid, _gid = getpeereid()
            if uid != self.owner_uid:
                raise ControlProtocolError("wrong peer uid")

    def _unlink_owned_socket(self, expected_identity: Optional[tuple[int, int]]) -> None:
        if expected_identity is None:
            return
        try:
            st = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISSOCK(st.st_mode) and st.st_uid == self.owner_uid and (st.st_dev, st.st_ino) == expected_identity:
            self.socket_path.unlink()


def send_control_command(socket_path: os.PathLike[str] | str, command: str, *, timeout: float = 5.0) -> dict[str, object]:
    if command not in VALID_COMMANDS or not _valid_timeout(timeout):
        raise ControlProtocolError("invalid control command")
    request = json.dumps({"schema_version": 1, "command": command}, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(str(socket_path))
        client.sendall(request)
        response = _parse_response(_recv_bounded_json_line(client))
    return response


def _recv_bounded_json_line(conn: socket.socket) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = conn.recv(min(256, MAX_CONTROL_BYTES + 2 - total))
        except socket.timeout as exc:
            raise ControlProtocolError("timed out control frame") from exc
        if not chunk:
            raise ControlProtocolError("truncated control frame")
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_CONTROL_BYTES + 1:
            raise ControlProtocolError("oversized control frame")
        data = b"".join(chunks)
        newline = data.find(b"\n")
        if newline != -1:
            if newline != len(data) - 1:
                raise ControlProtocolError("extra control frame bytes")
            return data


def _parse_response(raw: bytes) -> dict[str, object]:
    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlProtocolError("invalid control response") from exc
    if not isinstance(response, dict) or set(response) != {"schema_version", "ok", "error_code"}:
        raise ControlProtocolError("invalid control response schema")
    if type(response.get("schema_version")) is not int or response["schema_version"] != 1:
        raise ControlProtocolError("invalid control response schema")
    if type(response.get("ok")) is not bool or response.get("error_code") not in VALID_ERROR_CODES:
        raise ControlProtocolError("invalid control response schema")
    return response


def _valid_timeout(timeout: float) -> bool:
    return isinstance(timeout, (int, float)) and type(timeout) is not bool and 0 < timeout <= MAX_TIMEOUT_SECONDS


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
