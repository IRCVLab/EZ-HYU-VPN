"""PTY OpenConnect connector with dual-TOTP prompt handling and process ownership."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import pty
import re
import select
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import FrameType
from typing import BinaryIO, Callable, Mapping, Optional, Sequence, TextIO

from .otp import Keychain, TotpError, TotpProvider
from .status import OpenConnectExpiryParser


PORTAL = "secure.hanyang.ac.kr"
AUTHGROUP = "HYU-ExternalGW-General"
OPENCONNECT = "/opt/homebrew/bin/openconnect"
VPNC_SCRIPT = "/opt/homebrew/etc/vpnc/vpnc-script"
PRIVILEGED_HELPER = "/Library/PrivilegedHelperTools/com.hyu.vpn.helper"
INSTALLED_CONNECTOR_CONFIG_PATH = Path("/Library/Application Support/HYU VPN/connector-config.json")
INSTALLED_OATHTOOL_PATH = Path("/Library/Application Support/HYU VPN/runtime/current/bin/oathtool")
INSTALLED_TRUSTED_PARENT = Path("/Library/Application Support/HYU VPN")
CONNECTOR_CONFIG_MAX_BYTES = 4096
TOTP_STATE_PATH = Path.home() / "Library" / "Application Support" / "hyu-openconnect" / "totp-counter.json"

_PROMPT_RE = re.compile(rb"(?:Password|Challenge):\s*$", re.IGNORECASE)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,128}$")
_EVENT_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

NETWORK_SCRIPT_EVENT_KINDS = frozenset(
    {
        "network-script-bad-configuration",
        "network-script-state-mismatch",
        "network-script-security-failure",
        "network-script-teardown-incomplete",
        "network-script-preflight-drift",
        "network-script-upstream-failed",
        "network-script-postcondition-failed",
        "network-script-failed",
    }
)
CONNECTOR_EVENT_KINDS = frozenset({"hip-succeeded", "session-expiry", "connected"}) | NETWORK_SCRIPT_EVENT_KINDS


class ConnectorProtocolError(RuntimeError):
    """Raised for a local bounded control/event protocol failure."""


class ConnectorRuntimeConfigError(RuntimeError):
    """Raised when the installed connector runtime config is not trusted."""


@dataclass(frozen=True)
class ConnectorRuntimeConfig:
    oathtool_path: str
    oathtool_sha256: str


@dataclass(frozen=True)
class ConnectorConfig:
    helper_path: str = PRIVILEGED_HELPER
    openconnect_path: str = OPENCONNECT
    portal: str = PORTAL
    authgroup: str = AUTHGROUP
    vpnc_script: str = VPNC_SCRIPT
    hip_wrapper: Optional[str] = None
    sudo_path: Optional[str] = "/usr/bin/sudo"


@dataclass(frozen=True)
class ConnectorEvent:
    kind: str
    timestamp: Optional[datetime] = None

    def to_json_line(self) -> str:
        if self.kind not in CONNECTOR_EVENT_KINDS:
            raise ValueError("invalid connector event")
        if self.timestamp is None or self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("connector event timestamp is required")
        timestamp = self.timestamp.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        line = json.dumps(
            {"schema_version": 1, "event": self.kind, "timestamp": timestamp},
            separators=(",", ":"),
            sort_keys=True,
        )
        if len(line.encode("utf-8")) > 512 or "\n" in line:
            raise ValueError("oversized connector event")
        return line


def parse_connector_event_line(line: str) -> ConnectorEvent:
    if not isinstance(line, str) or len(line.encode("utf-8")) > 512 or "\n" in line:
        raise ValueError("invalid connector event line")
    try:
        document = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid connector event line") from exc
    if not isinstance(document, dict) or set(document) != {"schema_version", "event", "timestamp"}:
        raise ValueError("invalid connector event schema")
    schema_version = document.get("schema_version")
    event_name = document.get("event")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version != 1:
        raise ValueError("invalid connector event schema")
    if not isinstance(event_name, str) or event_name not in CONNECTOR_EVENT_KINDS:
        raise ValueError("invalid connector event schema")
    raw_timestamp = document.get("timestamp")
    if not isinstance(raw_timestamp, str):
        raise ValueError("invalid connector event timestamp")
    if _EVENT_TIMESTAMP_RE.fullmatch(raw_timestamp) is None:
        raise ValueError("invalid connector event timestamp")
    try:
        timestamp = datetime.strptime(raw_timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("invalid connector event timestamp") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("invalid connector event timestamp")
    return ConnectorEvent(event_name, timestamp.astimezone(timezone.utc).replace(microsecond=0))


def write_connector_event(event: ConnectorEvent, *, stream: TextIO = sys.stdout) -> None:
    stream.write(event.to_json_line() + "\n")
    stream.flush()


class ConnectorEventParser:
    """Extract only fixed, non-secret lifecycle events from bounded progress text."""

    _HIP_SUCCESS = "HIP report submitted successfully"
    _CONNECTED = ("hyu-vpnc-wrapperd-event: network configuration verified",)

    def __init__(self, *, now=lambda: datetime.now(timezone.utc), max_buffer_bytes: int = 4096) -> None:
        if isinstance(max_buffer_bytes, bool) or not isinstance(max_buffer_bytes, int) or max_buffer_bytes <= 0 or max_buffer_bytes > 65536:
            raise ValueError("invalid connector event buffer size")
        self.now = now
        self.max_buffer_bytes = max_buffer_bytes
        self._expiry = OpenConnectExpiryParser(max_buffer_bytes=max_buffer_bytes, now=now)
        self._buffer = ""
        self._connected_emitted = False
        self._fatal_emitted = False

    def feed(self, chunk: bytes | str) -> list[ConnectorEvent]:
        if self._fatal_emitted:
            return []
        text = chunk.decode("utf-8", "replace") if isinstance(chunk, bytes) else chunk
        events: list[ConnectorEvent] = []
        expiry = self._expiry.feed(text)
        combined = self._buffer + text
        bounded = combined.encode("utf-8", "replace")[-self.max_buffer_bytes :]
        combined = bounded.decode("utf-8", "ignore")
        lines = combined.replace("\r", "\n").split("\n")
        self._buffer = lines.pop() if lines else ""
        for line in lines:
            fatal_kind = self._network_script_error_kind(" ".join(line.strip().split()))
            if fatal_kind is not None:
                self._fatal_emitted = True
                self._buffer = ""
                return [ConnectorEvent(fatal_kind, self.now())]
        for line in lines:
            normalized = " ".join(line.strip().split())
            if re.search(r"(?:^|:)\s*HIP report submitted successfully$", normalized):
                events.append(ConnectorEvent("hip-succeeded", self.now()))
        if expiry is not None:
            events.append(ConnectorEvent("session-expiry", expiry))
        for line in lines:
            normalized = " ".join(line.strip().split())
            if not self._connected_emitted and normalized in self._CONNECTED:
                self._connected_emitted = True
                events.append(ConnectorEvent("connected", self.now()))
        return events

    @staticmethod
    def _network_script_error_kind(normalized: str) -> Optional[str]:
        prefix = "hyu-vpnc-wrapperd: "
        if not normalized.startswith(prefix):
            return None
        detail = normalized[len(prefix) :]
        if detail == "bad helper configuration":
            return "network-script-bad-configuration"
        if detail in {"recorded process did not match live process", "session already exists"}:
            return "network-script-state-mismatch"
        if detail == "unauthorized invocation" or detail.startswith(("insecure path: ", "forbidden path: ")):
            return "network-script-security-failure"
        if detail.startswith("teardown incomplete: "):
            return "network-script-teardown-incomplete"
        if detail == "network preflight drift":
            return "network-script-preflight-drift"
        if detail == "network upstream failed":
            return "network-script-upstream-failed"
        if detail == "network postcondition failed":
            return "network-script-postcondition-failed"
        return "network-script-failed"


def load_connector_runtime_config(
    *,
    config_path: os.PathLike[str] | str = INSTALLED_CONNECTOR_CONFIG_PATH,
    expected_oathtool_path: os.PathLike[str] | str = INSTALLED_OATHTOOL_PATH,
    trusted_parent: os.PathLike[str] | str = INSTALLED_TRUSTED_PARENT,
    required_uid: int = 0,
) -> ConnectorRuntimeConfig:
    """Load and verify the fixed installed oathtool artifact before TOTP use.

    Production intentionally has no Homebrew fallback: the connector may use only the
    installer-copied, root-owned runtime oathtool whose hash is pinned in the fixed
    root-owned config file. Tests can inject an isolated config/path/uid.
    """
    config = _trusted_path(config_path)
    expected_oathtool = _trusted_path(expected_oathtool_path)
    parent = _trusted_path(trusted_parent)
    _validate_owned_parent_chain(parent, config.parent, required_uid=required_uid)
    _validate_owned_parent_chain(parent, expected_oathtool.parent, required_uid=required_uid)
    try:
        document = json.loads(
            _read_bounded_regular_file(
                config,
                required_uid=required_uid,
                exact_mode=0o644,
                max_bytes=CONNECTOR_CONFIG_MAX_BYTES,
            ).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ConnectorRuntimeConfigError) as exc:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration") from exc
    if not isinstance(document, dict) or set(document) != {"schema_version", "oathtool_path", "oathtool_sha256"}:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
    schema_version = document.get("schema_version")
    oathtool_path = document.get("oathtool_path")
    oathtool_sha256 = document.get("oathtool_sha256")
    if isinstance(schema_version, bool) or schema_version != 1:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
    if not isinstance(oathtool_path, str) or oathtool_path != str(expected_oathtool):
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
    if not isinstance(oathtool_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", oathtool_sha256) is None:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
    actual_hash = _sha256_regular_file(expected_oathtool, required_uid=required_uid, exact_mode=0o755)
    if actual_hash != oathtool_sha256:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
    return ConnectorRuntimeConfig(oathtool_path=str(expected_oathtool), oathtool_sha256=oathtool_sha256)


def _validate_owned_parent_chain(trusted_parent: Path, target_parent: Path, *, required_uid: int) -> None:
    try:
        relative_parts = target_parent.relative_to(trusted_parent).parts
    except ValueError:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration") from None
    current = trusted_parent
    _validate_secure_directory(current, required_uid=required_uid)
    for part in relative_parts:
        current = current / part
        _validate_secure_directory(current, required_uid=required_uid)


def _trusted_path(value: os.PathLike[str] | str) -> Path:
    raw = os.fspath(value)
    if not raw or any(part in {".", ".."} for part in raw.split(os.sep) if part):
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
    path = Path(raw)
    if not path.is_absolute():
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
    return path


def _validate_secure_directory(path: Path, *, required_uid: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
    _validate_owner_and_mode(info, required_uid=required_uid)


def _validate_owner_and_mode(info: os.stat_result, *, required_uid: int) -> None:
    if info.st_uid != required_uid:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
    if info.st_mode & 0o022:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")


def _validate_regular_file_info(info: os.stat_result, *, required_uid: int, exact_mode: int) -> None:
    if not stat.S_ISREG(info.st_mode):
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
    if info.st_uid != required_uid:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
    if stat.S_IMODE(info.st_mode) != exact_mode:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration")


def _open_verified_regular_file(path: Path, *, required_uid: int, exact_mode: int) -> int:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration") from exc
    try:
        _validate_regular_file_info(os.fstat(fd), required_uid=required_uid, exact_mode=exact_mode)
    except Exception:
        os.close(fd)
        raise
    return fd


def _read_bounded_regular_file(path: Path, *, required_uid: int, exact_mode: int, max_bytes: int) -> bytes:
    fd = _open_verified_regular_file(path, required_uid=required_uid, exact_mode=exact_mode)
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(fd, min(4096, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
        if total == 0:
            raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
        return b"".join(chunks)
    except OSError as exc:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration") from exc
    finally:
        os.close(fd)


def _sha256_regular_file(path: Path, *, required_uid: int, exact_mode: int) -> str:
    fd = _open_verified_regular_file(path, required_uid=required_uid, exact_mode=exact_mode)
    digest = hashlib.sha256()
    try:
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    except OSError as exc:
        raise ConnectorRuntimeConfigError("invalid connector runtime configuration") from exc
    finally:
        os.close(fd)
    return digest.hexdigest()


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ConnectorRuntimeConfigError("invalid connector runtime configuration")
        document[key] = value
    return document


def default_hip_wrapper() -> str:
    return str(Path(__file__).resolve().parents[2] / "bin" / "gp-hip-report")


def build_openconnect_argv(username: str, *, config: ConnectorConfig = ConnectorConfig()) -> list[str]:
    command: list[str] = []
    if config.sudo_path:
        command.extend([config.sudo_path, "-n"])
    command.extend([
        config.openconnect_path,
        "--protocol=gp",
        f"--user={username}",
        f"--authgroup={config.authgroup}",
        "--passwd-on-stdin",
        f"--script={config.vpnc_script}",
        f"--csd-wrapper={config.hip_wrapper or default_hip_wrapper()}",
        config.portal,
    ])
    return command


def build_helper_argv(*, config: ConnectorConfig = ConnectorConfig()) -> list[str]:
    command: list[str] = []
    if config.sudo_path:
        command.extend([config.sudo_path, "-n"])
    command.extend([config.helper_path, "start"])
    return command


class PromptSession:
    def __init__(
        self,
        argv: Sequence[str],
        *,
        password: str,
        totp_provider: Optional[TotpProvider],
        start_username: Optional[str] = None,
        environ: Optional[Mapping[str, str]] = None,
        stdout: Optional[BinaryIO] = sys.stdout.buffer,
        stderr: Optional[TextIO] = sys.stderr,
        event_sink: Optional[Callable[[ConnectorEvent], None]] = None,
        terminate_timeout: float = 5.0,
    ) -> None:
        self.argv = list(argv)
        self.password = password
        self.totp_provider = totp_provider
        self.start_username = start_username
        self.environ = dict(environ) if environ is not None else None
        self.stdout = stdout
        self.stderr = stderr
        self.event_sink = event_sink
        self.event_parser = ConnectorEventParser()
        self.terminate_timeout = terminate_timeout
        self._proc: Optional[subprocess.Popen[bytes]] = None
        self._received_signal: Optional[int] = None

    def run(self) -> int:
        if self.start_username is not None and _USERNAME_RE.fullmatch(self.start_username) is None:
            self._write_error("Helper start request invalid\n")
            return 1
        master, slave = pty.openpty()
        old_handlers: dict[int, object] = {}
        try:
            try:
                self._proc = subprocess.Popen(
                    self.argv,
                    stdin=subprocess.PIPE,
                    stdout=slave,
                    stderr=slave,
                    bufsize=0,
                    close_fds=True,
                    start_new_session=True,
                    env=self.environ,
                )
            except (OSError, subprocess.SubprocessError):
                self._write_error("OpenConnect launch failed\n")
                return 1
            os.close(slave)
            slave = -1
            self._install_signal_handlers(old_handlers)
            try:
                if self.start_username is not None:
                    self._send_start_header(self.start_username)
                self._send_line(self.password)
                return self._pump_until_exit(master)
            except (BrokenPipeError, OSError):
                self._write_error("OpenConnect child input failed\n")
                self._stop_child()
                return 1
        except TotpError:
            self._write_error("TOTP generation failed\n")
            self._stop_child()
            return 1
        except ConnectorProtocolError:
            self._write_error("Connector event channel failed\n")
            self._stop_child()
            return 1
        finally:
            self._restore_signal_handlers(old_handlers)
            if self._proc is not None and self._proc.poll() is None:
                self._stop_child()
            if slave != -1:
                os.close(slave)
            try:
                os.close(master)
            except OSError:
                pass

    def _install_signal_handlers(self, old_handlers: dict[int, object]) -> None:
        for signum in (signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, self._handle_signal)

    def _restore_signal_handlers(self, old_handlers: dict[int, object]) -> None:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)

    def _handle_signal(self, signum: int, _frame: Optional[FrameType]) -> None:
        self._received_signal = signum
        self._terminate_child(signum)

    def _pump_until_exit(self, master: int) -> int:
        tail = b""
        while True:
            if self._received_signal is not None:
                return self._wait_for_child()
            proc = self._require_proc()
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                self._handle_output_chunk(chunk)
                tail = (tail + chunk)[-512:]
                prompt = self._prompt_from_tail(tail)
                if prompt is not None:
                    if self._respond_to_prompt(prompt):
                        tail = b""
            if proc.poll() is not None:
                self._drain(master)
                break
        return self._wait_for_child()

    def _prompt_from_tail(self, tail: bytes) -> Optional[bytes]:
        normalized = tail.replace(b"\r", b"\n")
        segment = normalized.split(b"\n")[-1].lower()
        if not _PROMPT_RE.search(segment):
            return None
        compact = b" ".join(segment.strip().split())
        if compact.endswith(b"gateway challenge:"):
            return b"gateway challenge"
        if compact.endswith(b"challenge:"):
            return b"challenge"
        if compact.endswith(b"password:"):
            return b"password"
        return None

    def _respond_to_prompt(self, prompt_key: bytes) -> bool:
        lower = prompt_key.lower()
        if lower.endswith(b"password"):
            # The portal consumes the startup password through --passwd-on-stdin.
            # Hanyang's gateway then presents a separate Password: prompt.
            self._send_line(self.password)
            return True
        if lower.endswith(b"challenge"):
            if self.totp_provider is None:
                raise TotpError("TOTP generation failed")
            self._send_line(self.totp_provider.current())
            return True
        return False

    def _send_line(self, value: str) -> None:
        proc = self._require_proc()
        if proc.stdin is None:
            raise BrokenPipeError("child stdin unavailable")
        proc.stdin.write(value.encode("utf-8") + b"\n")
        proc.stdin.flush()

    def _send_start_header(self, username: str) -> None:
        proc = self._require_proc()
        if proc.stdin is None:
            raise BrokenPipeError("child stdin unavailable")
        proc.stdin.write(f"HYU-Username: {username}\n\n".encode("ascii"))
        proc.stdin.flush()

    def _drain(self, master: int) -> None:
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.05)
            if not ready:
                break
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            self._handle_output_chunk(chunk)

    def _handle_output_chunk(self, chunk: bytes) -> None:
        if self.stdout is not None:
            self.stdout.write(chunk)
            self.stdout.flush()
        try:
            events = self.event_parser.feed(chunk)
            if self.event_sink is not None:
                for event in events:
                    self.event_sink(event)
            if any(event.kind in NETWORK_SCRIPT_EVENT_KINDS for event in events):
                raise ConnectorProtocolError("connector network script failed")
        except ConnectorProtocolError:
            raise
        except Exception:
            raise ConnectorProtocolError("connector event sink failed") from None

    def _terminate_child(self, signum: int) -> None:
        proc = self._proc
        if proc is None or proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signum)
        except ProcessLookupError:
            return

    def _stop_child(self) -> None:
        proc = self._proc
        if proc is None:
            return
        self._terminate_child(signal.SIGTERM)
        try:
            self._wait_for_child()
        except (OSError, subprocess.SubprocessError):
            return

    def _wait_for_child(self) -> int:
        proc = self._require_proc()
        try:
            try:
                return proc.wait(timeout=self.terminate_timeout) or 0
            except subprocess.TimeoutExpired:
                self._terminate_child(signal.SIGKILL)
                return proc.wait(timeout=self.terminate_timeout) or 0
        finally:
            if proc.stdin is not None and not proc.stdin.closed:
                proc.stdin.close()

    def _require_proc(self) -> subprocess.Popen[bytes]:
        if self._proc is None:
            raise RuntimeError("child process was not started")
        return self._proc

    def _write_error(self, message: str) -> None:
        if self.stderr is not None:
            self.stderr.write(message)
            self.stderr.flush()


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    config: ConnectorConfig = ConnectorConfig(),
    runtime_config_path: os.PathLike[str] | str = INSTALLED_CONNECTOR_CONFIG_PATH,
    runtime_expected_oathtool_path: os.PathLike[str] | str = INSTALLED_OATHTOOL_PATH,
    runtime_trusted_parent: os.PathLike[str] | str = INSTALLED_TRUSTED_PARENT,
    runtime_required_uid: int = 0,
) -> int:
    if argv:
        print("hyu-vpn-connect does not accept arguments", file=sys.stderr)
        return 2
    try:
        runtime_config = load_connector_runtime_config(
            config_path=runtime_config_path,
            expected_oathtool_path=runtime_expected_oathtool_path,
            trusted_parent=runtime_trusted_parent,
            required_uid=runtime_required_uid,
        )
    except ConnectorRuntimeConfigError:
        print("invalid connector runtime configuration", file=sys.stderr)
        return 1
    try:
        keychain = Keychain()
        username = keychain.read("gp-vpn-username")
        password = keychain.read("gp-vpn-password")
        totp_seed = keychain.read("gp-vpn-totp")
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    provider = TotpProvider(totp_seed, oathtool_path=runtime_config.oathtool_path, state_path=TOTP_STATE_PATH)
    return PromptSession(
        build_helper_argv(config=config),
        password=password,
        totp_provider=provider,
        start_username=username,
        stdout=None,
        event_sink=write_connector_event,
    ).run()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
