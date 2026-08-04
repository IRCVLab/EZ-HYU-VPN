"""PTY OpenConnect connector with dual-TOTP prompt handling and process ownership."""

from __future__ import annotations

import errno
import os
import pty
import re
import select
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import BinaryIO, Mapping, Optional, Sequence, TextIO

from .otp import Keychain, TotpError, TotpProvider


PORTAL = "secure.hanyang.ac.kr"
AUTHGROUP = "HYU-ExternalGW-General"
OPENCONNECT = "/opt/homebrew/bin/openconnect"
VPNC_SCRIPT = "/opt/homebrew/etc/vpnc/vpnc-script"

_PROMPT_RE = re.compile(rb"(?:Password|Challenge):\s*$", re.IGNORECASE)


@dataclass(frozen=True)
class ConnectorConfig:
    openconnect_path: str = OPENCONNECT
    portal: str = PORTAL
    authgroup: str = AUTHGROUP
    vpnc_script: str = VPNC_SCRIPT
    hip_wrapper: Optional[str] = None
    sudo_path: Optional[str] = "/usr/bin/sudo"


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


class PromptSession:
    def __init__(
        self,
        argv: Sequence[str],
        *,
        password: str,
        totp_provider: Optional[TotpProvider],
        environ: Optional[Mapping[str, str]] = None,
        stdout: Optional[BinaryIO] = sys.stdout.buffer,
        stderr: Optional[TextIO] = sys.stderr,
        terminate_timeout: float = 5.0,
    ) -> None:
        self.argv = list(argv)
        self.password = password
        self.totp_provider = totp_provider
        self.environ = dict(environ) if environ is not None else None
        self.stdout = stdout
        self.stderr = stderr
        self.terminate_timeout = terminate_timeout
        self._proc: Optional[subprocess.Popen[bytes]] = None
        self._received_signal: Optional[int] = None

    def run(self) -> int:
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
                if self.stdout is not None:
                    self.stdout.write(chunk)
                    self.stdout.flush()
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
            if self.stdout is not None:
                self.stdout.write(chunk)
                self.stdout.flush()

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


def main(argv: Optional[Sequence[str]] = None, *, config: ConnectorConfig = ConnectorConfig()) -> int:
    del argv  # reserved for future CLI flags; avoid parsing secrets from arguments.
    try:
        keychain = Keychain()
        username = keychain.read("gp-vpn-username")
        password = keychain.read("gp-vpn-password")
        totp_seed = keychain.read("gp-vpn-totp")
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    provider = TotpProvider(totp_seed)
    return PromptSession(
        build_openconnect_argv(username, config=config),
        password=password,
        totp_provider=provider,
    ).run()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
