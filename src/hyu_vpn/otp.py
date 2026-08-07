"""Secret retrieval and TOTP generation boundaries for HYU VPN."""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import tempfile
import time
import re
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence


CREDENTIAL_READER = "/Applications/HYU VPN.app/Contents/MacOS/HYUVPNCredentialReader"
OATHTOOL = "/opt/homebrew/bin/oathtool"
SUBPROCESS_TIMEOUT = 5.0


class TotpError(RuntimeError):
    """Raised when a TOTP value cannot be generated safely."""


class CredentialReader:
    def __init__(self, *, reader_path: str = CREDENTIAL_READER, runner: Optional[Callable[..., subprocess.CompletedProcess[str]]] = None) -> None:
        self.reader_path = reader_path
        self.runner = runner or subprocess.run

    def read(self, service: str) -> str:
        argv = [self.reader_path, service]
        try:
            completed = self.runner(
                argv,
                capture_output=True,
                text=True,
                check=False,
                timeout=SUBPROCESS_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError):
            raise RuntimeError(f"missing credential: {service}") from None
        value = (completed.stdout or "").strip()
        if completed.returncode != 0 or not value:
            raise RuntimeError(f"missing credential: {service}")
        return value


class TotpProvider:
    def __init__(
        self,
        secret: str,
        *,
        oathtool_path: str = OATHTOOL,
        runner: Optional[Callable[..., subprocess.CompletedProcess[str]]] = None,
        environ: Optional[Mapping[str, str]] = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        max_wait: float = 31.0,
        state_path: Optional[os.PathLike[str] | str] = None,
    ) -> None:
        self.secret = secret
        self.oathtool_path = oathtool_path
        self.runner = runner or subprocess.run
        self.environ = dict(environ) if environ is not None else None
        self.clock = clock
        self.sleep = sleep
        self.max_wait = max_wait
        self.state_path = Path(state_path) if state_path is not None else None
        self._last: Optional[str] = None

    def current(self) -> str:
        if self.state_path is not None:
            return self._current_with_counter_guard()
        value = self._generate()
        if self._last is not None and value == self._last:
            wait = _seconds_until_next_totp_window(self.clock(), self.max_wait)
            self.sleep(wait)
            value = self._generate()
            if value == self._last:
                raise TotpError("TOTP generation failed")
        self._last = value
        return value

    def _current_with_counter_guard(self) -> str:
        assert self.state_path is not None
        lock_path = self.state_path.with_name(self.state_path.name + ".lock")
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            os.chmod(lock_path, 0o600)
        except OSError:
            raise TotpError("TOTP generation failed") from None
        with os.fdopen(lock_fd, "r+") as lock_file:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                last_counter = self._read_last_counter()
                now = self.clock()
                counter = _totp_counter(now)
                if last_counter is not None and counter <= last_counter:
                    wait = _seconds_until_next_totp_window(now, self.max_wait)
                    self.sleep(wait)
                    now = self.clock()
                    counter = _totp_counter(now)
                    if counter <= last_counter:
                        raise TotpError("TOTP generation failed")
                value = self._generate()
                generated_counter = _totp_counter(self.clock())
                if generated_counter != counter:
                    counter = generated_counter
                    if last_counter is not None and counter <= last_counter:
                        raise TotpError("TOTP generation failed")
                    value = self._generate()
                    stable_counter = _totp_counter(self.clock())
                    if stable_counter != counter:
                        raise TotpError("TOTP generation failed")
                if self._last is not None and value == self._last:
                    now = self.clock()
                    wait = _seconds_until_next_totp_window(now, self.max_wait)
                    self.sleep(wait)
                    now = self.clock()
                    counter = _totp_counter(now)
                    if last_counter is not None and counter <= last_counter:
                        raise TotpError("TOTP generation failed")
                    value = self._generate()
                    generated_counter = _totp_counter(self.clock())
                    if generated_counter != counter:
                        counter = generated_counter
                        if last_counter is not None and counter <= last_counter:
                            raise TotpError("TOTP generation failed")
                        value = self._generate()
                        stable_counter = _totp_counter(self.clock())
                        if stable_counter != counter:
                            raise TotpError("TOTP generation failed")
                    if value == self._last:
                        raise TotpError("TOTP generation failed")
                self._write_last_counter(counter)
                self._last = value
                return value
            except TotpError:
                raise
            except OSError:
                raise TotpError("TOTP generation failed") from None

    def _read_last_counter(self) -> Optional[int]:
        assert self.state_path is not None
        if not self.state_path.exists():
            return None
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise TotpError("TOTP generation failed") from None
        if not isinstance(data, dict):
            raise TotpError("TOTP generation failed")
        if set(data) != {"last_counter"}:
            raise TotpError("TOTP generation failed")
        counter = data.get("last_counter")
        if not isinstance(counter, int) or counter < 0:
            raise TotpError("TOTP generation failed")
        return counter

    def _write_last_counter(self, counter: int) -> None:
        assert self.state_path is not None
        payload = json.dumps({"last_counter": counter}, separators=(",", ":"))
        tmp_name = None
        try:
            fd, tmp_name = tempfile.mkstemp(prefix=self.state_path.name + ".", suffix=".tmp", dir=str(self.state_path.parent))
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, self.state_path)
            os.chmod(self.state_path, 0o600)
        except OSError:
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
            raise TotpError("TOTP generation failed") from None

    def _generate(self) -> str:
        try:
            completed = self.runner(
                [self.oathtool_path, "--totp", "-b", "-"],
                input=self.secret + "\n",
                capture_output=True,
                text=True,
                check=False,
                env=self.environ,
                timeout=SUBPROCESS_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError):
            raise TotpError("TOTP generation failed") from None
        value = (completed.stdout or "").strip()
        if completed.returncode != 0 or re.fullmatch(r"[0-9]{6}", value) is None:
            raise TotpError("TOTP generation failed")
        return value


def _seconds_until_next_totp_window(now: float, max_wait: float) -> float:
    remainder = int(now) % 30
    wait = 30 - remainder if remainder else 30
    return min(max(wait, 1), max_wait)


def _totp_counter(now: float) -> int:
    return int(now) // 30
