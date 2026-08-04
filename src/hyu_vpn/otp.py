"""Secret retrieval and TOTP generation boundaries for HYU VPN."""

from __future__ import annotations

import subprocess
import time
from typing import Callable, Mapping, Optional, Sequence


SECURITY = "/usr/bin/security"
OATHTOOL = "/opt/homebrew/bin/oathtool"


class TotpError(RuntimeError):
    """Raised when a TOTP value cannot be generated safely."""


class Keychain:
    def __init__(self, *, security_path: str = SECURITY, runner: Optional[Callable[..., subprocess.CompletedProcess[str]]] = None) -> None:
        self.security_path = security_path
        self.runner = runner or subprocess.run

    def read(self, service: str) -> str:
        argv = [self.security_path, "find-generic-password", "-s", service, "-w"]
        completed = self.runner(argv, capture_output=True, text=True, check=False)
        value = (completed.stdout or "").strip()
        if completed.returncode != 0 or not value:
            raise RuntimeError(f"missing keychain item: {service}")
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
    ) -> None:
        self.secret = secret
        self.oathtool_path = oathtool_path
        self.runner = runner or subprocess.run
        self.environ = dict(environ) if environ is not None else None
        self.clock = clock
        self.sleep = sleep
        self.max_wait = max_wait
        self._last: Optional[str] = None

    def current(self) -> str:
        value = self._generate()
        if self._last is not None and value == self._last:
            wait = _seconds_until_next_totp_window(self.clock(), self.max_wait)
            self.sleep(wait)
            value = self._generate()
            if value == self._last:
                raise TotpError("TOTP generation failed")
        self._last = value
        return value

    def _generate(self) -> str:
        completed = self.runner(
            [self.oathtool_path, "--totp", "-b", self.secret],
            capture_output=True,
            text=True,
            check=False,
            env=self.environ,
        )
        value = (completed.stdout or "").strip()
        if completed.returncode != 0 or not value:
            raise TotpError("TOTP generation failed")
        return value


def _seconds_until_next_totp_window(now: float, max_wait: float) -> float:
    remainder = int(now) % 30
    wait = 30 - remainder if remainder else 30
    return min(max(wait, 1), max_wait)
