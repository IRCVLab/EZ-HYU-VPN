"""Network readiness probes and owned tunnel evidence for HYU VPN."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, Set


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def __call__(self, argv: list[str], timeout: float) -> object: ...


@dataclass(frozen=True)
class OwnedSessionEvidence:
    interfaces: Set[str] = field(default_factory=set)

    def owns_interface(self, name: Optional[str]) -> bool:
        return bool(name and name in self.interfaces)


def _run_command(argv: list[str], timeout: float) -> CommandResult:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return CommandResult(tuple(argv), completed.returncode, completed.stdout, completed.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CommandResult(tuple(argv), 1, "", exc.__class__.__name__)


def route_interface(stdout: str) -> Optional[str]:
    for line in stdout.splitlines():
        if line.strip().lower().startswith("interface:"):
            return line.split(":", 1)[1].strip() or None
    return None


def route_gateway(stdout: str) -> Optional[str]:
    for line in stdout.splitlines():
        if line.strip().lower().startswith("gateway:"):
            return line.split(":", 1)[1].strip() or None
    return None


class NetworkReadiness:
    def __init__(
        self,
        *,
        command_runner: Optional[Callable[[list[str], float], object]] = None,
        timeout: float = 2.0,
        dns_name: str = "secure.hanyang.ac.kr",
        stable_samples: int = 2,
        poll_interval: float = 5.0,
        wake_gap: float = 60.0,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.command_runner = command_runner or _run_command
        self.timeout = timeout
        self.dns_name = dns_name
        self.stable_samples = stable_samples
        self.poll_interval = poll_interval
        self.wake_gap = wake_gap
        self.monotonic = monotonic
        self.sleep = sleep

    def ready_once(self) -> Optional[tuple[str, str]]:
        route = self.command_runner(["/sbin/route", "-n", "get", "default"], self.timeout)
        if getattr(route, "returncode", 1) != 0:
            return None
        iface = route_interface(getattr(route, "stdout", ""))
        gateway = route_gateway(getattr(route, "stdout", ""))
        if not iface or not gateway or iface.startswith("utun"):
            return None
        dns = self.command_runner(["/usr/bin/dig", "+short", self.dns_name], self.timeout)
        if getattr(dns, "returncode", 1) != 0 or not getattr(dns, "stdout", "").strip():
            return None
        return iface, gateway

    def wait_until_ready(self, *, max_attempts: Optional[int] = None, stop_requested: Optional[Callable[[], bool]] = None) -> bool:
        stable = 0
        last_sample: Optional[tuple[str, str]] = None
        last_time: Optional[float] = None
        attempts = 0
        while max_attempts is None or attempts < max_attempts:
            if stop_requested is not None and stop_requested():
                return False
            now = self.monotonic()
            if last_time is not None and now - last_time > self.wake_gap:
                stable = 0
                last_sample = None
            last_time = now
            attempts += 1
            sample = self.ready_once()
            if sample is not None and sample == last_sample:
                stable += 1
            elif sample is not None:
                stable = 1
                last_sample = sample
            else:
                stable = 0
                last_sample = None
            if stable >= self.stable_samples:
                return True
            if max_attempts is not None and attempts >= max_attempts:
                break
            self.sleep(self.poll_interval)
        return False
