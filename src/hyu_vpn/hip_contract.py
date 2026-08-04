"""Contract types for OpenConnect HIP script invocation."""

from __future__ import annotations

import argparse
from urllib.parse import parse_qs
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence


class HipInvocationError(ValueError):
    """Raised when OpenConnect HIP invocation arguments are invalid."""


class _HipArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - defensive argparse hook
        raise HipInvocationError(message)


@dataclass(frozen=True)
class CookieIdentity:
    user: str
    domain: Optional[str] = None
    computer: Optional[str] = None

    @classmethod
    def from_encoded(cls, value: str) -> "CookieIdentity":
        parsed = parse_qs(value, keep_blank_values=True)

        def first(name: str) -> Optional[str]:
            values = parsed.get(name)
            return values[0] if values else None

        user = first("user")
        if user is None:
            raise HipInvocationError("missing required cookie field: user")

        return cls(
            user=user,
            domain=first("domain"),
            computer=first("computer"),
        )


@dataclass(frozen=True)
class HipInvocation:
    cookie: str
    client_ip: Optional[str]
    client_ipv6: Optional[str]
    md5: str
    client_os: Optional[str] = None
    app_version: Optional[str] = None

    @classmethod
    def from_argv(cls, argv: Sequence[str], environ: Mapping[str, str]) -> "HipInvocation":
        parser = _HipArgumentParser(add_help=False)
        parser.add_argument("--cookie")
        parser.add_argument("--client-ip")
        parser.add_argument("--client-ipv6")
        parser.add_argument("--md5")
        parser.add_argument("--client-os")
        parser.add_argument("--app-version")
        parsed, _ = parser.parse_known_args(list(argv))

        missing = []
        if not parsed.cookie:
            missing.append("--cookie")
        if not parsed.md5:
            missing.append("--md5")
        if not (parsed.client_ip or parsed.client_ipv6):
            missing.append("--client-ip or --client-ipv6")
        if missing:
            raise HipInvocationError("missing required option(s): " + ", ".join(missing))

        return cls(
            cookie=parsed.cookie,
            client_ip=parsed.client_ip,
            client_ipv6=parsed.client_ipv6,
            md5=parsed.md5,
            client_os=parsed.client_os,
            app_version=parsed.app_version or environ.get("APP_VERSION"),
        )
