"""Safe OpenConnect csd-wrapper CLI for HYU GlobalProtect HIP reports."""

from __future__ import annotations

import os
import sys
from dataclasses import replace
from datetime import datetime
from typing import BinaryIO, Callable, Mapping, Optional, Protocol, Sequence, TextIO

from .hip_contract import CookieIdentity, HipInvocation, HipInvocationError
from .hip_xml import Drive, MacPosture, NetworkInterface, Patch, Product, build_hip_xml
from .macos_posture import MacPostureCollector


class _StdoutLike(Protocol):
    buffer: BinaryIO


_KNOWN_OPTIONS = {
    "--cookie",
    "--client-ip",
    "--client-ipv6",
    "--md5",
    "--client-os",
    "--app-version",
}


def main(
    argv: Optional[Sequence[str]] = None,
    environ: Optional[Mapping[str, str]] = None,
    *,
    _collector_factory: Callable[[], MacPostureCollector] = MacPostureCollector,
    _stdout: _StdoutLike = sys.stdout,
    _stderr: TextIO = sys.stderr,
    _now: Callable[[], datetime] = datetime.now,
) -> int:
    """Emit exactly one HIP XML document to stdout for OpenConnect.

    Diagnostics are intentionally class-only and redacted. Test seams are private
    keyword-only arguments so production behavior is not controlled by the
    environment.
    """

    args = tuple(sys.argv[1:] if argv is None else argv)
    env = dict(environ) if environ is not None else dict(os.environ)
    try:
        _validate_exact_options(args)
        invocation = HipInvocation.from_argv(args, env)
        _validate_authoritative_invocation(invocation)
        invocation = _clean_invocation(invocation)
    except HipInvocationError as exc:
        _write_stderr(_stderr, f"HIP invocation error: {_safe_invocation_message(str(exc))}\n")
        return 2

    try:
        identity = CookieIdentity.from_encoded(invocation.cookie)
        _validate_authoritative_identity(identity)
    except HipInvocationError:
        _write_stderr(_stderr, "HIP cookie error\n")
        return 2

    try:
        posture = _clean_posture(_collector_factory().collect())
    except Exception:
        _write_stderr(_stderr, "HIP collection error\n")
        return 3

    try:
        xml = build_hip_xml(invocation, identity, posture, _now())
    except Exception:
        _write_stderr(_stderr, "HIP XML generation error\n")
        return 4

    try:
        _write_all(_stdout.buffer, xml)
        _stdout.buffer.flush()
    except (BrokenPipeError, OSError):
        _write_stderr(_stderr, "HIP output error\n")
        return 5
    return 0


def _validate_exact_options(argv: Sequence[str]) -> None:
    index = 0
    unknown: list[str] = []
    while index < len(argv):
        item = argv[index]
        if item == "--":
            unknown.append("--")
            break
        if item.startswith("--"):
            option = item.split("=", 1)[0]
            if option not in _KNOWN_OPTIONS:
                unknown.append(option)
                if "=" not in item and index + 1 < len(argv) and not argv[index + 1].startswith("--"):
                    index += 1
            elif "=" not in item:
                index += 1
                if index >= len(argv):
                    raise HipInvocationError(f"missing value for {option}")
        else:
            unknown.append("argument")
        index += 1
    if unknown:
        raise HipInvocationError("unknown option(s): " + ", ".join(dict.fromkeys(unknown)))


def _safe_invocation_message(message: str) -> str:
    allowed = [name for name in (*_KNOWN_OPTIONS, "--client-ip or --client-ipv6") if name in message]
    if "unknown option" in message:
        return "unknown option"
    if allowed:
        return ", ".join(dict.fromkeys(allowed))
    return "invalid arguments"


def _write_stderr(stderr: TextIO, message: str) -> None:
    try:
        stderr.write(message)
        stderr.flush()
    except Exception:
        pass


def _write_all(stream: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = stream.write(view[offset:])
        if not isinstance(written, int) or written <= 0 or written > len(view) - offset:
            raise OSError("short HIP output write")
        offset += written


def _validate_authoritative_text(value: Optional[str]) -> None:
    if value is None:
        return
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise HipInvocationError("invalid authoritative text") from None
    if "\ufffd" in value:
        raise HipInvocationError("invalid authoritative text")


def _validate_authoritative_invocation(invocation: HipInvocation) -> None:
    for value in (
        invocation.cookie,
        invocation.client_ip,
        invocation.client_ipv6,
        invocation.md5,
        invocation.client_os,
    ):
        _validate_authoritative_text(value)


def _validate_authoritative_identity(identity: CookieIdentity) -> None:
    for value in (identity.user, identity.domain, identity.computer):
        _validate_authoritative_text(value)


def _clean_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    repaired = value.encode("utf-8", "replace").decode("utf-8", "replace")
    return "".join(
        character
        for character in repaired
        if character in "\t\n\r"
        or (
            ord(character) >= 0x20
            and not 0x7F <= ord(character) <= 0x9F
            and ord(character) not in {0xFFFE, 0xFFFF}
        )
    )


def _clean_tuple(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(_clean_text(value) or "" for value in values)


def _clean_invocation(invocation: HipInvocation) -> HipInvocation:
    return replace(
        invocation,
        app_version=_clean_text(invocation.app_version),
    )


def _clean_posture(posture: MacPosture) -> MacPosture:
    host = posture.host_info
    interfaces = tuple(
        NetworkInterface(
            name=_clean_text(interface.name) or "unknown",
            description=_clean_text(interface.description),
            mac_address=_clean_text(interface.mac_address),
            ipv4_addresses=_clean_tuple(interface.ipv4_addresses),
            ipv6_addresses=_clean_tuple(interface.ipv6_addresses),
        )
        for interface in host.interfaces
    )
    clean_host = replace(
        host,
        host_name=_clean_text(host.host_name),
        user_name=_clean_text(host.user_name),
        os=_clean_text(host.os),
        os_version=_clean_text(host.os_version),
        client_version=_clean_text(host.client_version),
        os_vendor=_clean_text(host.os_vendor),
        domain=_clean_text(host.domain),
        host_id=_clean_text(host.host_id),
        interfaces=interfaces,
        interface_name=_clean_text(host.interface_name),
        mac_address=_clean_text(host.mac_address),
    )
    return replace(
        posture,
        host_info=clean_host,
        anti_malware=tuple(_clean_product(product) for product in posture.anti_malware),
        disk_backup=tuple(_clean_product(product) for product in posture.disk_backup),
        disk_encryption=tuple(_clean_drive(drive) for drive in posture.disk_encryption),
        firewall=tuple(_clean_product(product) for product in posture.firewall),
        patch_management_product=_clean_product(posture.patch_management_product),
        patches=tuple(_clean_patch(patch) for patch in posture.patches),
    )


def _clean_product(product: Product) -> Product:
    return replace(
        product,
        name=_clean_text(product.name) or "",
        vendor=_clean_text(product.vendor),
        version=_clean_text(product.version),
        defver=_clean_text(product.defver),
        engver=_clean_text(product.engver),
        datemon=_clean_text(product.datemon),
        dateday=_clean_text(product.dateday),
        dateyear=_clean_text(product.dateyear),
        prod_type=_clean_text(product.prod_type),
        os_type=_clean_text(product.os_type),
        real_time_protection=_clean_text(product.real_time_protection),
        last_full_scan_time=_clean_text(product.last_full_scan_time),
        last_backup_time=_clean_text(product.last_backup_time),
        is_enabled=_clean_text(product.is_enabled),
    )


def _clean_drive(drive: Drive) -> Drive:
    return replace(
        drive,
        drive_name=_clean_text(drive.drive_name) or "",
        enc_state=_clean_text(drive.enc_state),
        product_version=_clean_text(drive.product_version),
    )


def _clean_patch(patch: Patch) -> Patch:
    return replace(
        patch,
        title=_clean_text(patch.title) or "",
        description=_clean_text(patch.description),
        product=_clean_text(patch.product),
        vendor=_clean_text(patch.vendor),
        info_url=_clean_text(patch.info_url),
        kb_article_id=_clean_text(patch.kb_article_id),
        security_bulletin_id=_clean_text(patch.security_bulletin_id),
        severity=_clean_text(patch.severity),
        category=_clean_text(patch.category),
        is_installed=_clean_text(patch.is_installed),
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
