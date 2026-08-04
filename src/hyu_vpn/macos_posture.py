"""macOS posture collection for HIP reports."""

from __future__ import annotations

import json
import os
import plistlib
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional, Sequence, Tuple

from .hip_xml import Drive, HostInfo, MacPosture, NetworkInterface, Patch, Product


@dataclass(frozen=True)
class CommandResult:
    argv: Sequence[str]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner:
    def run(self, argv: Sequence[str], timeout: float) -> CommandResult:
        try:
            env = os.environ.copy()
            env["LC_ALL"] = "C"
            env["LANG"] = "C"
            completed = subprocess.run(
                list(argv),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=env,
            )
            return CommandResult(tuple(argv), completed.returncode, completed.stdout, completed.stderr)
        except (subprocess.TimeoutExpired, TimeoutError) as exc:
            stdout = getattr(exc, "stdout", "") or ""
            stderr = getattr(exc, "stderr", "") or "timed out"
            return CommandResult(tuple(argv), -1, stdout if isinstance(stdout, str) else stdout.decode("utf-8", "replace"), stderr if isinstance(stderr, str) else stderr.decode("utf-8", "replace"))
        except (FileNotFoundError, PermissionError) as exc:
            return CommandResult(tuple(argv), 127, "", str(exc))


class MacPostureCollector:
    def __init__(
        self,
        runner: Optional[CommandRunner] = None,
        *,
        system_version_plist: Path | str = "/System/Library/CoreServices/SystemVersion.plist",
        xprotect_plist: Path | str = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
        software_update_cache: Path | str | None = None,
        now: Optional[Callable[[], datetime]] = None,
        software_update_timeout: float = 45.0,
    ) -> None:
        self.runner = runner or CommandRunner()
        self.system_version_plist = Path(system_version_plist)
        self.xprotect_plist = Path(xprotect_plist)
        self.software_update_cache = Path(software_update_cache) if software_update_cache is not None else Path.home() / ".cache" / "hyu-openconnect" / "softwareupdate-cache.json"
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.software_update_timeout = software_update_timeout

    def collect(self) -> MacPosture:
        os_version = self._collect_os_version()
        interface_name, mac_address = self._collect_physical_identity()
        interfaces = (NetworkInterface(name=interface_name, mac_address=mac_address),) if interface_name else ()
        xprotect = self._collect_xprotect()
        gatekeeper = self._collect_gatekeeper()
        filevault = self._collect_filevault()
        app_firewall = self._collect_application_firewall()
        pf = self._collect_packet_filter()
        patches, patch_scan_state = self._collect_software_updates()
        return MacPosture(
            host_info=HostInfo(
                os=f"Apple Mac OS X {os_version}" if os_version else "Apple Mac OS X",
                os_version=os_version,
                os_vendor="Apple",
                interface_name=interface_name,
                mac_address=mac_address,
                host_id=mac_address,
                interfaces=interfaces,
            ),
            anti_malware=(xprotect, gatekeeper),
            disk_encryption=(filevault,),
            firewall=(app_firewall, pf),
            patch_management_product=Product(vendor="Apple Inc.", name="Software Update", version="3.0", is_enabled=patch_scan_state),
            patches=patches,
        )

    def _collect_os_version(self) -> Optional[str]:
        data = _read_plist(self.system_version_plist)
        return _string_value(data.get("ProductVersion"))

    def _collect_xprotect(self) -> Product:
        data = _read_plist(self.xprotect_plist)
        version = _string_value(data.get("CFBundleShortVersionString") or data.get("CFBundleVersion"))
        definition_date = _date_value(data.get("LastModification") or data.get("BuildDate"))
        if definition_date is None:
            definition_date = _file_mtime_date(self.xprotect_plist)
        date_parts = _date_parts(definition_date)
        return Product(
            vendor="Apple Inc.",
            name="Xprotect",
            version=version or "n/a",
            defver=version or "",
            engver="",
            datemon=date_parts[0],
            dateday=date_parts[1],
            dateyear=date_parts[2],
            prod_type="3",
            os_type="4",
            real_time_protection="yes" if version else "n/a",
            last_full_scan_time="n/a",
        )

    def _collect_software_updates(self) -> tuple[Tuple[Patch, ...], str]:
        cached = self._read_update_cache()
        if cached is not None:
            return cached, "yes"
        status = self._run_status(("/usr/sbin/softwareupdate", "--list"), self.software_update_timeout)
        if status.returncode != 0:
            return (), "n/a"
        patches = _parse_softwareupdate_list(status.stdout)
        if patches is None:
            return (), "n/a"
        self._write_update_cache(patches)
        return patches, "yes"

    def _read_update_cache(self) -> Optional[Tuple[Patch, ...]]:
        try:
            raw = json.loads(self.software_update_cache.read_text(encoding="utf-8"))
            created = datetime.fromisoformat(raw.get("created_at", ""))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if self.now() - created > timedelta(hours=6):
                return None
            patches = raw.get("patches")
            if not isinstance(patches, list):
                return None
            parsed: list[Patch] = []
            for item in patches:
                if not isinstance(item, dict):
                    return None
                title = _string_value(item.get("title") or item.get("id"))
                if title is None:
                    return None
                parsed.append(_patch_from_title(title, _string_value(item.get("severity")) or "1"))
            return tuple(parsed)
        except (FileNotFoundError, OSError, ValueError, TypeError):
            return None

    def _write_update_cache(self, patches: Tuple[Patch, ...]) -> None:
        payload = {
            "created_at": self.now().isoformat(),
            "patches": [{"title": patch.title, "severity": patch.severity or "1"} for patch in patches],
        }
        self.software_update_cache.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.software_update_cache.name}.",
            suffix=".tmp",
            dir=str(self.software_update_cache.parent),
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, sort_keys=True)
                fh.write("\n")
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.software_update_cache)
            os.chmod(self.software_update_cache, 0o600)
        finally:
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass

    def _collect_physical_identity(self) -> tuple[Optional[str], Optional[str]]:
        status = self._run_status(("/usr/sbin/networksetup", "-listallhardwareports"), 5.0)
        if status.returncode == 0:
            parsed = _parse_networksetup_hardware_ports(status.stdout)
            if parsed is not None:
                return parsed
        status = self._run_status(("/sbin/ifconfig",), 5.0)
        if status.returncode == 0:
            parsed = _parse_ifconfig_interfaces(status.stdout)
            if parsed is not None:
                return parsed
        return None, None

    def _collect_gatekeeper(self) -> Product:
        status = self._run_status(("/usr/sbin/spctl", "--status"), 5.0)
        rtp = _parse_yes_no_na(status.stdout, "assessments enabled", "assessments disabled") if status.returncode == 0 else "n/a"
        return Product(vendor="Apple Inc.", name="Gatekeeper", version="n/a", defver="", engver="", datemon="", dateday="", dateyear="", prod_type="3", os_type="4", real_time_protection=rtp, last_full_scan_time="n/a")

    def _collect_filevault(self) -> Drive:
        status = self._run_status(("/usr/bin/fdesetup", "status"), 5.0)
        enc_state = "unknown"
        if status.returncode == 0:
            text = status.stdout.lower()
            if "filevault is on" in text:
                enc_state = "encrypted"
            elif "filevault is off" in text:
                enc_state = "unencrypted"
        return Drive(drive_name="All", enc_state=enc_state)

    def _collect_application_firewall(self) -> Product:
        status = self._run_status(("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"), 5.0)
        enabled = _parse_yes_no_na(status.stdout, "firewall is enabled", "firewall is disabled") if status.returncode == 0 else "n/a"
        return Product(vendor="Apple Inc.", name="Mac OS X Builtin Firewall", version="n/a", is_enabled=enabled)

    def _collect_packet_filter(self) -> Product:
        status = self._run_status(("/sbin/pfctl", "-s", "info"), 5.0)
        enabled = _parse_yes_no_na(status.stdout, "status: enabled", "status: disabled") if status.returncode == 0 else "n/a"
        return Product(vendor="OpenBSD", name="Packet Filter", version="n/a", is_enabled=enabled)

    def _run_status(self, argv: Sequence[str], timeout: float) -> CommandResult:
        return self.runner.run(tuple(argv), timeout)


def _read_plist(path: Path) -> dict:
    try:
        with path.open("rb") as fh:
            data = plistlib.load(fh)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, PermissionError, plistlib.InvalidFileException, OSError, ValueError):
        return {}


def _string_value(value: object) -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _date_value(value: object) -> Optional[str]:
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, str) and value.strip():
        return value.strip()[:10]
    return None


def _file_mtime_date(path: Path) -> Optional[str]:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).date().isoformat()
    except OSError:
        return None


def _date_parts(value: Optional[str]) -> tuple[str, str, str]:
    if not value:
        return "", "", ""
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})", value)
    if not match:
        return "", "", ""
    return match.group(2), match.group(3), match.group(1)


def _parse_yes_no_na(stdout: str, enabled_phrase: str, disabled_phrase: str) -> str:
    text = stdout.lower()
    if enabled_phrase in text:
        return "yes"
    if disabled_phrase in text:
        return "no"
    return "n/a"


_MAC_RE = re.compile(r"(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b")
_EXCLUDED_INTERFACE_PREFIXES = ("lo", "utun", "tun", "tap", "ipsec", "gif", "stf", "awdl", "llw", "bridge")


def _valid_mac(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    match = _MAC_RE.search(value.strip())
    if not match:
        return None
    mac = match.group(1).lower()
    if mac == "00:00:00:00:00:00":
        return None
    return mac


def _is_physical_interface(name: Optional[str]) -> bool:
    if not name:
        return False
    lowered = name.lower()
    return not any(lowered.startswith(prefix) for prefix in _EXCLUDED_INTERFACE_PREFIXES)


def _parse_networksetup_hardware_ports(stdout: str) -> Optional[tuple[str, str]]:
    candidates: list[tuple[str, str, str]] = []
    current: dict[str, str] = {}
    for raw_line in stdout.splitlines() + [""]:
        line = raw_line.strip()
        if not line:
            device = current.get("Device")
            mac = _valid_mac(current.get("Ethernet Address"))
            port = current.get("Hardware Port", "")
            if _is_physical_interface(device) and mac:
                candidates.append((port, device, mac))
            current = {}
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current[key.strip()] = value.strip()
    if not candidates:
        return None
    for port, device, mac in candidates:
        if port.lower() == "wi-fi":
            return device, mac
    return candidates[0][1], candidates[0][2]


def _parse_ifconfig_interfaces(stdout: str) -> Optional[tuple[str, str]]:
    current_name: Optional[str] = None
    current_is_physical = False
    for line in stdout.splitlines():
        header = re.match(r"^([A-Za-z0-9_.-]+):\s+flags=", line)
        if header:
            current_name = header.group(1)
            current_is_physical = _is_physical_interface(current_name)
            continue
        if current_is_physical and "ether" in line:
            mac = _valid_mac(line)
            if mac:
                return current_name, mac
    return None


_LABEL_RE = re.compile(r"^\s*\*\s+Label:\s*(.+?)\s*$")


def _patch_from_title(title: str, severity: str) -> Patch:
    return Patch(
        title=title,
        description=title,
        product="macOS",
        vendor="Apple Inc.",
        info_url=None,
        kb_article_id=None,
        security_bulletin_id=None,
        severity=severity,
        category="update",
        is_installed="no",
    )


def _parse_softwareupdate_list(stdout: str) -> Optional[Tuple[Patch, ...]]:
    lowered = stdout.lower()
    if "no new software available" in lowered:
        return ()

    patches: list[Patch] = []
    current_label: Optional[str] = None
    current_restart = False

    def flush() -> None:
        nonlocal current_label, current_restart
        if current_label:
            patches.append(_patch_from_title(current_label, "2" if current_restart else "1"))
        current_label = None
        current_restart = False

    for line in stdout.splitlines():
        label_match = _LABEL_RE.match(line)
        if label_match:
            flush()
            current_label = label_match.group(1).strip()
            continue
        if current_label and "restart" in line.lower():
            current_restart = True
    flush()
    if patches:
        return tuple(patches)
    return None
