"""Deterministic HIP v4 XML generation."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Tuple

from .hip_contract import CookieIdentity, HipInvocation


@dataclass(frozen=True)
class HostInfo:
    host_name: Optional[str] = None
    user_name: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    interface_name: Optional[str] = None
    mac_address: Optional[str] = None


@dataclass(frozen=True)
class Product:
    name: str
    version: Optional[str] = None
    definition_date: Optional[str] = None
    real_time_protection: Optional[str] = None
    state: Optional[str] = None
    enabled: Optional[str] = None


@dataclass(frozen=True)
class Drive:
    name: str
    encrypted: Optional[str] = None


@dataclass(frozen=True)
class Patch:
    id: str
    severity: Optional[str] = None


def _default_anti_malware() -> Tuple[Product, ...]:
    return (Product(name="XProtect"),)


def _default_disk_backup() -> Tuple[Product, ...]:
    return (Product(name="Time Machine"),)


def _default_disk_encryption() -> Tuple[Drive, ...]:
    return (Drive(name="FileVault"),)


def _default_firewall() -> Tuple[Product, ...]:
    return (Product(name="Application Firewall"), Product(name="Packet Filter"))


def _default_data_loss_prevention() -> Tuple[Product, ...]:
    return (Product(name="Gatekeeper"),)


@dataclass(frozen=True)
class MacPosture:
    host_info: HostInfo = field(default_factory=HostInfo)
    anti_malware: Tuple[Product, ...] = field(default_factory=_default_anti_malware)
    disk_backup: Tuple[Product, ...] = field(default_factory=_default_disk_backup)
    disk_encryption: Tuple[Drive, ...] = field(default_factory=_default_disk_encryption)
    firewall: Tuple[Product, ...] = field(default_factory=_default_firewall)
    patches: Tuple[Patch, ...] = ()
    data_loss_prevention: Tuple[Product, ...] = field(default_factory=_default_data_loss_prevention)


_CATEGORY_ORDER = (
    "host-info",
    "anti-malware",
    "disk-backup",
    "disk-encryption",
    "firewall",
    "patch-management",
    "data-loss-prevention",
)


def _add_text(parent: ET.Element, tag: str, value: Optional[str]) -> ET.Element:
    child = ET.SubElement(parent, tag)
    if value is not None:
        child.text = value
    return child


def _known_or_unknown(value: Optional[str]) -> str:
    return value if value is not None else "unknown"


def _add_host_info(category: ET.Element, invocation: HipInvocation, posture: HostInfo) -> None:
    _add_text(category, "host-name", posture.host_name)
    _add_text(category, "user-name", posture.user_name)
    _add_text(category, "os", posture.os)
    _add_text(category, "os-version", posture.os_version)
    if posture.interface_name or posture.mac_address or invocation.client_ip or invocation.client_ipv6:
        interfaces = ET.SubElement(category, "network-interfaces")
        interface = ET.SubElement(interfaces, "interface")
        _add_text(interface, "name", posture.interface_name)
        _add_text(interface, "mac-address", posture.mac_address)
        _add_text(interface, "ipv4", invocation.client_ip)
        _add_text(interface, "ipv6", invocation.client_ipv6)


def _add_anti_malware(category: ET.Element, products: Tuple[Product, ...]) -> None:
    for product in products:
        node = ET.SubElement(category, "product")
        _add_text(node, "name", product.name)
        _add_text(node, "version", product.version)
        _add_text(node, "definition-date", product.definition_date)
        _add_text(node, "real-time-protection", _known_or_unknown(product.real_time_protection))


def _add_disk_backup(category: ET.Element, products: Tuple[Product, ...]) -> None:
    for product in products:
        node = ET.SubElement(category, "product")
        _add_text(node, "name", product.name)
        _add_text(node, "state", _known_or_unknown(product.state))


def _add_disk_encryption(category: ET.Element, drives: Tuple[Drive, ...]) -> None:
    for drive in drives:
        node = ET.SubElement(category, "product")
        _add_text(node, "name", drive.name)
        _add_text(node, "encrypted", _known_or_unknown(drive.encrypted))


def _add_firewall(category: ET.Element, products: Tuple[Product, ...]) -> None:
    for product in products:
        node = ET.SubElement(category, "product")
        _add_text(node, "name", product.name)
        _add_text(node, "enabled", _known_or_unknown(product.enabled))


def _add_patch_management(category: ET.Element, patches: Tuple[Patch, ...]) -> None:
    if not patches:
        return
    product = ET.SubElement(category, "product")
    _add_text(product, "name", "Apple Software Update")
    missing = ET.SubElement(product, "missing-patches")
    for patch in patches:
        node = ET.SubElement(missing, "patch")
        _add_text(node, "id", patch.id)
        _add_text(node, "severity", _known_or_unknown(patch.severity))


def _add_data_loss_prevention(category: ET.Element, products: Tuple[Product, ...]) -> None:
    for product in products:
        node = ET.SubElement(category, "product")
        _add_text(node, "name", product.name)
        _add_text(node, "enabled", _known_or_unknown(product.enabled))


def build_hip_xml(
    invocation: HipInvocation,
    identity: CookieIdentity,
    posture: MacPosture,
    generated_at: datetime,
) -> bytes:
    root = ET.Element("hip-report")
    _add_text(root, "report-version", "4")
    _add_text(root, "md5-sum", invocation.md5)
    _add_text(root, "user", identity.user)
    _add_text(root, "domain", identity.domain)
    _add_text(root, "computer", identity.computer)
    _add_text(root, "client-ip", invocation.client_ip)
    _add_text(root, "client-ipv6", invocation.client_ipv6)
    _add_text(root, "generated-at", generated_at.isoformat())

    categories = ET.SubElement(root, "categories")
    for name in _CATEGORY_ORDER:
        category = ET.SubElement(categories, "category", {"name": name})
        if name == "host-info":
            _add_host_info(category, invocation, posture.host_info)
        elif name == "anti-malware":
            _add_anti_malware(category, posture.anti_malware)
        elif name == "disk-backup":
            _add_disk_backup(category, posture.disk_backup)
        elif name == "disk-encryption":
            _add_disk_encryption(category, posture.disk_encryption)
        elif name == "firewall":
            _add_firewall(category, posture.firewall)
        elif name == "patch-management":
            _add_patch_management(category, posture.patches)
        elif name == "data-loss-prevention":
            _add_data_loss_prevention(category, posture.data_loss_prevention)

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
