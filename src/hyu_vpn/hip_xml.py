"""Deterministic HIP v4 XML generation."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Tuple

from .hip_contract import CookieIdentity, HipInvocation


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    description: Optional[str] = None
    mac_address: Optional[str] = None
    ipv4_addresses: Tuple[str, ...] = ()
    ipv6_addresses: Tuple[str, ...] = ()


@dataclass(frozen=True)
class HostInfo:
    host_name: Optional[str] = None
    user_name: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    client_version: Optional[str] = None
    os_vendor: Optional[str] = "Apple"
    domain: Optional[str] = None
    host_id: Optional[str] = None
    interfaces: Tuple[NetworkInterface, ...] = ()
    interface_name: Optional[str] = None
    mac_address: Optional[str] = None


@dataclass(frozen=True)
class Product:
    name: str
    vendor: Optional[str] = None
    version: Optional[str] = None
    defver: Optional[str] = None
    engver: Optional[str] = None
    datemon: Optional[str] = None
    dateday: Optional[str] = None
    dateyear: Optional[str] = None
    prod_type: Optional[str] = None
    os_type: Optional[str] = None
    real_time_protection: Optional[str] = None
    last_full_scan_time: Optional[str] = None
    last_backup_time: Optional[str] = None
    is_enabled: Optional[str] = None


@dataclass(frozen=True)
class Drive:
    drive_name: str
    enc_state: Optional[str] = None
    product_version: Optional[str] = None


@dataclass(frozen=True)
class Patch:
    title: str
    description: Optional[str] = None
    product: Optional[str] = None
    vendor: Optional[str] = None
    info_url: Optional[str] = None
    kb_article_id: Optional[str] = None
    security_bulletin_id: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    is_installed: Optional[str] = None


_AM_DATE_DEFAULTS = {"defver": "", "engver": "", "datemon": "", "dateday": "", "dateyear": "", "prod_type": "3", "os_type": "4"}


def _apple_product(name: str, version: Optional[str] = "n/a", **kwargs: Optional[str]) -> Product:
    return Product(vendor="Apple Inc.", name=name, version=version, **kwargs)


def _default_anti_malware() -> Tuple[Product, ...]:
    return (
        _apple_product("Xprotect", real_time_protection="n/a", last_full_scan_time="n/a", **_AM_DATE_DEFAULTS),
        _apple_product("Gatekeeper", real_time_protection="n/a", last_full_scan_time="n/a", **_AM_DATE_DEFAULTS),
    )


def _default_disk_backup() -> Tuple[Product, ...]:
    return (_apple_product("Time Machine", version="1.3", last_backup_time="n/a"),)


def _default_disk_encryption_drives() -> Tuple[Drive, ...]:
    return (Drive(drive_name="All", enc_state="unknown"),)


def _default_firewall() -> Tuple[Product, ...]:
    return (
        _apple_product("Mac OS X Builtin Firewall", is_enabled="n/a"),
        Product(vendor="OpenBSD", name="Packet Filter", version="n/a", is_enabled="n/a"),
    )


def _default_patch_management_product() -> Product:
    return _apple_product("Software Update", version="3.0", is_enabled="n/a")


@dataclass(frozen=True)
class MacPosture:
    host_info: HostInfo = field(default_factory=HostInfo)
    anti_malware: Tuple[Product, ...] = field(default_factory=_default_anti_malware)
    disk_backup: Tuple[Product, ...] = field(default_factory=_default_disk_backup)
    disk_encryption: Tuple[Drive, ...] = field(default_factory=_default_disk_encryption_drives)
    firewall: Tuple[Product, ...] = field(default_factory=_default_firewall)
    patch_management_product: Product = field(default_factory=_default_patch_management_product)
    patches: Tuple[Patch, ...] = ()


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


def _value_or_na(value: Optional[str]) -> str:
    return value if value is not None else "n/a"


def _value_or_unknown(value: Optional[str]) -> str:
    return value if value is not None else "unknown"


def _prod_attrs(product: Product) -> dict[str, str]:
    attrs = {
        "vendor": product.vendor,
        "name": product.name,
        "version": product.version,
        "defver": product.defver,
        "engver": product.engver,
        "datemon": product.datemon,
        "dateday": product.dateday,
        "dateyear": product.dateyear,
        "prodType": product.prod_type,
        "osType": product.os_type,
    }
    return {key: value for key, value in attrs.items() if value is not None}


def _add_product_info(parent: ET.Element, product: Product) -> ET.Element:
    product_info = ET.SubElement(parent, "ProductInfo")
    ET.SubElement(product_info, "Prod", _prod_attrs(product))
    return product_info


def _add_list_product(category: ET.Element, product: Product) -> ET.Element:
    entries = category.find("list")
    if entries is None:
        entries = ET.SubElement(category, "list")
    entry = ET.SubElement(entries, "entry")
    return _add_product_info(entry, product)


def _interfaces(posture: HostInfo, invocation: HipInvocation) -> Tuple[NetworkInterface, ...]:
    def with_invocation_addresses(interface: NetworkInterface) -> NetworkInterface:
        ipv4_addresses = interface.ipv4_addresses or ((invocation.client_ip,) if invocation.client_ip else ())
        ipv6_addresses = interface.ipv6_addresses or ((invocation.client_ipv6,) if invocation.client_ipv6 else ())
        return NetworkInterface(
            name=interface.name,
            description=interface.description,
            mac_address=interface.mac_address,
            ipv4_addresses=ipv4_addresses,
            ipv6_addresses=ipv6_addresses,
        )

    if posture.interfaces:
        return tuple(with_invocation_addresses(interface) for interface in posture.interfaces)
    if posture.interface_name or posture.mac_address or invocation.client_ip or invocation.client_ipv6:
        return (NetworkInterface(
            name=posture.interface_name or "unknown",
            description=posture.interface_name,
            mac_address=posture.mac_address,
            ipv4_addresses=(invocation.client_ip,) if invocation.client_ip else (),
            ipv6_addresses=(invocation.client_ipv6,) if invocation.client_ipv6 else (),
        ),)
    return ()


def _add_address_entries(parent: ET.Element, tag: str, addresses: Tuple[str, ...]) -> None:
    if not addresses:
        return
    container = ET.SubElement(parent, tag)
    for address in addresses:
        ET.SubElement(container, "entry", {"name": address})


def _add_host_info(category: ET.Element, invocation: HipInvocation, identity: CookieIdentity, posture: HostInfo) -> None:
    _add_text(category, "client-version", posture.client_version or invocation.app_version)
    os_text = posture.os or (f"Apple Mac OS X {posture.os_version}" if posture.os_version else None)
    _add_text(category, "os", os_text)
    _add_text(category, "os-vendor", posture.os_vendor)
    _add_text(category, "domain", posture.domain if posture.domain is not None else identity.domain)
    _add_text(category, "host-name", posture.host_name or identity.computer)
    _add_text(category, "host-id", posture.host_id)
    network = ET.SubElement(category, "network-interface")
    for interface in _interfaces(posture, invocation):
        entry = ET.SubElement(network, "entry", {"name": interface.name})
        _add_text(entry, "description", interface.description)
        _add_text(entry, "mac-address", interface.mac_address)
        _add_address_entries(entry, "ip-address", interface.ipv4_addresses)
        _add_address_entries(entry, "ipv6-address", interface.ipv6_addresses)


def _add_anti_malware(category: ET.Element, products: Tuple[Product, ...]) -> None:
    ET.SubElement(category, "list")
    for product in products:
        product_info = _add_list_product(category, product)
        _add_text(product_info, "real-time-protection", _value_or_na(product.real_time_protection))
        _add_text(product_info, "last-full-scan-time", _value_or_na(product.last_full_scan_time))


def _add_disk_backup(category: ET.Element, products: Tuple[Product, ...]) -> None:
    ET.SubElement(category, "list")
    for product in products:
        product_info = _add_list_product(category, product)
        _add_text(product_info, "last-backup-time", _value_or_na(product.last_backup_time))


def _add_disk_encryption(category: ET.Element, drives: Tuple[Drive, ...]) -> None:
    product_version = drives[0].product_version if drives and drives[0].product_version else "n/a"
    product_info = _add_list_product(category, _apple_product("FileVault", version=product_version))
    drives_node = ET.SubElement(product_info, "drives")
    for drive in drives:
        entry = ET.SubElement(drives_node, "entry")
        _add_text(entry, "drive-name", drive.drive_name)
        _add_text(entry, "enc-state", _value_or_unknown(drive.enc_state))


def _add_firewall(category: ET.Element, products: Tuple[Product, ...]) -> None:
    ET.SubElement(category, "list")
    for product in products:
        product_info = _add_list_product(category, product)
        _add_text(product_info, "is-enabled", _value_or_na(product.is_enabled))


def _add_patch_management(category: ET.Element, product: Product, patches: Tuple[Patch, ...]) -> None:
    product_info = _add_list_product(category, product)
    _add_text(product_info, "is-enabled", _value_or_na(product.is_enabled))
    missing = ET.SubElement(category, "missing-patches")
    for patch in patches:
        entry = ET.SubElement(missing, "entry")
        _add_text(entry, "title", patch.title)
        _add_text(entry, "description", patch.description)
        _add_text(entry, "product", patch.product)
        _add_text(entry, "vendor", patch.vendor)
        _add_text(entry, "info-url", patch.info_url)
        _add_text(entry, "kb-article-id", patch.kb_article_id)
        _add_text(entry, "security-bulletin-id", patch.security_bulletin_id)
        _add_text(entry, "severity", patch.severity)
        _add_text(entry, "category", patch.category)
        _add_text(entry, "is-installed", _value_or_na(patch.is_installed))


def build_hip_xml(
    invocation: HipInvocation,
    identity: CookieIdentity,
    posture: MacPosture,
    generated_at: datetime,
) -> bytes:
    root = ET.Element("hip-report", {"name": "hip-report"})
    _add_text(root, "md5-sum", invocation.md5)
    _add_text(root, "user-name", identity.user)
    _add_text(root, "domain", identity.domain)
    _add_text(root, "host-name", identity.computer)
    _add_text(root, "host-id", posture.host_info.host_id)
    _add_text(root, "ip-address", invocation.client_ip)
    _add_text(root, "ipv6-address", invocation.client_ipv6)
    _add_text(root, "generate-time", generated_at.strftime("%m/%d/%Y %H:%M:%S"))
    _add_text(root, "hip-report-version", "4")

    categories = ET.SubElement(root, "categories")
    for name in _CATEGORY_ORDER:
        category = ET.SubElement(categories, "entry", {"name": name})
        if name == "host-info":
            _add_host_info(category, invocation, identity, posture.host_info)
        elif name == "anti-malware":
            _add_anti_malware(category, posture.anti_malware)
        elif name == "disk-backup":
            _add_disk_backup(category, posture.disk_backup)
        elif name == "disk-encryption":
            _add_disk_encryption(category, posture.disk_encryption)
        elif name == "firewall":
            _add_firewall(category, posture.firewall)
        elif name == "patch-management":
            _add_patch_management(category, posture.patch_management_product, posture.patches)
        elif name == "data-loss-prevention":
            ET.SubElement(category, "list")

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
