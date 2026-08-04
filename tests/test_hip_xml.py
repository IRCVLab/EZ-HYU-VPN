import sys
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.hip_contract import CookieIdentity, HipInvocation
from hyu_vpn.hip_xml import (
    Drive,
    HostInfo,
    MacPosture,
    NetworkInterface,
    Patch,
    Product,
    build_hip_xml,
)


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "native_hip_sanitized.xml"
GENERATED_AT = datetime(2026, 8, 4, 1, 2, 3, tzinfo=timezone.utc)
CATEGORY_ORDER = [
    "host-info",
    "anti-malware",
    "disk-backup",
    "disk-encryption",
    "firewall",
    "patch-management",
    "data-loss-prevention",
]


def sample_invocation():
    return HipInvocation(
        cookie="COOKIE",
        client_ip="192.0.2.10",
        client_ipv6="2001:db8::10",
        md5="00000000000000000000000000000000",
        client_os="mac",
        app_version="OpenConnect TEST",
    )


def sample_identity():
    return CookieIdentity(user="TEST-USER", domain="", computer="TEST-HOST")


def sample_posture():
    return MacPosture(
        host_info=HostInfo(
            host_name="TEST-HOST",
            user_name="TEST-USER",
            os="Apple Mac OS X 14.0",
            os_version="14.0",
            client_version="OpenConnect TEST",
            os_vendor="Apple",
            domain="",
            host_id="TEST-HOST-ID",
            interfaces=(NetworkInterface(
                name="en0",
                description="Wi-Fi",
                mac_address="00:00:00:00:00:00",
                ipv4_addresses=("192.0.2.10",),
                ipv6_addresses=("2001:db8::10",),
            ),),
        ),
        anti_malware=(
            Product(
                vendor="Apple Inc.",
                name="Xprotect",
                version="TEST-XPROTECT",
                defver="TEST-DEFVER",
                engver="",
                datemon="08",
                dateday="01",
                dateyear="2026",
                prod_type="3",
                os_type="4",
                real_time_protection="yes",
                last_full_scan_time="n/a",
            ),
            Product(
                vendor="Apple Inc.",
                name="Gatekeeper",
                version="TEST-GATEKEEPER",
                defver="",
                engver="",
                datemon="08",
                dateday="01",
                dateyear="2026",
                prod_type="3",
                os_type="4",
                real_time_protection="yes",
                last_full_scan_time="n/a",
            ),
        ),
        disk_backup=(Product(vendor="Apple Inc.", name="Time Machine", version="TEST-TM", last_backup_time="n/a"),),
        disk_encryption=(Drive(drive_name="All", enc_state="encrypted"),),
        firewall=(
            Product(vendor="Apple Inc.", name="Mac OS X Builtin Firewall", version="TEST-FW", is_enabled="yes"),
            Product(vendor="OpenBSD", name="Packet Filter", version="TEST-PF", is_enabled="no"),
        ),
        patch_management_product=Product(vendor="Apple Inc.", name="Software Update", version="3.0", is_enabled="yes"),
        patches=(Patch(
            title="TEST-UPDATE-001",
            description="TEST-UPDATE-001",
            product="macOS",
            vendor="Apple Inc.",
            severity="2",
            category="update",
            is_installed="no",
        ),),
    )


class HipXmlTests(unittest.TestCase):
    def test_matches_sanitized_native_shape_fixture_without_alias_normalization(self):
        generated = ET.fromstring(build_hip_xml(sample_invocation(), sample_identity(), sample_posture(), GENERATED_AT))
        native = ET.parse(FIXTURE).getroot()

        self.assertEqual(ET.tostring(generated, encoding="unicode"), ET.tostring(native, encoding="unicode"))

    def test_uses_native_entry_productinfo_schema_and_rejects_simplified_paths(self):
        root = ET.fromstring(build_hip_xml(sample_invocation(), sample_identity(), sample_posture(), GENERATED_AT))

        self.assertEqual(root.tag, "hip-report")
        self.assertEqual(root.attrib, {"name": "hip-report"})
        self.assertEqual([child.tag for child in root], [
            "md5-sum", "user-name", "domain", "host-name", "host-id",
            "ip-address", "ipv6-address", "generate-time", "hip-report-version", "categories",
        ])
        self.assertEqual(root.findtext("generate-time"), "08/04/2026 01:02:03")
        self.assertEqual([entry.attrib["name"] for entry in root.findall("./categories/entry")], CATEGORY_ORDER)
        self.assertIsNotNone(root.find("./categories/entry[@name='anti-malware']/list/entry/ProductInfo/Prod"))
        self.assertIsNone(root.find("./categories/category"))
        self.assertIsNone(root.find(".//network-interfaces/interface"))
        self.assertIsNone(root.find(".//product/name"))
        self.assertIsNone(root.find(".//enabled"))
        self.assertIsNone(root.find(".//encrypted"))
        self.assertIsNone(root.find(".//definition-date"))
        self.assertIsNone(root.find(".//missing-patches//id"))

    def test_category_specific_native_structures_and_state_encodings(self):
        root = ET.fromstring(build_hip_xml(sample_invocation(), sample_identity(), sample_posture(), GENERATED_AT))

        interface = root.find("./categories/entry[@name='host-info']/network-interface/entry")
        self.assertEqual(interface.attrib, {"name": "en0"})
        self.assertEqual(interface.findtext("mac-address"), "00-00-00-00-00-00")
        self.assertEqual(interface.find("./ip-address/entry").attrib, {"name": "192.0.2.10"})
        self.assertEqual(interface.find("./ipv6-address/entry").attrib, {"name": "2001:db8::10"})

        am_products = root.findall("./categories/entry[@name='anti-malware']/list/entry/ProductInfo")
        self.assertEqual([node.find("Prod").attrib["name"] for node in am_products], ["Xprotect", "Gatekeeper"])
        self.assertEqual([node.findtext("real-time-protection") for node in am_products], ["yes", "yes"])
        self.assertEqual([node.findtext("last-full-scan-time") for node in am_products], ["n/a", "n/a"])

        self.assertEqual(root.findtext("./categories/entry[@name='disk-backup']/list/entry/ProductInfo/last-backup-time"), "n/a")
        self.assertEqual(root.findtext("./categories/entry[@name='disk-encryption']/list/entry/ProductInfo/drives/entry/enc-state"), "encrypted")
        self.assertEqual(
            [node.text for node in root.findall("./categories/entry[@name='firewall']/list/entry/ProductInfo/is-enabled")],
            ["yes", "no"],
        )
        patch_category = root.find("./categories/entry[@name='patch-management']")
        self.assertIsNotNone(patch_category.find("list/entry/ProductInfo/Prod"))
        self.assertEqual(patch_category.findtext("list/entry/ProductInfo/is-enabled"), "yes")
        self.assertEqual(patch_category.findtext("missing-patches/entry/is-installed"), "no")
        self.assertEqual(patch_category.findtext("missing-patches/entry/severity"), "2")
        self.assertEqual(root.find("./categories/entry[@name='data-loss-prevention']/list").text, None)
        self.assertEqual(root.findall("./categories/entry[@name='data-loss-prevention']/list/*"), [])
        self.assertEqual(root.findall(".//Prod[@name='Gatekeeper']"), [am_products[1].find("Prod")])

    def test_escapes_xml_text_and_attributes_without_changing_values(self):
        dangerous = "Ampersand & less < greater > quote \" apostrophe ' 한글 $(rm -rf /)"
        xml_bytes = build_hip_xml(
            HipInvocation(cookie="COOKIE", client_ip="192.0.2.10", client_ipv6="2001:db8::10", md5="0123456789abcdef0123456789abcdef"),
            CookieIdentity(user=dangerous, domain="HYU & <DOMAIN>", computer="mac > host"),
            MacPosture(
                host_info=HostInfo(host_name=dangerous, os="Apple Mac OS X & <15>", interfaces=(NetworkInterface(name="en&0", description=dangerous, mac_address="00:00:00:00:00:00"),)),
                anti_malware=(Product(vendor="Apple & Inc.", name=dangerous, version="v&<1>", real_time_protection="n/a", last_full_scan_time="n/a"),),
            ),
            GENERATED_AT,
        )

        raw_xml = xml_bytes.decode("utf-8")
        self.assertIn("Ampersand &amp; less &lt; greater &gt; quote", raw_xml)
        self.assertIn("vendor=\"Apple &amp; Inc.\"", raw_xml)
        root = ET.fromstring(xml_bytes)
        self.assertEqual(root.findtext("user-name"), dangerous)
        self.assertEqual(root.findtext("./categories/entry[@name='host-info']/host-name"), dangerous)
        self.assertEqual(root.find("./categories/entry[@name='anti-malware']/list/entry/ProductInfo/Prod").attrib["name"], dangerous)

    def test_unknown_local_states_use_native_non_optimistic_values(self):
        root = ET.fromstring(build_hip_xml(sample_invocation(), sample_identity(), MacPosture(), GENERATED_AT))

        self.assertEqual(root.findtext("./categories/entry[@name='anti-malware']/list/entry/ProductInfo/real-time-protection"), "n/a")
        self.assertEqual(root.findtext("./categories/entry[@name='disk-encryption']/list/entry/ProductInfo/drives/entry/enc-state"), "unknown")
        self.assertEqual(root.findtext("./categories/entry[@name='firewall']/list/entry/ProductInfo/is-enabled"), "n/a")
        self.assertEqual(root.findtext("./categories/entry[@name='patch-management']/list/entry/ProductInfo/is-enabled"), "n/a")
        self.assertNotIn("<is-enabled>yes</is-enabled>", ET.tostring(root, encoding="unicode"))
        self.assertNotIn("<enc-state>encrypted</enc-state>", ET.tostring(root, encoding="unicode"))


if __name__ == "__main__":
    unittest.main()
