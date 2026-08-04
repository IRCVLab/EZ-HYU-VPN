import sys
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.hip_contract import CookieIdentity, HipInvocation
from hyu_vpn.hip_xml import Drive, HostInfo, MacPosture, Patch, Product, build_hip_xml


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "native_hip_sanitized.xml"
GENERATED_AT = datetime(2026, 8, 4, 1, 2, 3, tzinfo=timezone.utc)


class HipXmlTests(unittest.TestCase):
    def test_builds_required_header_and_category_order(self):
        invocation = HipInvocation(
            cookie="COOKIE",
            client_ip="192.0.2.55",
            client_ipv6="2001:db8::55",
            md5="abcdef0123456789abcdef0123456789",
            client_os="mac",
        )
        identity = CookieIdentity(user="alice", domain="HYU", computer="alice-mac")
        posture = MacPosture(
            host_info=HostInfo(
                host_name="alice-mac",
                user_name="alice",
                os="macOS",
                os_version="14.5",
            )
        )

        xml_bytes = build_hip_xml(invocation, identity, posture, GENERATED_AT)

        root = ET.fromstring(xml_bytes)
        self.assertEqual(root.tag, "hip-report")
        self.assertEqual(root.findtext("report-version"), "4")
        self.assertEqual(root.findtext("md5-sum"), "abcdef0123456789abcdef0123456789")
        self.assertEqual(root.findtext("user"), "alice")
        self.assertEqual(root.findtext("domain"), "HYU")
        self.assertEqual(root.findtext("computer"), "alice-mac")
        self.assertEqual(root.findtext("client-ip"), "192.0.2.55")
        self.assertEqual(root.findtext("client-ipv6"), "2001:db8::55")
        self.assertEqual(root.findtext("generated-at"), "2026-08-04T01:02:03+00:00")
        self.assertEqual(
            [category.attrib["name"] for category in root.findall("./categories/category")],
            [
                "host-info",
                "anti-malware",
                "disk-backup",
                "disk-encryption",
                "firewall",
                "patch-management",
                "data-loss-prevention",
            ],
        )

    def test_matches_native_fixture_schema_after_normalizing_dynamic_values(self):
        generated = ET.fromstring(build_hip_xml(
            HipInvocation(
                cookie="COOKIE",
                client_ip="198.51.100.42",
                client_ipv6="2001:db8::42",
                md5="feedfacefeedfacefeedfacefeedface",
                client_os="mac",
            ),
            CookieIdentity(user="real-user", domain="", computer="real-host"),
            MacPosture(
                host_info=HostInfo(
                    host_name="real-host",
                    user_name="real-user",
                    os="macOS TEST",
                    os_version="14.0",
                    interface_name="en0",
                    mac_address="00:00:00:00:00:00",
                ),
                anti_malware=(Product(
                    name="XProtect",
                    version="TEST-XPROTECT",
                    definition_date="2000-01-01",
                    real_time_protection=None,
                ),),
                disk_backup=(Product(name="Time Machine", state=None),),
                disk_encryption=(Drive(name="FileVault", encrypted=None),),
                firewall=(
                    Product(name="Application Firewall", enabled=None),
                    Product(name="Packet Filter", enabled=None),
                ),
                patches=(Patch(id="TEST-UPDATE-001", severity=None),),
                data_loss_prevention=(Product(name="Gatekeeper", enabled=None),),
            ),
            GENERATED_AT,
        ))
        native = ET.parse(FIXTURE).getroot()

        self._normalize_dynamic_values(generated)
        self.assertEqual(ET.tostring(generated, encoding="unicode"), ET.tostring(native, encoding="unicode"))

    def test_escapes_xml_text_without_changing_posture_values(self):
        dangerous = "Ampersand & less < greater > quote \" apostrophe ' 한글 $(rm -rf /)"
        xml_bytes = build_hip_xml(
            HipInvocation(
                cookie="COOKIE",
                client_ip="192.0.2.10",
                client_ipv6="2001:db8::10",
                md5="0123456789abcdef0123456789abcdef",
            ),
            CookieIdentity(user=dangerous, domain="HYU & <DOMAIN>", computer="mac > host"),
            MacPosture(
                host_info=HostInfo(host_name=dangerous, user_name=dangerous, os="macOS & <15>", os_version="14.0"),
                anti_malware=(Product(name=dangerous, version="v&<1>", definition_date="2000-01-01", real_time_protection="unknown"),),
            ),
            GENERATED_AT,
        )

        raw_xml = xml_bytes.decode("utf-8")
        self.assertIn("Ampersand &amp; less &lt; greater &gt; quote", raw_xml)
        self.assertIn("HYU &amp; &lt;DOMAIN&gt;", raw_xml)
        root = ET.fromstring(xml_bytes)
        self.assertEqual(root.findtext("user"), dangerous)
        self.assertEqual(root.findtext("./categories/category[@name='host-info']/host-name"), dangerous)
        self.assertEqual(root.findtext("./categories/category[@name='anti-malware']/product/name"), dangerous)

    def test_unknown_posture_is_never_reported_as_enabled_or_encrypted(self):
        xml_bytes = build_hip_xml(
            HipInvocation(
                cookie="COOKIE",
                client_ip="192.0.2.10",
                client_ipv6=None,
                md5="0123456789abcdef0123456789abcdef",
            ),
            CookieIdentity(user="alice"),
            MacPosture(),
            GENERATED_AT,
        )

        root = ET.fromstring(xml_bytes)
        self.assertEqual(root.findtext("./categories/category[@name='disk-encryption']/product/name"), "FileVault")
        self.assertEqual(root.findtext("./categories/category[@name='disk-encryption']/product/encrypted"), "unknown")
        self.assertEqual(root.findtext("./categories/category[@name='firewall']/product/name"), "Application Firewall")
        self.assertEqual(root.findtext("./categories/category[@name='firewall']/product/enabled"), "unknown")
        self.assertNotIn("<enabled>yes</enabled>", xml_bytes.decode("utf-8"))
        self.assertNotIn("<encrypted>encrypted</encrypted>", xml_bytes.decode("utf-8"))

    def _normalize_dynamic_values(self, root):
        for path, value in {
            "md5-sum": "00000000000000000000000000000000",
            "user": "TEST-USER",
            "computer": "TEST-HOST",
            "client-ip": "192.0.2.10",
            "client-ipv6": "2001:db8::10",
            "./categories/category[@name='host-info']/host-name": "TEST-HOST",
            "./categories/category[@name='host-info']/user-name": "TEST-USER",
            "./categories/category[@name='host-info']/network-interfaces/interface/ipv4": "192.0.2.10",
            "./categories/category[@name='host-info']/network-interfaces/interface/ipv6": "2001:db8::10",
        }.items():
            element = root.find(path)
            self.assertIsNotNone(element, path)
            element.text = value
        generated_at = root.find("generated-at")
        if generated_at is not None:
            root.remove(generated_at)


if __name__ == "__main__":
    unittest.main()
