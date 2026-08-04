import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hyu_vpn.hip_contract import CookieIdentity, HipInvocation, HipInvocationError


class HipInvocationArgumentTests(unittest.TestCase):
    def test_client_os_and_app_version_are_captured_from_openconnect_context(self):
        invocation = HipInvocation.from_argv([
            "--cookie", "COOKIE-VALUE",
            "--md5", "0123456789abcdef0123456789abcdef",
            "--client-ip", "192.0.2.10",
            "--client-os", "mac",
        ], {"APP_VERSION": "OpenConnect 9.21"})

        self.assertEqual(invocation.client_os, "mac")
        self.assertEqual(invocation.app_version, "OpenConnect 9.21")

    def test_cookie_md5_and_at_least_one_client_address_are_required(self):
        base_argv = [
            "--cookie", "COOKIE-VALUE",
            "--md5", "0123456789abcdef0123456789abcdef",
            "--client-ip", "192.0.2.10",
        ]

        invocation = HipInvocation.from_argv(base_argv, {})
        self.assertEqual(invocation.cookie, "COOKIE-VALUE")
        self.assertEqual(invocation.md5, "0123456789abcdef0123456789abcdef")
        self.assertEqual(invocation.client_ip, "192.0.2.10")
        self.assertIsNone(invocation.client_ipv6)

        ipv6_only = HipInvocation.from_argv([
            "--cookie", "COOKIE-VALUE",
            "--md5", "0123456789abcdef0123456789abcdef",
            "--client-ipv6", "2001:db8::10",
        ], {})
        self.assertIsNone(ipv6_only.client_ip)
        self.assertEqual(ipv6_only.client_ipv6, "2001:db8::10")

        required_cases = [
            (["--md5", "m", "--client-ip", "192.0.2.10"], "--cookie"),
            (["--cookie", "c", "--client-ip", "192.0.2.10"], "--md5"),
            (["--cookie", "c", "--md5", "m"], "--client-ip or --client-ipv6"),
        ]
        for argv, missing_name in required_cases:
            with self.subTest(missing=missing_name):
                with self.assertRaisesRegex(HipInvocationError, missing_name):
                    HipInvocation.from_argv(argv, {})


class CookieIdentityTests(unittest.TestCase):
    def test_decodes_reordered_cookie_identity_fields_and_preserves_blank_domain(self):
        identity = CookieIdentity.from_encoded(
            "computer=TEST+HOST&domain=&user=TEST%2DUSER"
        )

        self.assertEqual(identity.user, "TEST-USER")
        self.assertEqual(identity.domain, "")
        self.assertEqual(identity.computer, "TEST HOST")

    def test_absent_optional_cookie_identity_values_are_none(self):
        identity = CookieIdentity.from_encoded("user=TEST%2DUSER")

        self.assertEqual(identity.user, "TEST-USER")
        self.assertIsNone(identity.domain)
        self.assertIsNone(identity.computer)


class NativeHipFixtureTests(unittest.TestCase):
    def test_sanitized_native_fixture_preserves_category_order_and_test_identifiers(self):
        fixture = Path(__file__).resolve().parent / "fixtures" / "native_hip_sanitized.xml"
        root = ET.parse(fixture).getroot()

        categories = [category.attrib["name"] for category in root.findall("./categories/category")]
        self.assertEqual(categories, [
            "host-info",
            "anti-malware",
            "disk-backup",
            "disk-encryption",
            "firewall",
            "patch-management",
            "data-loss-prevention",
        ])

        xml_text = fixture.read_text(encoding="utf-8")
        self.assertIn("TEST-USER", xml_text)
        self.assertIn("TEST-HOST", xml_text)
        self.assertIn("00:00:00:00:00:00", xml_text)
        self.assertIn("192.0.2.10", xml_text)
        self.assertIn("2001:db8::10", xml_text)


if __name__ == "__main__":
    unittest.main()
