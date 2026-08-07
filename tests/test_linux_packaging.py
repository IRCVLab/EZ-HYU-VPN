from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LinuxPackagingTests(unittest.TestCase):
    def test_service_is_hardened_but_keeps_required_tunnel_access(self):
        unit = (ROOT / "packaging/linux/hyu-vpn.service").read_text()
        for required in (
            "NoNewPrivileges=yes",
            "ProtectSystem=full",
            "ProtectHome=yes",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
            "CapabilityBoundingSet=CAP_NET_ADMIN",
            "DeviceAllow=/dev/net/tun rw",
            "Restart=on-failure",
            "RuntimeDirectoryMode=0750",
            "StateDirectoryMode=0700",
        ):
            self.assertIn(required, unit)
        self.assertNotIn("Environment=", unit)

    def test_package_declares_runtime_dependencies_and_graphical_entry(self):
        control = (ROOT / "packaging/linux/debian/control").read_text()
        for dependency in (
            "vpnc-scripts",
            "libgnutls30",
            "libxml2",
            "libgtk-4-1",
            "dbus-user-session",
        ):
            self.assertIn(dependency, control)
        desktop = (ROOT / "packaging/linux/hyu-vpn.desktop").read_text()
        self.assertIn("Exec=/usr/bin/hyu-vpn", desktop)
        self.assertIn("Terminal=false", desktop)

    def test_maintainer_scripts_are_idempotent_and_purge_only_owned_state(self):
        postinst = (ROOT / "packaging/linux/debian/postinst").read_text()
        self.assertIn("/etc/hyu-vpn/owner.uid", postinst)
        self.assertIn("chmod 0644", postinst)
        self.assertIn("systemctl restart hyu-vpn.service || true", postinst)
        postrm = (ROOT / "packaging/linux/debian/postrm").read_text()
        self.assertIn('if [ "${1:-}" = purge ]', postrm)
        self.assertNotIn("/home/", postrm)

    def test_vpnc_wrapper_integrates_systemd_resolved_without_logging_dns_or_secrets(self):
        wrapper = (ROOT / "packaging/linux/hyu-vpnc-script").read_text()
        self.assertIn("/usr/share/vpnc-scripts/vpnc-script", wrapper)
        self.assertIn('"$RESOLVECTL" dns "$TUNDEV"', wrapper)
        self.assertIn(
            '"$RESOLVECTL" domain "$TUNDEV" \'~hanyang.ac.kr\' \'~hyu.ac.kr\'',
            wrapper,
        )
        self.assertIn('"$RESOLVECTL" default-route "$TUNDEV" no', wrapper)
        self.assertIn(
            '/usr/bin/timeout 4 "$RESOLVECTL" query '
            '--interface="$TUNDEV" secure.hanyang.ac.kr',
            wrapper,
        )
        self.assertNotIn('"$RESOLVECTL" domain "$TUNDEV" \'~.\'', wrapper)
        self.assertIn('suffix="${TUNDEV#tun}"', wrapper)
        self.assertIn("''|*[!0-9]*) return 1", wrapper)
        self.assertIn("nameserver 127.0.0.53", wrapper)
        self.assertNotIn("set -x", wrapper)
        self.assertNotIn("echo $INTERNAL_IP4_DNS", wrapper)

    def test_openconnect_download_is_bounded_and_cached_atomically(self):
        script = (ROOT / "scripts/build-openconnect-linux.sh").read_text()
        self.assertIn("--connect-timeout 15", script)
        self.assertIn("--max-time 180", script)
        self.assertIn('mktemp "$ARCHIVE.partial.XXXXXX"', script)
        self.assertIn('mv -- "$partial" "$ARCHIVE"', script)

    def test_packaging_sources_contain_no_credential_fields_or_values(self):
        combined = "\n".join(
            path.read_text(errors="replace")
            for path in (ROOT / "packaging/linux").rglob("*")
            if path.is_file()
        )
        for forbidden in (
            "PASSWORD-CANARY",
            "SEED-CANARY",
            "credentials.enc",
            "credentials.key",
        ):
            self.assertNotIn(forbidden, combined)

    def test_built_deb_has_expected_root_owned_layout_when_requested(self):
        raw = os.environ.get("HYU_VPN_DEB")
        if not raw:
            self.skipTest("set HYU_VPN_DEB for artifact inspection")
        deb = Path(raw)
        self.assertTrue(deb.is_file())
        contents = subprocess.check_output(
            ["dpkg-deb", "--contents", str(deb)], text=True
        )
        for path in (
            "./usr/bin/hyu-vpn",
            "./usr/lib/hyu-vpn/hyu-vpn-service",
            "./usr/lib/hyu-vpn/hyu-vpn-hip",
            "./usr/lib/hyu-vpn/hyu-vpnc-script",
            "./usr/lib/hyu-vpn/runtime/openconnect",
            "./usr/lib/hyu-vpn/runtime/lib/libopenconnect.so.5",
            "./usr/lib/systemd/system/hyu-vpn.service",
            "./usr/share/applications/hyu-vpn.desktop",
        ):
            self.assertIn(path, contents)
        for line in contents.splitlines():
            self.assertRegex(line, r"^[-dl][rwxstST-]{9} root/root ")


if __name__ == "__main__":
    unittest.main()
