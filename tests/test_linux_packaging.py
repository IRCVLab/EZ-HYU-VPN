from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
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
            "DeviceAllow=/dev/net/tun rw",
            "Restart=on-failure",
            "StartLimitIntervalSec=60s",
            "StartLimitBurst=3",
            "TimeoutStopSec=30s",
            "CapabilityBoundingSet=CAP_CHOWN CAP_NET_ADMIN CAP_NET_RAW",
            "AmbientCapabilities=CAP_CHOWN CAP_NET_ADMIN CAP_NET_RAW",
            "RuntimeDirectoryMode=0750",
            "StateDirectoryMode=0700",
        ):
            self.assertIn(required, unit)
        self.assertNotIn("Environment=", unit)
        for excessive in ("CAP_DAC_OVERRIDE", "CAP_FOWNER"):
            self.assertNotIn(excessive, unit)

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

    def test_vpnc_wrapper_preserves_established_ssh_reply_routes_before_split_routes(self):
        wrapper = (ROOT / "packaging/linux/hyu-vpnc-script").read_text()
        self.assertIn("preserve_established_ssh_routes", wrapper)
        self.assertIn("cleanup_established_ssh_routes", wrapper)
        self.assertIn('"$SS" -H -4 -n -t state established', wrapper)
        self.assertIn("sport = :22", wrapper)
        self.assertIn('"$IP" -4 route add "$peer/32"', wrapper)
        self.assertIn('"$IP" -4 route del "$peer/32"', wrapper)
        self.assertIn("valid_ipv4", wrapper)
        self.assertIn("umask 077", wrapper)
        preserve = wrapper.index("preserve_established_ssh_routes")
        upstream = wrapper.index('"$UPSTREAM" "$@"')
        self.assertLess(preserve, upstream)

    def _run_vpnc_wrapper_route_guard(
        self, *, portal_ip, ssh_line, upstream_exit, reasons
    ):
        source = (ROOT / "packaging/linux/hyu-vpnc-script").read_text()
        with tempfile.TemporaryDirectory() as raw:
            temp = Path(raw)
            log = temp / "calls.log"
            state = temp / "established-ssh-routes"
            fake_ip = temp / "ip"
            fake_ss = temp / "ss"
            fake_getent = temp / "getent"
            upstream = temp / "upstream"
            fake_ip.write_text(
                "#!/bin/sh\n"
                "case \"${3:-}\" in\n"
                "  show) exit 0 ;;\n"
                "  get) printf '%s\\n' \"$4 via 192.168.0.1 dev eth0 src 192.168.0.10\" ;;\n"
                "  add) printf 'add %s\\n' \"$*\" >> \"$HYU_TEST_LOG\" ;;\n"
                "  del) printf 'del %s\\n' \"$*\" >> \"$HYU_TEST_LOG\" ;;\n"
                "  *) exit 64 ;;\n"
                "esac\n"
            )
            fake_ss.write_text(
                "#!/bin/sh\n"
                + (f"printf '%s\\n' '{ssh_line}'\n" if ssh_line else "exit 0\n")
            )
            fake_getent.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' '{portal_ip} STREAM portal.hanyang.ac.kr'\n"
            )
            upstream.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' upstream >> \"$HYU_TEST_LOG\"\n"
                "exit \"$HYU_UPSTREAM_EXIT\"\n"
            )
            for executable in (fake_ip, fake_ss, fake_getent, upstream):
                executable.chmod(0o700)
            script = source
            for tool in ("awk", "cat", "chmod", "chown", "grep", "install", "mktemp", "mv", "printf", "readlink", "rm", "sort", "timeout"):
                located = shutil.which(tool)
                if located is not None:
                    script = script.replace(f"/usr/bin/{tool}", located)
            script = script.replace(
                "UPSTREAM=/usr/share/vpnc-scripts/vpnc-script", f"UPSTREAM={upstream}"
            )
            script = script.replace("IP=/usr/sbin/ip", f"IP={fake_ip}")
            script = script.replace("SS=/usr/bin/ss", f"SS={fake_ss}")
            script = script.replace("GETENT=/usr/bin/getent", f"GETENT={fake_getent}")
            script = script.replace(
                "RESOLVECTL=/usr/bin/resolvectl", f"RESOLVECTL={temp / 'resolvectl'}"
            )
            script = script.replace("/etc/resolv.conf", str(temp / "resolv.conf"))
            script = script.replace(
                "SSH_ROUTE_STATE=/run/hyu-vpn/established-ssh-routes",
                f"SSH_ROUTE_STATE={state}",
            )
            wrapper = temp / "wrapper"
            wrapper.write_text(script)
            wrapper.chmod(0o700)
            env = os.environ.copy()
            env.update(
                {
                    "HYU_TEST_LOG": str(log),
                    "HYU_UPSTREAM_EXIT": str(upstream_exit),
                    "TUNDEV": "tun0",
                }
            )
            snapshots = []
            for reason in reasons:
                env["reason"] = reason
                completed = subprocess.run(
                    [str(wrapper)], env=env, text=True, capture_output=True, check=False
                )
                snapshots.append(
                    (
                        completed,
                        log.read_text().splitlines(),
                        state.read_text() if state.exists() else None,
                    )
                )
            return snapshots

    def test_vpnc_wrapper_route_guard_orders_add_upstream_cleanup_on_failure(self):
        snapshots = self._run_vpnc_wrapper_route_guard(
            portal_ip="166.104.177.170",
            ssh_line="tcp 0 0 192.168.0.10:22 166.104.168.168:57477",
            upstream_exit=23,
            reasons=("connect",),
        )
        completed, calls, state_text = snapshots[0]
        self.assertEqual(completed.returncode, 23, completed.stderr)
        self.assertEqual(
            calls,
            [
                "add -4 route add 166.104.168.168/32 via 192.168.0.1 dev eth0 proto 186 metric 42760",
                "add -4 route add 166.104.177.170/32 via 192.168.0.1 dev eth0 proto 186 metric 42760",
                "upstream",
                "del -4 route del 166.104.168.168/32 via 192.168.0.1 dev eth0 proto 186 metric 42760",
                "del -4 route del 166.104.177.170/32 via 192.168.0.1 dev eth0 proto 186 metric 42760",
            ],
        )
        self.assertIsNone(state_text)

    def test_vpnc_wrapper_rejects_portal_route_outside_hanyang_network(self):
        snapshots = self._run_vpnc_wrapper_route_guard(
            portal_ip="203.0.113.10",
            ssh_line="",
            upstream_exit=23,
            reasons=("connect",),
        )
        completed, calls, state_text = snapshots[0]
        self.assertEqual(completed.returncode, 23, completed.stderr)
        self.assertEqual(calls, ["upstream"])
        self.assertIsNone(state_text)

    def test_vpnc_wrapper_removes_portal_route_on_disconnect(self):
        snapshots = self._run_vpnc_wrapper_route_guard(
            portal_ip="166.104.177.170",
            ssh_line="",
            upstream_exit=0,
            reasons=("connect", "disconnect"),
        )
        connected, connected_calls, connected_state = snapshots[0]
        self.assertEqual(connected.returncode, 0, connected.stderr)
        self.assertEqual(
            connected_calls,
            [
                "add -4 route add 166.104.177.170/32 via 192.168.0.1 dev eth0 proto 186 metric 42760",
                "upstream",
            ],
        )
        self.assertEqual(connected_state, "166.104.177.170 192.168.0.1 eth0\n")

        disconnected, disconnected_calls, disconnected_state = snapshots[1]
        self.assertEqual(disconnected.returncode, 0, disconnected.stderr)
        self.assertEqual(
            disconnected_calls,
            [
                "add -4 route add 166.104.177.170/32 via 192.168.0.1 dev eth0 proto 186 metric 42760",
                "upstream",
                "upstream",
                "del -4 route del 166.104.177.170/32 via 192.168.0.1 dev eth0 proto 186 metric 42760",
            ],
        )
        self.assertIsNone(disconnected_state)

    def test_vpnc_wrapper_flushes_owned_routes_even_when_runtime_state_was_lost(self):
        source = (ROOT / "packaging/linux/hyu-vpnc-script").read_text()
        self.assertIn('route flush proto "$SSH_ROUTE_PROTOCOL" metric "$SSH_ROUTE_METRIC"', source)

    def test_linux_portal_probe_is_bound_to_observed_physical_interface_and_monitor_errors_back_off(self):
        network = (ROOT / "rust/crates/hyu-vpn-platform-linux/src/network.rs").read_text()
        service = (ROOT / "rust/apps/hyu-vpn-linux-service/src/lib.rs").read_text()
        self.assertIn("bind_device(Some(identity.interface.as_bytes()))", network)
        self.assertIn("tokio::time::sleep(error_delay)", service)
        self.assertNotIn("current_identity().await.ok().flatten()", service)

    def test_deb_checksum_is_lf_terminated_and_uses_only_the_artifact_basename(self):
        script = (ROOT / "scripts/package-linux.sh").read_text()
        self.assertIn('cd "$OUT"', script)
        self.assertIn('sha256sum "$(basename "$DEB")"', script)
        self.assertNotIn('sha256sum "$DEB" >', script)
        workflow = (ROOT / ".github/workflows/ubuntu.yml").read_text()
        self.assertIn(
            '(cd "$(dirname "$deb")" && sha256sum -c "$(basename "$deb").sha256")',
            workflow,
        )

    def test_openconnect_download_is_bounded_and_cached_atomically(self):
        script = (ROOT / "scripts/build-openconnect-linux.sh").read_text()
        self.assertIn("--connect-timeout 15", script)
        self.assertIn("--max-time 180", script)
        self.assertIn('mktemp "$ARCHIVE.partial.XXXXXX"', script)
        self.assertIn('mv -- "$partial" "$ARCHIVE"', script)

    def test_openconnect_download_has_verified_github_mirror_fallback(self):
        script = (ROOT / "scripts/build-openconnect-linux.sh").read_text()
        primary = (
            "https://www.infradead.org/openconnect/download/"
            "openconnect-$VERSION.tar.gz"
        )
        mirror = (
            "https://github.com/IRCVLab/EZ-HYU-VPN/releases/download/"
            "v0.1.1/openconnect-$VERSION.tar.gz"
        )
        self.assertIn("SOURCE_URLS=(", script)
        self.assertIn(primary, script)
        self.assertIn(mirror, script)
        self.assertLess(script.index(primary), script.index(mirror))
        self.assertIn('for source_url in "${SOURCE_URLS[@]}"; do', script)
        self.assertIn('"$source_url"', script)

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
