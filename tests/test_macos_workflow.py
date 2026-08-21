import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from typing import Optional
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "macos.yml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
PACKAGE = ROOT / "scripts" / "package-macos.sh"
DMG_ACCEPTANCE = ROOT / "scripts" / "macos-dmg-acceptance.sh"
README = ROOT / "README.md"


class MacOSWorkflowTests(unittest.TestCase):
    def test_macos_ci_tests_builds_and_verifies_arm64_dmg(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("runs-on: macos-26", text)
        self.assertNotIn("runs-on: macos-15", text)
        self.assertIn('test "$(sw_vers -productVersion | cut -d. -f1)" = 26', text)
        self.assertIn("swift test", text)
        self.assertIn("hyu-vpn-helper-test-harness", text)
        self.assertIn("hyu-vpn-menu-harness", text)
        self.assertIn("hyu-vpn-installer-harness", text)
        self.assertIn("test-wrapperd-closed-stderr.sh", text)
        self.assertIn("python3 -m unittest discover -s tests -v", text)
        self.assertNotIn("python3 -m unittest discover -v", text)
        self.assertIn("ce053a9353d6c909e1475b01fa88acafbfaef5181e1cdcfa8e271e7696b2284b", text)
        self.assertIn("scripts/package-macos.sh", text)
        self.assertIn("hdiutil verify", text)
        self.assertIn("codesign --verify --deep --strict", text)
        self.assertIn("actions/upload-artifact@v4", text)

    def test_swift_ci_commands_have_independent_bounded_steps(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        expected = {
            "Swift package tests": "swift test --package-path macos --no-parallel </dev/null",
            "Privileged helper harness": "swift run --package-path macos hyu-vpn-helper-test-harness </dev/null",
            "Menu harness": "swift run --package-path macos hyu-vpn-menu-harness </dev/null",
            "Installer harness": "swift run --package-path macos hyu-vpn-installer-harness </dev/null",
            "Wrapper daemon harness": "macos/Scripts/test-wrapperd-closed-stderr.sh </dev/null",
        }
        self.assertNotIn("- name: Swift tests", text)
        for name, command in expected.items():
            block = f"- name: {name}\n        timeout-minutes: 10\n        run: {command}"
            self.assertIn(block, text)

    def test_platform_workflows_do_not_duplicate_feature_branch_and_pr_runs(self):
        for name in ("macos.yml", "ubuntu.yml", "windows.yml"):
            text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
            self.assertIn("branches: [main]", text)
            self.assertNotIn('"feat/**"', text)

    def test_release_collects_all_three_platforms(self):
        text = RELEASE.read_text(encoding="utf-8")
        for workflow in ("macOS", "Ubuntu", "Windows"):
            self.assertIn(workflow, text)
        for suffix in ("*.dmg", "*.deb", "*.msi", "*.sha256"):
            self.assertIn(suffix, text)

    def test_release_rejects_nonportable_or_mismatched_checksum_assets(self):
        text = RELEASE.read_text(encoding="utf-8")
        self.assertIn("Validate portable release checksums", text)
        self.assertIn("checksum must use LF without CR", text)
        self.assertIn("checksum must reference its sibling basename", text)
        self.assertIn("checksum digest mismatch", text)

    def test_macos_packager_uses_fresh_arm64_release_builder_inputs(self):
        text = PACKAGE.read_text(encoding="utf-8")
        self.assertIn("WORKSPACE_VERSION", text)
        self.assertIn('VERSION="${VERSION:-$WORKSPACE_VERSION}"', text)
        self.assertNotIn('VERSION="${VERSION:-0.2.3}"', text)
        self.assertIn("uname -m", text)
        self.assertIn("arm64", text)
        self.assertIn("swift build", text)
        self.assertIn("assemble-menu-app.sh", text)
        self.assertIn("assemble-installer-app.sh", text)
        self.assertIn("package-release.py", text)
        self.assertIn("--source-compliance-bundle", text)
        self.assertIn("--rebind-source-compliance-bundle", text)
        self.assertIn("EZ-HYU-VPN-arm64.dmg", text)
        self.assertIn("mktemp -d /private/tmp/hyu-vpn-macos-build.XXXXXX", text)
        self.assertIn("RELEASE_OUTPUT_ROOT", text)
        self.assertNotIn("$ROOT/target/macos-package", text)
        for forbidden in ("password", "totp_seed", "credentials.enc"):
            self.assertNotIn(forbidden, text.lower())
        self.assertIn('/opt/homebrew/bin/brew', text)
        self.assertIn('/usr/local/bin/brew', text)
        self.assertNotIn('BREW="${BREW:-', text)

    def test_macos_workflow_builds_and_tests_rust_backend(self):
        text = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("cargo fmt --all -- --check", text)
        self.assertIn("cargo build --package hyu-vpn-platform-macos --package hyu-vpn-macos-service --package hyu-vpn-hip --release", text)
        self.assertIn("cargo test --package hyu-vpn-platform-macos --package hyu-vpn-macos-service --package hyu-vpn-hip", text)
        self.assertIn("cargo clippy --package hyu-vpn-platform-macos --package hyu-vpn-macos-service --package hyu-vpn-hip", text)
        self.assertIn("hyu-vpn-platform-macos", text)
        self.assertIn("hyu-vpn-macos-service", text)
        self.assertIn("test -x target/release/hyu-vpn-macos-service", text)
        self.assertIn('test -x "$mountpoint/hyu-vpn-macos-service"', text)
        self.assertIn('lipo -archs "$mountpoint/hyu-vpn-macos-service"', text)
        self.assertIn('codesign --verify --strict "$mountpoint/hyu-vpn-macos-service"', text)
        self.assertIn('hyu-vpn-native-client', text)
        self.assertIn("find \"$mountpoint\"", text)
        self.assertIn("while IFS= read -r -d '' candidate", text)
        self.assertIn('src/hyu_vpn', text)
        self.assertIn('/usr/bin/py', text)
        self.assertIn('thon3', text)
        self.assertIn('PYTHON3_PATH', text)


    def test_macos_dmg_acceptance_script_is_read_only_and_bounded(self):
        self.assertTrue(DMG_ACCEPTANCE.exists(), "Task 8 requires a reusable DMG acceptance script")
        self.assertTrue(DMG_ACCEPTANCE.stat().st_mode & 0o111, "acceptance script must be executable")
        text = DMG_ACCEPTANCE.read_text(encoding="utf-8")

        for required in [
            "set -euo pipefail",
            "hdiutil verify",
            "hdiutil attach -readonly -nobrowse -mountpoint",
            "hdiutil detach",
            "mktemp -d /private/tmp/hyu-vpn-dmg-acceptance.XXXXXX",
            "trap cleanup EXIT HUP INT TERM",
            "codesign --verify --deep --strict",
            "lipo -archs",
            "manifest.json",
            "shasum -a 256",
            "stat -f",
            "ProgramArguments",
            "/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service",
            "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp",
            "Install HYU VPN.app/Contents/MacOS/HYUVPNInstallerApp",
            "hyu-vpn-macos-service",
            "com.hyu.vpn.helper",
            "runtime/gp-hip-report",
            "hyu-vpn-service",
            "hyu-vpn-control",
            "hyu-vpn-connect",
            "src/hyu_vpn",
            "/usr/bin/python3",
            "PYTHON3_PATH",
        ]:
            with self.subTest(required=required):
                self.assertIn(required, text)

        for forbidden in [
            "open \"$mountpoint/Install HYU VPN.app\"",
            "open $mountpoint/Install",
            "launchctl bootstrap",
            "launchctl bootout",
            "launchctl kickstart",
            "sudo ",
            "networksetup",
            "scutil --nc",
            "route add",
            "ifconfig",
        ]:
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_macos_dmg_acceptance_script_checks_exact_manifested_payload(self):
        self.assertTrue(DMG_ACCEPTANCE.exists(), "Task 8 requires a reusable DMG acceptance script")
        text = DMG_ACCEPTANCE.read_text(encoding="utf-8")
        for rel in [
            "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp",
            "Install HYU VPN.app/Contents/MacOS/HYUVPNInstallerApp",
            "hyu-vpn-macos-service",
            "com.hyu.vpn.helper",
            "runtime/gp-hip-report",
            "launchd/com.hyu.vpn.service.plist.in",
        ]:
            with self.subTest(rel=rel):
                self.assertIn(rel, text)
        self.assertIn('"sha256"', text)
        self.assertIn('"size"', text)
        self.assertIn('"mode"', text)
        self.assertIn('actual_manifest != expected_manifest', text)
        self.assertIn('expected_files != actual_files', text)


    def _write_dmg_acceptance_fixture(self, root: Path, *, legacy_path: Optional[str] = None, forbidden_content: Optional[bytes] = None, large_file_size: Optional[int] = None) -> None:
        required_files = {
            "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp": b"menu",
            "Install HYU VPN.app/Contents/MacOS/HYUVPNInstallerApp": b"installer",
            "hyu-vpn-macos-service": b"service",
            "com.hyu.vpn.helper": b"helper",
            "runtime/gp-hip-report": b"hip",
            "launchd/com.hyu.vpn.service.plist.in": b'<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>ProgramArguments</key><array><string>@SERVICE_PATH@</string></array></dict></plist>\n',
        }
        if legacy_path is not None:
            required_files[legacy_path] = b"legacy binary path without content token"
        if forbidden_content is not None:
            required_files["README-lab.md"] = forbidden_content
        if large_file_size is not None:
            required_files["large-safe-text.txt"] = b"A" * large_file_size
        for rel, data in required_files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            if rel in {
                "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp",
                "Install HYU VPN.app/Contents/MacOS/HYUVPNInstallerApp",
                "hyu-vpn-macos-service",
                "com.hyu.vpn.helper",
                "runtime/gp-hip-report",
            }:
                path.chmod(0o755)
            else:
                path.chmod(0o644)
        manifest = {"schema": 1, "name": "HYU VPN", "manifest": "manifest.json", "files": {}}
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                rel = path.relative_to(root).as_posix()
                data = path.read_bytes()
                manifest["files"][rel] = {
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                    "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
                }
        (root / "manifest.json").write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")

    def _write_fake_dmg_tools(self, bin_dir: Path) -> None:
        hdiutil = bin_dir / "hdiutil"
        hdiutil.write_text(
            "#!/bin/bash\n"
            "set -euo pipefail\n"
            "case \"${1:-}\" in\n"
            "  verify) exit 0 ;;\n"
            "  attach)\n"
            "    mount=\"\"\n"
            "    while [[ $# -gt 0 ]]; do\n"
            "      if [[ \"$1\" = -mountpoint ]]; then shift; mount=\"$1\"; fi\n"
            "      shift || true\n"
            "    done\n"
            "    python3 - \"$HYU_TEST_MOUNT_SOURCE\" \"$mount\" <<'PY'\n"
            "import os, shutil, sys\n"
            "src, dst = sys.argv[1], sys.argv[2]\n"
            "shutil.copytree(src, dst, dirs_exist_ok=True, symlinks=True)\n"
            "special = os.environ.get('HYU_TEST_SPECIAL')\n"
            "if special == 'symlink':\n"
            "    os.symlink('/tmp/legacy-target', os.path.join(dst, 'unmanifested-link'))\n"
            "elif special == 'fifo':\n"
            "    os.mkfifo(os.path.join(dst, 'unmanifested-fifo'))\n"
            "PY\n"
            "    exit 0 ;;\n"
            "  detach)\n"
            "    if [[ \"${HYU_TEST_DETACH_FAIL:-}\" = 1 ]]; then echo 'simulated busy mount with /Users/example/password-secret' >&2; exit 88; fi\n"
            "    find \"$2\" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +\n"
            "    exit 0 ;;\n"
            "esac\n"
            "exit 64\n",
            encoding="utf-8",
        )
        hdiutil.chmod(0o755)
        for name, body in {
            "codesign": "#!/bin/bash\nexit 0\n",
            "lipo": "#!/bin/bash\necho arm64\n",
            "file": "#!/bin/bash\necho \"$1: ASCII text\"\n",
        }.items():
            path = bin_dir / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)

    def _run_dmg_acceptance_fixture(self, fixture: Path, *, special: Optional[str] = None, detach_fail: bool = False, max_file_bytes: Optional[int] = None) -> subprocess.CompletedProcess[str]:
        bin_dir = fixture.parent / "fake-bin"
        bin_dir.mkdir(exist_ok=True)
        self._write_fake_dmg_tools(bin_dir)
        dmg = fixture.parent / "fixture.dmg"
        dmg.write_text("fake dmg", encoding="utf-8")
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["HYU_TEST_MOUNT_SOURCE"] = str(fixture)
        if special is not None:
            env["HYU_TEST_SPECIAL"] = special
        if detach_fail:
            env["HYU_TEST_DETACH_FAIL"] = "1"
        if max_file_bytes is not None:
            env["HYU_DMG_ACCEPTANCE_MAX_FILE_BYTES"] = str(max_file_bytes)
        return subprocess.run([str(DMG_ACCEPTANCE), str(dmg)], text=True, capture_output=True, env=env, timeout=20)

    def test_macos_dmg_acceptance_rejects_unmanifested_symlink_or_special_entries(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as td:
            fixture = Path(td) / "payload"
            fixture.mkdir()
            self._write_dmg_acceptance_fixture(fixture)
            for special in ("symlink", "fifo"):
                with self.subTest(special=special):
                    result = self._run_dmg_acceptance_fixture(fixture, special=special)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("special-entry", result.stderr)
                    self.assertNotIn("legacy-target", result.stderr)

    def test_macos_dmg_acceptance_rejects_legacy_tokens_in_every_path_before_binary_exemption(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as td:
            fixture = Path(td) / "payload"
            fixture.mkdir()
            self._write_dmg_acceptance_fixture(fixture, legacy_path="HYU VPN.app/Contents/MacOS/hyu-vpn-control")
            result = self._run_dmg_acceptance_fixture(fixture)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("forbidden-token:path", result.stderr)
            self.assertIn("legacy-backend", result.stderr)

    def test_macos_dmg_acceptance_preserves_primary_error_while_reporting_cleanup_failure(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as td:
            fixture = Path(td) / "payload"
            fixture.mkdir()
            self._write_dmg_acceptance_fixture(fixture)
            result = self._run_dmg_acceptance_fixture(fixture, special="symlink", detach_fail=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("special-entry", result.stderr)
            self.assertIn("cleanup-failed:detach", result.stderr)
            self.assertNotIn("password-secret", result.stderr)
            self.assertNotIn("PASS", result.stdout)

    def test_macos_dmg_acceptance_success_leaves_no_temp_acceptance_dirs(self):
        before = {path.resolve(strict=False) for path in Path("/private/tmp").glob("hyu-vpn-dmg-acceptance.*")}
        with tempfile.TemporaryDirectory(dir="/private/tmp") as td:
            fixture = Path(td) / "payload"
            fixture.mkdir()
            self._write_dmg_acceptance_fixture(fixture)
            result = self._run_dmg_acceptance_fixture(fixture)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS", result.stdout)
        after = {path.resolve(strict=False) for path in Path("/private/tmp").glob("hyu-vpn-dmg-acceptance.*")}
        new_paths = sorted(str(path) for path in after - before)
        for path in new_paths:
            shutil.rmtree(path, ignore_errors=True)
        self.assertEqual(new_paths, [])

    def test_macos_dmg_acceptance_requires_clean_detach_before_pass(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as td:
            fixture = Path(td) / "payload"
            fixture.mkdir()
            self._write_dmg_acceptance_fixture(fixture)
            result = self._run_dmg_acceptance_fixture(fixture, detach_fail=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("PASS", result.stdout)
            self.assertIn("cleanup-failed:detach", result.stderr)
            self.assertNotIn("password-secret", result.stderr)

    def test_macos_dmg_acceptance_bounds_file_reads_and_sanitizes_forbidden_content(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as td:
            fixture = Path(td) / "payload"
            fixture.mkdir()
            self._write_dmg_acceptance_fixture(fixture, forbidden_content=b"password=SECRET-RAW-LINE\n/usr/bin/python3\n")
            result = self._run_dmg_acceptance_fixture(fixture)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("forbidden-token:content", result.stderr)
            self.assertIn("python-runtime", result.stderr)
            self.assertNotIn("SECRET-RAW-LINE", result.stdout + result.stderr)
            self.assertNotIn("/usr/bin/python3", result.stdout + result.stderr)

            fixture = Path(td) / "large-payload"
            fixture.mkdir()
            self._write_dmg_acceptance_fixture(fixture, large_file_size=64)
            result = self._run_dmg_acceptance_fixture(fixture, max_file_bytes=32)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("size-limit:file", result.stderr)

    def test_readme_windows_uses_exact_three_field_credential_form(self):
        text = README.read_text(encoding="utf-8")
        self.assertIn("HYU ID, 비밀번호, TOTP 비밀키를 한 창에 한 번씩", text)
        self.assertNotIn("비밀번호 확인 2칸", text)
        self.assertNotIn("TOTP 비밀키 확인 2칸", text)


if __name__ == "__main__":
    unittest.main()
