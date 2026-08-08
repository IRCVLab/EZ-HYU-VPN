import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "macos.yml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
PACKAGE = ROOT / "scripts" / "package-macos.sh"
README = ROOT / "README.md"


class MacOSWorkflowTests(unittest.TestCase):
    def test_macos_ci_tests_builds_and_verifies_arm64_dmg(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("runs-on: macos-15", text)
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

    def test_release_collects_all_three_platforms(self):
        text = RELEASE.read_text(encoding="utf-8")
        for workflow in ("macOS", "Ubuntu", "Windows"):
            self.assertIn(workflow, text)
        for suffix in ("*.dmg", "*.deb", "*.msi", "*.sha256"):
            self.assertIn(suffix, text)

    def test_macos_packager_uses_fresh_arm64_release_builder_inputs(self):
        text = PACKAGE.read_text(encoding="utf-8")
        self.assertIn("uname -m", text)
        self.assertIn("arm64", text)
        self.assertIn("swift build", text)
        self.assertIn("assemble-menu-app.sh", text)
        self.assertIn("assemble-installer-app.sh", text)
        self.assertIn("package-release.py", text)
        self.assertIn("--source-compliance-bundle", text)
        self.assertIn("EZ-HYU-VPN-arm64.dmg", text)
        self.assertIn("mktemp -d /private/tmp/hyu-vpn-macos-build.XXXXXX", text)
        self.assertIn("RELEASE_OUTPUT_ROOT", text)
        self.assertNotIn("$ROOT/target/macos-package", text)
        for forbidden in ("password", "totp_seed", "credentials.enc"):
            self.assertNotIn(forbidden, text.lower())
        self.assertIn('/opt/homebrew/bin/brew', text)
        self.assertIn('/usr/local/bin/brew', text)
        self.assertNotIn('BREW="${BREW:-', text)

    def test_readme_windows_uses_exact_three_field_credential_form(self):
        text = README.read_text(encoding="utf-8")
        self.assertIn("HYU ID, 비밀번호, TOTP 비밀키를 한 창에 한 번씩", text)
        self.assertNotIn("비밀번호 확인 2칸", text)
        self.assertNotIn("TOTP 비밀키 확인 2칸", text)


if __name__ == "__main__":
    unittest.main()
