import json
import os
import plistlib
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
PREFLIGHT = REPO / "scripts" / "preflight.sh"
ASSEMBLER = REPO / "scripts" / "assemble-app.sh"
FIXTURE = REPO / "tests" / "fixtures" / "app-bundle"

EXPECTED_APP_NAME = "HYU VPN.app"
EXPECTED_BUNDLE_ID = "com.hyu.vpn.menubar"
EXPECTED_VERSION = "0.1.0"
EXPECTED_EXECUTABLE = "HYUVPNMenuApp"


class BuildPreflightTests(unittest.TestCase):
    maxDiff = None

    def run_preflight(self):
        result = subprocess.run(
            [str(PREFLIGHT)],
            cwd=REPO,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        self.assertEqual("", result.stderr)
        return json.loads(result.stdout)

    def test_preflight_reports_required_macos_toolchain_capabilities(self):
        metadata = self.run_preflight()

        self.assertEqual(1, metadata["schema_version"])
        self.assertTrue(metadata["read_only"])
        self.assertIn(metadata["host_arch"], ["arm64", "x86_64"])
        self.assertGreaterEqual(int(metadata["swift"]["major_version"]), 6)
        self.assertTrue(metadata["swift"]["appkit_compiles"])

        for tool in ["codesign", "hdiutil", "plutil", "security", "visudo"]:
            with self.subTest(tool=tool):
                self.assertTrue(metadata["tools"][tool]["available"])
                self.assertTrue(Path(metadata["tools"][tool]["path"]).is_absolute())
                self.assertTrue(os.access(metadata["tools"][tool]["path"], os.X_OK))

    def test_preflight_discovers_homebrew_dependencies_from_stable_prefixes(self):
        metadata = self.run_preflight()

        self.assertEqual(["/opt/homebrew", "/usr/local"], metadata["homebrew"]["searched_prefixes"])
        self.assertIn(metadata["homebrew"]["prefix"], metadata["homebrew"]["searched_prefixes"])
        self.assertEqual(
            ["openconnect", "oath-toolkit"],
            [dep["name"] for dep in metadata["homebrew"]["dependencies"]],
        )
        for dep in metadata["homebrew"]["dependencies"]:
            with self.subTest(dep=dep["name"]):
                self.assertTrue(dep["available"])
                self.assertTrue(Path(dep["prefix"]).is_absolute())
                self.assertTrue(Path(dep["executable"]).is_absolute())

    def test_preflight_script_is_static_read_only_probe_only(self):
        source = PREFLIGHT.read_text()
        forbidden = [
            "sudo ",
            "launchctl ",
            "scutil --set",
            "networksetup ",
            "ifconfig ",
            "route ",
            "kill ",
            "pkill ",
            "openconnect ",
            "security add-",
            "security delete-",
        ]
        for token in forbidden:
            with self.subTest(token=token):
                self.assertNotIn(token, source)


class AppBundleFixtureTests(unittest.TestCase):
    def assemble_bundle(self, destination: Path) -> Path:
        subprocess.run(
            [str(ASSEMBLER), str(FIXTURE), str(destination)],
            cwd=REPO,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return destination / EXPECTED_APP_NAME

    def test_assembler_creates_required_bundle_layout_and_plist_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self.assemble_bundle(Path(tmp))

            self.assertTrue((app / "Contents" / "MacOS").is_dir())
            self.assertTrue((app / "Contents" / "Resources").is_dir())
            plist_path = app / "Contents" / "Info.plist"
            self.assertTrue(plist_path.is_file())

            with plist_path.open("rb") as fh:
                plist = plistlib.load(fh)
            self.assertTrue(plist["LSUIElement"])
            self.assertEqual(EXPECTED_BUNDLE_ID, plist["CFBundleIdentifier"])
            self.assertEqual(EXPECTED_VERSION, plist["CFBundleShortVersionString"])
            self.assertEqual(EXPECTED_VERSION, plist["CFBundleVersion"])
            self.assertEqual(EXPECTED_EXECUTABLE, plist["CFBundleExecutable"])

            executable = app / "Contents" / "MacOS" / EXPECTED_EXECUTABLE
            self.assertTrue(executable.is_file())
            self.assertTrue(os.access(executable, os.X_OK))

    def test_assembler_ad_hoc_signs_the_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = self.assemble_bundle(Path(tmp))

            result = subprocess.run(
                ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)

            details = subprocess.run(
                ["/usr/bin/codesign", "-dv", str(app)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertIn("Signature=adhoc", details.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
