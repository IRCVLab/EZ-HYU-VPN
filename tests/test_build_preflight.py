import json
import os
import plistlib
import hashlib
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

    def snapshot_sandbox_tree(self, root: Path):
        snapshot = {}
        for path in sorted([root, *root.rglob("*")]):
            rel = str(path.relative_to(root)) if path != root else "."
            st = path.lstat()
            entry = {
                "mode": stat.S_IMODE(st.st_mode),
                "type": "dir" if path.is_dir() else "file" if path.is_file() else "other",
            }
            if path.is_file():
                entry["mtime_ns"] = st.st_mtime_ns
                entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            snapshot[rel] = entry
        return snapshot

    def snapshot_path_metadata(self, paths):
        metadata = {}
        for path in paths:
            try:
                st = path.lstat()
            except FileNotFoundError:
                metadata[str(path)] = None
                continue
            metadata[str(path)] = {
                "mode": stat.S_IMODE(st.st_mode),
                "mtime_ns": st.st_mtime_ns,
                "uid": st.st_uid,
                "gid": st.st_gid,
                "type": "dir" if path.is_dir() else "file" if path.is_file() else "other",
            }
        return metadata

    def openconnect_process_snapshot(self):
        result = subprocess.run(
            ["/bin/ps", "-axo", "pid=,comm=,args="],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        processes = []
        for line in result.stdout.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) < 2:
                continue
            pid, comm = parts[0], parts[1]
            args = parts[2] if len(parts) == 3 else ""
            if Path(comm).name == "openconnect" or "bin/openconnect" in args:
                processes.append((pid, comm, args))
        return tuple(sorted(processes))

    def protected_route_tuple(self):
        result = subprocess.run(
            ["/sbin/route", "-n", "get", "166.104.100.100"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            return ("absent",)
        interesting = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith(("route to:", "destination:", "gateway:", "interface:")):
                interesting.append(stripped)
        return tuple(interesting)

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

        for tool in ["codesign", "hdiutil", "plutil", "visudo"]:
            with self.subTest(tool=tool):
                self.assertTrue(metadata["tools"][tool]["available"])
                self.assertTrue(Path(metadata["tools"][tool]["path"]).is_absolute())
                self.assertTrue(os.access(metadata["tools"][tool]["path"], os.X_OK))
        self.assertNotIn("security", metadata["tools"])

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

    def test_preflight_is_behaviorally_read_only_against_sandbox_vpn_and_system_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp)
            home = sandbox / "home"
            tmpdir = sandbox / "tmp"
            home.mkdir()
            tmpdir.mkdir()
            relevant_paths = [
                home / "Library" / "Application Support" / "HYU VPN",
                home / "Library" / "LaunchAgents" / "local.hyu-openconnect.plist",
                home / "Library" / "LaunchAgents" / "com.hyu.vpn.service.plist",
                home / "Library" / "LaunchAgents" / "com.hyu.vpn.menubar.plist",
                Path("/Library/Application Support/HYU VPN"),
                Path("/Library/LaunchAgents/local.hyu-openconnect.plist"),
                Path("/Library/LaunchAgents/com.hyu.vpn.service.plist"),
                Path("/Library/LaunchAgents/com.hyu.vpn.menubar.plist"),
                Path("/Library/Preferences/SystemConfiguration/preferences.plist"),
                Path("/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist"),
            ]
            before = {
                "sandbox": self.snapshot_sandbox_tree(sandbox),
                "openconnect": self.openconnect_process_snapshot(),
                "protected_route": self.protected_route_tuple(),
                "paths": self.snapshot_path_metadata(relevant_paths),
            }

            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(home),
                    "TMPDIR": str(tmpdir),
                    "XDG_CACHE_HOME": str(home / ".cache"),
                    "XDG_CONFIG_HOME": str(home / ".config"),
                    "XDG_STATE_HOME": str(home / ".local" / "state"),
                }
            )
            result = subprocess.run(
                [str(PREFLIGHT)],
                cwd=REPO,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            self.assertEqual("", result.stderr)
            self.assertTrue(json.loads(result.stdout)["read_only"])

            after = {
                "sandbox": self.snapshot_sandbox_tree(sandbox),
                "openconnect": self.openconnect_process_snapshot(),
                "protected_route": self.protected_route_tuple(),
                "paths": self.snapshot_path_metadata(relevant_paths),
            }
            self.assertEqual(before, after)

    def test_preflight_source_read_only_allowlist_defense_in_depth(self):
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
    def test_assembler_uses_required_absolute_system_tools(self):
        source = ASSEMBLER.read_text()
        required_tokens = [
            "/bin/rm -rf",
            "/bin/mkdir -p",
            "/bin/chmod 0755",
            "/bin/cp ",
            "/usr/bin/dirname ",
            "/usr/bin/find ",
            "/usr/bin/swiftc ",
            "/usr/bin/plutil ",
            "/usr/bin/codesign ",
            "/usr/bin/python3 ",
        ]
        for token in required_tokens:
            with self.subTest(token=token):
                self.assertIn(token, source)

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

    def test_assembler_accepts_relative_fixture_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(
                [str(ASSEMBLER), "tests/fixtures/app-bundle", tmp],
                cwd=REPO,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            self.assertTrue((Path(tmp) / EXPECTED_APP_NAME / "Contents" / "Info.plist").is_file())

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
