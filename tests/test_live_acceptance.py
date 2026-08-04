from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests" / "live_acceptance.sh"


class LiveAcceptanceScriptTests(unittest.TestCase):
    def run_script(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        if env:
            merged.update(env)
        return subprocess.run(
            [str(SCRIPT), *args],
            cwd=ROOT,
            env=merged,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

    def test_default_mode_is_read_only_dry_run(self):
        with tempfile.TemporaryDirectory() as td:
            audit = Path(td) / "mutations.log"
            before = set(Path(td).iterdir())

            result = self.run_script(
                env={
                    "TMPDIR": td,
                    "HYU_ACCEPTANCE_MUTATION_AUDIT": str(audit),
                }
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("mode=dry-run", result.stdout)
            self.assertIn("state_changes=none", result.stdout)
            self.assertIn("launch_agent=", result.stdout)
            self.assertIn("native_connection=", result.stdout)
            self.assertNotIn("password", result.stdout.lower())
            self.assertNotIn("cookie", result.stdout.lower())
            self.assertFalse(audit.exists(), "dry-run recorded a state-changing action")
            self.assertEqual(set(Path(td).iterdir()), before)

    def test_explicit_dry_run_matches_default_contract(self):
        result = self.run_script("--dry-run")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mode=dry-run", result.stdout)
        self.assertIn("state_changes=none", result.stdout)

    def test_unknown_option_fails_without_action(self):
        with tempfile.TemporaryDirectory() as td:
            audit = Path(td) / "mutations.log"
            result = self.run_script(
                "--not-a-mode",
                env={"HYU_ACCEPTANCE_MUTATION_AUDIT": str(audit)},
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("usage:", result.stderr.lower())
            self.assertFalse(audit.exists())

    def test_log_privacy_check_allows_prompts_and_explicit_empty_auth_cookies(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "openconnect.log"
            log.write_text(
                "Password: \nChallenge: \n"
                "GlobalProtect login returned portal-userauthcookie=empty\n"
                "GlobalProtect login returned portal-prelogonuserauthcookie=empty\n",
                encoding="utf-8",
            )

            result = self.run_script("--check-log", str(log))

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "log_privacy=passed")

    def test_log_privacy_check_rejects_nonempty_secret_assignments_without_echoing_value(self):
        canary = "SECRET-CANARY-DO-NOT-PRINT"
        for field in ("authcookie", "cookie", "password", "totp", "host-id", "interface-mac"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as td:
                log = Path(td) / "openconnect.log"
                log.write_text(f"{field}={canary}\n", encoding="utf-8")

                result = self.run_script("--check-log", str(log))

                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout.strip(), "log_privacy=failed")
                self.assertNotIn(canary, result.stdout + result.stderr)

    def test_script_declares_reversible_execute_safety_contract(self):
        text = SCRIPT.read_text(encoding="utf-8")

        self.assertTrue(os.access(SCRIPT, os.X_OK))
        self.assertIn("trap 'cleanup $?" , text)
        self.assertIn("snapshot_state", text)
        self.assertIn("disconnect_native_gracefully", text)
        self.assertIn("restore_native_if_needed", text)
        self.assertIn("native_ui_connected", text)
        self.assertIn("no_new_openconnect_process", text)
        self.assertIn("HIP report submitted successfully", text)
        self.assertIn("166.104.100.100", text)
        self.assertNotIn("find-generic-password -w", text)
        self.assertNotIn("password[=:]", text.lower())

    def test_cleanup_ignores_repeated_stop_signals_and_never_kills_only_the_wrapper(self):
        text = SCRIPT.read_text(encoding="utf-8")
        cleanup_body = text.split("cleanup() {", 1)[1].split("\n}", 1)[0]
        stop_body = text.split("stop_connector() {", 1)[1].split("\n}", 1)[0]

        self.assertIn("trap '' INT TERM", cleanup_body)
        self.assertNotIn('kill -KILL "$CONNECT_PID"', stop_body)
        self.assertIn("return 1", stop_body)

    def test_native_rollback_is_armed_before_disconnect_is_attempted(self):
        text = SCRIPT.read_text(encoding="utf-8")
        body = text.split("disconnect_native_gracefully() {", 1)[1].split("\n}", 1)[0]

        click = body.index("click_native_button Disconnect")
        armed = body.index("NATIVE_STOPPED=1")
        verify = body.index("wait_for_native_state disconnected")
        self.assertLess(click, armed)
        self.assertLess(armed, verify)

    def test_execute_tracks_and_remediates_only_its_owned_openconnect_group(self):
        text = SCRIPT.read_text(encoding="utf-8")

        self.assertIn("capture_owned_openconnect_group", text)
        self.assertIn("owned_openconnect_group_present", text)
        self.assertIn("signal_owned_openconnect_group TERM", text)
        self.assertIn("signal_owned_openconnect_group HUP", text)
        self.assertIn("OWNED_OPENCONNECT_PGID", text)


if __name__ == "__main__":
    unittest.main()
