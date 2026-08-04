from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "tests" / "live_acceptance_gate.sh"
NOW = 1_700_000_000


class LiveAcceptanceGateTests(unittest.TestCase):
    def run_gate(self, *args: str, env: dict[str, str] | None = None, now: int = NOW) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        if env:
            merged.update(env)
        script = f'''
set -u
source "{GATE}"
parse_live_acceptance_args "$@" || exit $?
if [ "$LIVE_ACCEPTANCE_MODE" = execute ]; then
    require_live_mutation_ack "{now}" || exit $?
fi
printf 'mode=%s\nack=%s\ncheck_log=%s\n' "$LIVE_ACCEPTANCE_MODE" "${{LIVE_MUTATION_ACK_NONCE:-}}" "${{LIVE_ACCEPTANCE_CHECK_LOG:-}}"
'''
        return subprocess.run(
            ["/bin/bash", "-c", script, "gate", *args],
            cwd=ROOT,
            env=merged,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    def assert_rejected(self, *args: str, env: dict[str, str] | None = None, now: int = NOW) -> None:
        result = self.run_gate(*args, env=env, now=now)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("mode=execute", result.stdout)

    def test_valid_execute_requires_matching_fresh_nonce(self):
        nonce = f"hyu-live-mutation-{NOW}"
        result = self.run_gate("--execute", "--acknowledge-live-mutation", nonce, env={"HYU_VPN_ALLOW_LIVE_MUTATION": nonce})

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mode=execute", result.stdout)
        self.assertIn(f"ack={nonce}", result.stdout)

    def test_rejects_missing_ack_for_execute(self):
        self.assert_rejected("--execute", env={"HYU_VPN_ALLOW_LIVE_MUTATION": f"hyu-live-mutation-{NOW}"})

    def test_rejects_env_mismatch(self):
        self.assert_rejected(
            "--execute",
            "--acknowledge-live-mutation",
            f"hyu-live-mutation-{NOW}",
            env={"HYU_VPN_ALLOW_LIVE_MUTATION": f"hyu-live-mutation-{NOW - 1}"},
        )

    def test_rejects_stale_future_and_bad_nonce(self):
        cases = [
            (f"hyu-live-mutation-{NOW - 301}", NOW),
            (f"hyu-live-mutation-{NOW + 1}", NOW),
            ("yes", NOW),
            (f"hyu-live-mutation-{NOW}-extra", NOW),
        ]
        for nonce, now in cases:
            with self.subTest(nonce=nonce):
                self.assert_rejected("--execute", "--acknowledge-live-mutation", nonce, env={"HYU_VPN_ALLOW_LIVE_MUTATION": nonce}, now=now)

    def test_rejects_duplicate_mode_or_ack_args(self):
        nonce = f"hyu-live-mutation-{NOW}"
        self.assert_rejected("--dry-run", "--execute")
        self.assert_rejected("--execute", "--execute")
        self.assert_rejected(
            "--execute",
            "--acknowledge-live-mutation",
            nonce,
            "--acknowledge-live-mutation",
            nonce,
            env={"HYU_VPN_ALLOW_LIVE_MUTATION": nonce},
        )

    def test_check_log_mode_parses_without_live_ack(self):
        result = self.run_gate("--check-log", "/tmp/nonsecret.log")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mode=check-log", result.stdout)
        self.assertIn("check_log=/tmp/nonsecret.log", result.stdout)


if __name__ == "__main__":
    unittest.main()
