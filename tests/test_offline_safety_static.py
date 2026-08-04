from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIVE_SCRIPT = ROOT / "tests" / "live_acceptance.sh"
GATE = ROOT / "tests" / "live_acceptance_gate.sh"
README = ROOT / "README.md"


class OfflineSafetyStaticTests(unittest.TestCase):
    def test_live_script_sources_isolated_gate_and_does_not_inline_nonce_logic(self):
        text = LIVE_SCRIPT.read_text(encoding="utf-8")
        gate = GATE.read_text(encoding="utf-8")

        self.assertIn("source ", text)
        self.assertIn("live_acceptance_gate.sh", text)
        self.assertIn("parse_live_acceptance_args", text)
        self.assertIn("require_live_mutation_ack", text)
        self.assertNotIn("HYU_VPN_ALLOW_LIVE_MUTATION", text)
        self.assertIn("HYU_VPN_ALLOW_LIVE_MUTATION", gate)
        self.assertNotIn("/bin/ps", gate)
        self.assertNotIn("/sbin/route", gate)
        self.assertNotIn("launchctl", gate)

    def test_live_execute_gate_is_before_any_live_reads_or_mutations(self):
        text = LIVE_SCRIPT.read_text(encoding="utf-8")
        main_tail = text.split('if [ "$MODE" = dry-run ]', 1)[1]
        run_execute_body = text.split("run_execute() {", 1)[1].split("\n}", 1)[0]
        print_preconditions_body = text.split("print_preconditions() {", 1)[1].split("\n}", 1)[0]

        self.assertLess(main_tail.index("require_live_mutation_ack"), main_tail.index("run_execute"))
        self.assertIn("launch_agent_state", run_execute_body)
        self.assertIn("native_connection_confirmed", run_execute_body)
        self.assertNotIn("launch_agent_state", print_preconditions_body)
        self.assertNotIn("native_connection_active", print_preconditions_body)
        self.assertNotIn("CONNECTOR", print_preconditions_body)
        self.assertNotIn("/opt/homebrew", print_preconditions_body)
        self.assertIn("connector=not-read-dry-run", print_preconditions_body)
        self.assertIn("dependencies=not-read-dry-run", print_preconditions_body)

    def test_readme_offline_safe_commands_do_not_run_full_unittest_discovery_or_live_acceptance(self):
        readme = README.read_text(encoding="utf-8")
        offline_section = readme.split("Expected offline-safe behavior before live use:", 1)[1].split("During a real foreground attempt", 1)[0]

        self.assertNotIn("unittest discover", offline_section)
        self.assertNotIn("tests/live_acceptance.sh", offline_section)
        self.assertIn("tests.test_launchd_config", offline_section)
        self.assertIn("tests.test_supervisor", offline_section)
        self.assertIn("tests.test_offline_safety_static", offline_section)
        self.assertIn("tests.test_live_acceptance_gate", offline_section)
        self.assertNotIn("SupervisorLoopTests.test_missing_auto", offline_section)

    def test_readme_does_not_document_bootstrapping_quarantined_legacy_plist(self):
        readme = README.read_text(encoding="utf-8")

        self.assertIn("quarantine-only inert template", readme)
        self.assertIn("Do not bootstrap `launchd/local.hyu-openconnect.plist`", readme)
        self.assertNotIn("cp launchd/local.hyu-openconnect.plist", readme)


if __name__ == "__main__":
    unittest.main()
