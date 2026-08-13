# Task 9 Fix Round 1 Implementation Report

## Scope

Implemented all 6 reviewer-finding groups / 11 concrete fix requirements in Task 9 script/docs/tests. No real live install, sudo mutation, launchctl mutation, VPN connection, helper mutation, route/DNS mutation, uninstall, or Wi-Fi change was executed by this agent. Verification used fake-tool/state-machine fixtures, syntax/static checks, targeted test-root proof plumbing, and safe read-only preflight.

## Fixes

- Live mode reruns scripts/macos-dmg-acceptance.sh and then mounts the canonical regular DMG read-only/nobrowse; any `--dmg-acceptance-log` is bound to canonical path and digest and is never sufficient alone.
- Baseline capture records normalized default route identity, bounded DNS hash, internet probes, strict helper status, installed service identity, and `$HOME/Library/Application Support/hyu-openconnect/{credentials.key,credentials.enc}` metadata only.
- Added Unix-socket framed IPC for status/connect/disconnect/reconnect using exact schema v1 request keys, bounded frame/timeout handling, owner/mode socket validation, response request_id matching, and no secrets.
- Helper status now uses exact `sudo -n /Library/PrivilegedHelperTools/com.hyu.vpn.helper status`, rejects multiline/malformed/extra-key JSON, validates state-specific PID/uppercase nonce/utun rules, fingerprints owned OpenConnect PID, and uses helper `stop` for the owned-session boundary.
- Preflight additionally normalizes the currently installed legacy repair-required helper status shape into the internal strict schema when the helper omits null pid/tunnel fields, so preflight works on this actual Mac while still rejecting malformed or extra-key output.
- Install identity verifies against mounted DMG manifest hashes and backend version `0.2.0`; singleton and no-legacy/Python path phases report sanitized categories only.
- Rust service restart uses exact `launchctl kickstart -k gui/$UID/com.hyu.vpn.service`, then rechecks IPC/helper/singleton reconciliation.
- Disconnect uses IPC disconnect, helper stopped, normalized route/DNS baseline comparison, and post-mutation internet guard.
- Error trap calls exact helper repair when helper state is owned/running or repair-required, then rechecks internet.
- Test-root mode runs a targeted root-admin rollback unittest proof and emits test-root evidence; live mode requires test-root evidence.
- Uninstall is guarded behind `--exercise-uninstall-reinstall`; without it, the script says uninstall is not exercised and cannot claim full Task 9 completion.
- Physical Wi-Fi gate last uses safe interface detection, exact `networksetup -setairportpower <iface> off/on`, and a restore trap.

## TDD evidence

### RED

Replaced the earlier placeholder tests with fake-tool/state-machine tests, then ran:

```bash
python3 -m unittest -v tests.test_live_macos_rust_acceptance
```

The initial RED run failed on the intended missing behavior: placeholder phase output, forgeable DMG log reliance, missing test-root evidence, weak helper parsing, missing `--exercise-uninstall-reinstall`, missing physical Wi-Fi command audit, and missing docs/report boundaries.

### GREEN / verification

- `python3 -m unittest -v tests.test_live_macos_rust_acceptance` → `Ran 8 tests in 20.427s ... OK`.
- `bash -n scripts/live-macos-rust-acceptance.sh` → exit 0.
- `python3 -m py_compile tests/test_live_macos_rust_acceptance.py` → exit 0.
- Focused adjacent macOS gate: `python3 -m unittest -v tests.test_live_macos_rust_acceptance tests.test_macos_workflow tests.test_installer tests.test_launchd_config` → `Ran 71 tests in 130.407s ... OK`.
- Safe actual-Mac preflight: `scripts/live-macos-rust-acceptance.sh --mode preflight` → exit 0; captured route/DNS/internet/helper/credential metadata only and no mutation phases.

## Live boundaries

The implemented live command path is now concrete, but this agent ran it only against fake tools and fake IPC. Authorized root-agent/operator execution remains required for the real target Mac. The physical Wi-Fi gate last remains opt-in and user-present gated. If `--exercise-uninstall-reinstall` is not selected, the script intentionally reports partial Task 9 completion.

---

# Task 9 Fix Round 2 Implementation Report

## Scope

Fixed the 8 updated review findings without executing live mutations. All live install, root-admin live phases, launchctl mutation, VPN connection, helper stop/repair, uninstall/reinstall, and Wi-Fi power changes were exercised only through fake-tool/state-machine fixtures. Real local verification was limited to read-only preflight and marked test-root rollback evidence generation.

## Fix round 2 changes

- Corrected the production socket default to `$HOME/Library/Application Support/hyu-openconnect/daemon.sock`.
- Updated Unix-socket IPC to the actual `hyu-vpn-protocol` JSON shape: request schema v1 and response `schema_version`, `request_id`, `result` with `ack` and `status` variants. Old `ok/error_code/status` response handling is rejected.
- Removed load-bearing status-validation `|| true` shortcuts and added bounded monotonic polling for connected status/helper reconciliation.
- Strengthened test-root evidence from marker text to a 0600 owner-regular JSON document bound to canonical test root, DMG digest, mounted manifest digest, injection, timestamp, command contract, and result; live mode validates schema, mode, owner, age, root, and DMG digest.
- Added guarded cleanup/detach functions with a `/private/tmp/hyu-live-macos-rust.*` prefix guard, bounded detach retries, no generic `rm -rf`, and final cleanup failure propagation.
- Added nonce-dir validation and separate `hyu-install-mutation-EPOCH` nonces for root-admin uninstall/install invocations.
- Added no-Python/legacy category reporting and retained secret-safe audit behavior (no credential/log content reads).
- Physical Wi-Fi final gate now has explicit wait hooks for unhealthy/healthy/readiness and connected attempt within 10 seconds, rather than immediate off/on success printing.

## TDD evidence

### RED

Added fix-round-2 tests for exact Rust IPC protocol, production socket default, JSON-bound test-root evidence, cleanup temp-leak behavior, and static removal of protocol/cleanup placeholders. The first run failed on the old socket path, old `ok/error_code` IPC shape, marker evidence, and generic cleanup.

### GREEN / verification

- `python3 -m unittest -v tests.test_live_macos_rust_acceptance` → `Ran 12 tests ... OK`.
- Focused adjacent macOS gate: `python3 -m unittest -v tests.test_live_macos_rust_acceptance tests.test_macos_workflow tests.test_installer tests.test_launchd_config` → `Ran 75 tests in 147.586s ... OK`.
- Safe actual preflight with DMG: `scripts/live-macos-rust-acceptance.sh --mode preflight --dmg dist/macos/EZ-HYU-VPN-arm64.dmg` → exit 0, reran DMG acceptance, captured read-only route/DNS/internet/helper/credential metadata, state_changes=none.
- Safe marked test-root with DMG: `scripts/live-macos-rust-acceptance.sh --mode test-root --dmg dist/macos/EZ-HYU-VPN-arm64.dmg --test-root <marked temp root> --rollback-injection health --evidence-out <temp evidence>` → exit 0, targeted root-admin rollback unittest passed, evidence file mode `0600`, JSON bound to DMG SHA-256 `14675e18518ac65fa4c3f283c51893d653a909a6f860f0dc1aef104f523bd68b`.

## Boundaries

No real live mutation was run. Uninstall/reinstall and physical Wi-Fi remain opt-in live gates for the root agent/operator with user presence and fresh nonces.

---

# Task 9 Fix Round 3 Reviewer Findings

A. `phase_install_identity` must verify actual installed service/helper/menu executable hashes, modes, owners, launchd plist ProgramArguments/owner/mode, service health/IPC backend `0.2.0`, not mounted manifest values alone.
B. `phase_no_python_product_paths` must actually detect forbidden installed paths, Python launchd references, and Python product processes with bounded counts/categories only; negative residue fixtures must fail.
C. Owned reconnect must prove helper stop reaches stopped, reconnect produces a new helper pid and nonce with valid utun; same-generation fixtures must fail.
D. Service restart must prove launchctl kickstart preserves the same helper pid/nonce, connected state, and singleton service/menu; changed helper or duplicate fixtures must fail.
E. Uninstall/reinstall must use exact root-admin uninstall with fresh install nonce, verify product residue absent, then reinstall through verified GUI installer and rerun identity/no-Python/disconnected checks; fake root-admin must validate argv and state transitions.
F. Test-root must require DMG/test-root/evidence, build a test stage, invoke `installer/root-admin.sh --dry-run-root` with exact args and `HYU_VPN_FAIL_AFTER=health`, require injected failure/rollback proof, and bind JSON evidence to root/DMG/manifest/stage digests.
G. Physical Wi-Fi gate must poll until internet actually fails, then recovers, then observe backend/helper automatic transition within ten seconds; no immediate off/on success claim.
H. Tests must use executable fake commands/state mutations for A-G, including wrong hash, residue, same pid/nonce, changed helper on restart, invalid root args, and no offline transition failures.

## Fix Round 3 Implementation Evidence

Implemented reviewer findings A-H in script behavior and executable fixtures. No live install, privileged mutation, real helper stop/repair, VPN connection, uninstall/reinstall, launchctl mutation, or physical Wi-Fi change was executed by this agent.

### A-H checklist and executable proof map

- A install identity: `scripts/live-macos-rust-acceptance.sh` `phase_install_identity`, `verify_installed_file`, and `verify_launchd_plist` compare installed service/helper/menu hashes, modes, owners, direct Rust launchd ProgramArguments, and backend `0.2.0`. Negative proof: `tests/test_live_macos_rust_acceptance.py::test_round3_a_rejects_wrong_installed_service_hash` (line 466).
- B no Python/legacy residue: `phase_no_python_product_paths` checks exact forbidden app-support paths, launchd Python ProgramArguments, and bounded process categories with sanitized counts. Negative proof: `test_round3_b_rejects_legacy_python_residue_categories` (line 482).
- C owned reconnect: `phase_owned_openconnect_stop_reconnect` validates helper PID identity, uses helper `stop`, waits stopped, sends IPC reconnect, and requires new pid+nonce+utun. Negative proof: `test_round3_c_rejects_owned_reconnect_same_pid_nonce` (line 492).
- D service restart reconciliation: `phase_rust_service_restart_reconciliation` invokes exact `launchctl kickstart -k gui/$UID/com.hyu.vpn.service`, requires connected IPC status, singleton service/menu, and same helper generation. Negative proof: `test_round3_d_rejects_service_restart_changed_helper_generation` (line 499).
- E uninstall/reinstall: `phase_uninstall_residue_checks` requires `--exercise-uninstall-reinstall`, invokes root-admin uninstall with mounted payload/manifest and fresh `hyu-install-mutation-*`, verifies product residue absence, then reinstalls through the verified GUI installer and reruns identity/no-Python checks. Positive fake root-admin argv/state proof: `test_live_exercise_uninstall_reinstall_gate_invokes_uninstall_and_reinstall` (line 426).
- F test-root: `run_test_root` requires DMG and marked test root, invokes root-admin dry-root with `HYU_VPN_FAIL_AFTER=health`, payload/manifest/stage args and digests, runs the targeted rollback unittest, and writes 0600 JSON evidence bound to canonical root, DMG, manifest/stage digests, injection, timestamp, command contract, and result. Proof: `test_round3_e_test_root_invokes_exact_root_admin_dry_root_contract` (line 507) and `test_fix2_test_root_evidence_is_json_bound_to_dmg_manifest_and_mode_0600` (line 578).
- G physical Wi-Fi: `phase_physical_wifi_gate` remains final and opt-in, restores Wi-Fi on trap, waits for internet unhealthy then healthy, and observes backend/helper connected readiness within the bounded post-ready window. Negative proof: `test_round3_g_rejects_wifi_gate_when_internet_never_drops` (line 516); positive fake proof: `test_physical_wifi_gate_is_final_flagged_and_uses_exact_restore_trap_commands` (line 442).
- H executable fixtures: `Task9Fixture`, `IpcServer`, and fake `open`/`sudo`/`launchctl`/`networksetup`/`curl` mutate fixture state and validate command contracts rather than relying on string-only placeholder checks.

### Fix round 3 verification

- `bash -n scripts/live-macos-rust-acceptance.sh` → exit 0.
- `python3 -m py_compile tests/test_live_macos_rust_acceptance.py` → exit 0.
- `python3 -m unittest -v tests.test_live_macos_rust_acceptance` → `Ran 18 tests in 82.705s ... OK`.

Additional safe actual-Mac evidence for round 3:

- `scripts/live-macos-rust-acceptance.sh --mode preflight --dmg dist/macos/EZ-HYU-VPN-arm64.dmg` → exit 0; reran DMG acceptance; captured sanitized route/DNS/internet/helper/credential metadata; `state_changes=none`; DMG SHA-256 `14675e18518ac65fa4c3f283c51893d653a909a6f860f0dc1aef104f523bd68b`.
- `scripts/live-macos-rust-acceptance.sh --mode test-root --dmg dist/macos/EZ-HYU-VPN-arm64.dmg --test-root <marked temp root> --rollback-injection health --evidence-out <temp evidence>` → exit 0; targeted rollback harness passed; evidence file `0600`, result `rollback-proved`, same DMG SHA-256.
- `python3 -m unittest -v tests.test_live_macos_rust_acceptance tests.test_macos_workflow tests.test_installer tests.test_launchd_config` → `Ran 81 tests in 195.657s ... OK`; `git diff --check` initially flagged one trailing blank line, then report/checklist EOF whitespace was fixed.

---

# Task 9 Fix Round 4 Reviewer Findings

1. Test-root evidence must come from a real unprivileged `root-admin.sh --dry-run-root` execution against a staged native payload, not from live sudo or a fallback-only unittest. Expected proof is the `injected failure after health` marker, rollback journal completion, clean transaction state, no rollback residue, and 0600 JSON evidence bound to DMG/package/stage digests.
2. The physical Wi-Fi gate must run while connected and automatic reconnect is enabled, immediately after service restart reconciliation and before explicit disconnect; it must prove offline transition and automatic connected recovery without an explicit reconnect.
3. GUI installer launch must be bounded and must terminate only the owned `/usr/bin/open -W` process on timeout, then verify installed identity/IPC before continuing.

## Fix Round 4 Implementation Evidence

- Test-root: `run_test_root` now mounts the verified DMG, stages the mounted payload with `installer/manifest.py --stage-user-payload`, invokes the real `/bin/zsh installer/root-admin.sh --dry-run-root` unprivileged with a dry-root-confined allowlisted tools root, exact package/stage manifest digests, and `HYU_VPN_FAIL_AFTER=health`, requires the sanitized `injected failure after health` marker, explicitly rejects authentication-failure text, verifies `rollback-complete`, `transaction-state=complete`, and absence of key installed residues, then writes 0600 JSON evidence. Live mode recomputes the package and retained stage manifest hashes before accepting it. It never invokes live `sudo` for test-root. Negative proof: `test_round4_test_root_rejects_auth_failure_without_evidence` and `test_round4_live_rejects_stage_manifest_digest_tamper`.
- Wi-Fi ordering: `run_live` now places `phase_physical_wifi_gate` after `phase_rust_service_restart_reconciliation` and before `phase_disconnect_route_dns_restore`. The Wi-Fi phase requires connected status with `automatic_reconnect_enabled=true`, captures pid/nonce/transition, waits for internet drop and backend/helper offline transition, restores Wi-Fi, waits for internet recovery, then requires connected recovery with changed transition or helper generation and no explicit reconnect. Negative proof: `test_round4_wifi_gate_rejects_automatic_reconnect_disabled` plus existing no-offline-transition fixture.
- GUI installer: `run_installer_app` wraps `/usr/bin/open -W` with a bounded monotonic deadline, reports sanitized outcome only, and sends TERM/KILL only to the owned background `open` process on timeout. Both initial install identity and reinstall use this wrapper. Negative proof: `test_round4_bounded_gui_installer_timeout_fails`.

## Fix round 4 verification

- `python3 -m unittest -v tests.test_live_macos_rust_acceptance tests.test_macos_workflow tests.test_installer tests.test_launchd_config` → `Ran 85 tests in 222.127s ... OK` on August 12, 2026.
- Safe actual-Mac preflight with the local DMG passed before and after test-root execution: Google/GitHub/DNS all healthy, default route on `en0`, helper state unchanged at `repair-required`, no Rust service installed, and `state_changes=none`.
- Safe actual-Mac test-root proof passed with one exact `injected failure after health` marker, zero authentication-failure matches, one `rollback-complete`, `transaction-state=complete`, 0600 evidence, and a recomputed retained stage digest match. No live install or network mutation occurred in this round.
