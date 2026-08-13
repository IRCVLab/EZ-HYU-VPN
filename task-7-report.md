# Task 7 Fix Round 5 Code Review — APPROVE

Review scope: `1cfe6be..2fb7acf` / `.superpowers/sdd/2026-08-08-hyu-vpn-macos-rust-backend/review-task7-fix5.diff`, rechecking the single Fix Round 4 CRITICAL trust-boundary finding, transaction/recovery/uninstall branches, and the five earlier Fix Round 3 HIGH findings.

## Verdict

**APPROVE**

Fix round 5 removes the mutable `$STAGE`/`$PAYLOAD` native utility execution path from the privileged install phase. The root installer now creates a private `ROOT_NATIVE_TOOL` only from the package snapshot after package-manifest verification, and install-time fsync/helper parsing uses only that root/private package copy. A direct marker smoke confirmed that a tampered staged service is rejected without executing its `root-util fsync` code. I found no remaining load-bearing spec, security, or quality blockers in the scoped diff.

## Files Reviewed

3 changed files plus related installer/release context:

- `installer/root-admin.sh`
- `tests/test_installer.py`
- `task-7-report.md`

Additional context rechecked: Swift installer native staging path, release payload assembly/forbidden scanner, Rust `root-util` fsync/helper parser, HIP packaging, launchd template, rollback/recovery/uninstall branches.

## Severity Summary

- CRITICAL: 0
- HIGH: 0
- MEDIUM: 0
- LOW: 0

## Fix Round 4 CRITICAL Recheck

- **No mutable `$STAGE`/`$PAYLOAD` execution before verification:** fixed. `native_service_tools` no longer includes `$STAGE/bin/hyu-vpn-macos-service` or `$PAYLOAD/hyu-vpn-macos-service`; install action returns only `ROOT_NATIVE_TOOL` (`installer/root-admin.sh:210-215`). `ROOT_NATIVE_TOOL` is populated from `$PACKAGE_SNAPSHOT/hyu-vpn-macos-service` only after package manifest digest and package snapshot hash verification (`installer/root-admin.sh:410-422`). Stage digest/manifest/package-match verification still gates install before privileged destination mutations (`installer/root-admin.sh:439-442`, `installer/root-admin.sh:510-525`).
- **No unverified installed-service fallback during install:** fixed. The installed service candidate is allowed only outside install action, and is constrained by `trusted_native_tool` to the canonical installed path, non-symlink executable, non-group/world-writable mode, and root ownership in live mode (`installer/root-admin.sh:194-218`). Install-time health still runs the newly installed service only after files are copied/chowned/rendered and before commit (`installer/root-admin.sh:525-534`).
- **Real fsync remains:** retained. `durable_flush` still invokes `root-util fsync` through the trusted native tool once available (`installer/root-admin.sh:221-239`), and Rust `root-util fsync` tests pass. Early pre-snapshot journal/state writes intentionally do not execute any native tool when no trusted tool exists, avoiding the prior trust-boundary bug before any privileged destination mutation.
- **Strict helper parsing remains:** retained. `helper_state` / `helper_repair_nonce` still route helper status through the trusted Rust `root-util helper-state` / `helper-repair-nonce` parser (`installer/root-admin.sh:250-260`), and targeted parser tests pass.
- **Recovery/uninstall branch trust:** acceptable in scoped review. Rollback/recovery during install uses the root/private package tool when present and does not fall back to stage/payload. Uninstall may use `ROOT_NATIVE_TOOL` or the canonical installed service, but only after `trusted_native_tool` checks path, symlink, mode, and live root ownership (`installer/root-admin.sh:194-218`); no `$STAGE`/`$PAYLOAD` fallback remains.

## Previous HIGH Finding Recheck

1. **Production Swift installer Python-free / payload graph consistent:** remains fixed. `HYUVPNInstallerApp` uses native Swift manifest verification/staging, while release packaging ships `installer/root-admin.sh` but not `installer/manifest.py`; grep found only scanner token constants in `scripts/release_packaging.py`.
2. **Root immutable package binding:** fixed. The root transaction reconstructs from `$PACKAGE_SNAPSHOT`, compares staged-vs-package hashes, and now avoids executing the stage service before those checks. Regenerated-stage and payload-mutation regressions pass.
3. **Durable fsync:** fixed without returning to the prior unsafe stage execution. Rust root-util fsync tests pass.
4. **Strict helper status parsing:** fixed. Rust root-util parser tests pass.
5. **Functional packaged native HIP:** remains fixed. `hyu-vpn-hip` macOS CLI test passes; packaging path remains the Rust HIP binary rather than the deleted static stub.

## Validation Evidence

- `git diff --check 1cfe6be..2fb7acf` → pass.
- Focused trust/transaction tests: `python3 -m unittest -v tests.test_installer.RootAdminShellHarnessTests.test_tampered_stage_service_cannot_execute_root_util_before_rejection tests.test_installer.RootAdminShellHarnessTests.test_regenerated_stage_manifest_is_rejected_by_locked_package_payload tests.test_installer.RootAdminShellHarnessTests.test_payload_concurrent_change_after_user_stage_is_rejected_by_package_manifest tests.test_installer.RootAdminShellHarnessTests.test_root_admin_bootstraps_with_exact_admin_health_cli_then_commits_before_menu_boundary tests.test_installer.RootAdminShellHarnessTests.test_root_admin_real_health_cli_failure_rolls_back_and_recover_is_idempotent tests.test_installer.RootAdminShellHarnessTests.test_root_admin_static_security_contracts` → **Ran 6 tests in 9.102s, OK**.
- Independent marker smoke: tampered `stage/bin/hyu-vpn-macos-service` exited with `hash mismatch: bin/hyu-vpn-macos-service`, and marker existence was `False`.
- Focused Task 7 gate: `python3 -m unittest -v tests.test_packaging tests.test_installer tests.test_launchd_config tests.test_macos_workflow` → **Ran 111 tests in 105.280s, OK**.
- Static/syntax gates: `python3 -m py_compile installer/manifest.py scripts/release_packaging.py scripts/package-release.py tests/test_installer.py tests/test_macos_workflow.py tests/test_packaging.py`, `/bin/zsh -n installer/root-admin.sh`, `bash -n scripts/package-macos.sh`, `plutil -lint launchd/com.hyu.vpn.service.plist.in`, `cargo fmt --all -- --check` → pass.
- Targeted Rust gates: `cargo test --locked -p hyu-vpn-macos-service --all-targets root_util -- --nocapture` → **2 passed**; `cargo test --locked -p hyu-vpn-macos-service --all-targets health_cli -- --nocapture` → **2 passed**; `cargo test --locked -p hyu-vpn-hip --all-targets -- --nocapture` → macOS HIP CLI test passed.
- Relevant Rust suite: `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-hip --all-targets` → pass.
- Rust lint: `cargo clippy --locked -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-hip --all-targets -- -D warnings` → pass.
- Swift gates: `swift test --package-path macos --no-parallel` → exit 0; `swift run --package-path macos hyu-vpn-installer-harness </dev/null` → `HARNESS PASS hyu-vpn-installer-harness`.

`lsp_diagnostics` / `ast_grep_search` tools are not available in this execution surface; I substituted compile, syntax, lint, static grep, direct trust smoke, focused tests, Swift package checks, and relevant Rust suites.

## Recommendation

**APPROVE.** No load-bearing findings remain in the scoped Fix Round 5 review. Do not interpret this as release/publish approval; no live install, sudo mutation, signing identity, notarization, VPN connection, or external artifact publication was performed.

# Task 7 Fix Round 4 Code Review — REQUEST CHANGES

Review scope: `2de2822..1cfe6be` / `.superpowers/sdd/2026-08-08-hyu-vpn-macos-rust-backend/review-task7-fix4.diff`, rechecking the Task 7 brief/design/plan, Task 1 gates, installer transaction/security design, Rust service/Swift IPC paths, release packaging, and all five Fix Round 3 HIGH findings.

## Verdict

**REQUEST CHANGES**

Fix round 4 resolves several prior structural blockers (Swift production staging is now native/Python-free, helper status parsing uses the Rust schema-v1 parser, and the static HIP stub is replaced by a packaged Rust HIP binary), but it introduces a load-bearing trust-boundary regression: the privileged root installer can execute the mutable user-stage `bin/hyu-vpn-macos-service` for `root-util fsync` before verifying the stage manifest or binding the stage to the immutable package payload. A direct smoke proved a tampered staged service runs before the installer later rejects it.

## Files Reviewed

21 changed files plus related context:

- `.github/workflows/macos.yml`
- `Cargo.lock`
- `bin/gp-hip-report-native`
- `installer/root-admin.sh`
- `macos/Sources/HYUVPNInstallerApp/main.swift`
- `macos/Sources/HYUVPNInstallerCore/InstallerCore.swift`
- `macos/Tests/HYUVPNInstallerCoreTests/HYUVPNInstallerCoreTests.swift`
- `macos/Tests/HYUVPNInstallerHarness/main.swift`
- `rust/apps/hyu-vpn-hip/src/lib.rs`
- `rust/apps/hyu-vpn-hip/src/main.rs`
- `rust/apps/hyu-vpn-hip/tests/macos_cli.rs`
- `rust/apps/hyu-vpn-macos-service/Cargo.toml`
- `rust/apps/hyu-vpn-macos-service/src/main.rs`
- `rust/apps/hyu-vpn-macos-service/tests/root_util.rs`
- `scripts/package-macos.sh`
- `scripts/package-release.py`
- `scripts/release_packaging.py`
- `task-7-report.md`
- `tests/test_installer.py`
- `tests/test_macos_workflow.py`
- `tests/test_packaging.py`

Additional context read: Task 7 brief/design/report history, launchd template, Rust helper status parser, release/mounted validation paths, Swift installer harness.

## Severity Summary

- CRITICAL: 1
- HIGH: 0
- MEDIUM: 0
- LOW: 0

## Findings

### [CRITICAL] Root installer executes the mutable user-stage service before verifying stage/package trust

**Files:** `installer/root-admin.sh:194-207`, `installer/root-admin.sh:220-225`, `installer/root-admin.sh:388-415`

**Issue:** `native_service_tools` includes `$STAGE/bin/hyu-vpn-macos-service` (`installer/root-admin.sh:194-198`), and `durable_flush` executes the first available tool as `"$tool" root-util fsync "$target"` (`installer/root-admin.sh:200-207`). Those flushes run during transaction-state/journal setup (`installer/root-admin.sh:220-225`) before `copy_package_snapshot` verifies the package manifest, verifies the staged manifest, and compares staged files to package payload hashes (`installer/root-admin.sh:388-415`).

A direct smoke tampered `stage/bin/hyu-vpn-macos-service` after user staging without updating `stage/manifest.json`, made its `root-util fsync` path write a marker, then invoked `root-admin.sh`. The installer exited non-zero later with `hash mismatch: bin/hyu-vpn-macos-service`, but the marker was already created:

```text
exit 1
stderr-head ['hash mismatch: bin/hyu-vpn-macos-service']
marker /var/folders/.../hyu-fix4-preverify-marker-* True
```

That proves the mutable staged binary executes before the trust check that is supposed to reject it. In production the same script runs under the administrator/root phase, so this is a root/admin code-execution boundary, not just a test-order issue.

**Risk:** A local attacker who can alter the user-created stage between native staging and privileged root installation can execute arbitrary code via the staged service's `root-util fsync` implementation before the root installer rejects the tampered stage. This bypasses the Task 7 requirement that root installation bind to the locked package binary/hash before executing staged artifacts.

**Fix:** Never execute `$STAGE/bin/hyu-vpn-macos-service` before stage/package verification. Remove `$STAGE` from the pre-verification `native_service_tools` search path, or defer all fsync/helper-parser calls until a trusted `$TXN_SNAPSHOT/bin/hyu-vpn-macos-service` has been reconstructed from a verified package snapshot. If fsync must happen before the snapshot exists, use a trusted system/native path that is not sourced from the mutable user stage, or first verify the package manifest and copy only the package service into a root-owned private snapshot before any execution. Add a regression that tampers the stage service after staging and asserts no marker/side effect occurs before the hash mismatch.

## Prior Finding Recheck

1. **Production Swift installer Python-free / payload graph consistent:** fixed structurally. `macos/Sources/HYUVPNInstallerApp/main.swift:173-180` now calls `NativePayloadManifest.verify` and `NativePayloadManifest.stage`; `scripts/release_packaging.py:62-75`/`:850-858` no longer require or ship `installer/manifest.py`; static grep shows no `/usr/bin/python3` or `manifest.py` references in production Swift/root installer code (only release scanner token constants remain in `scripts/release_packaging.py`).
2. **Root binds immutable package binary/hash and rejects regenerated mutable stage:** partially fixed but unsafe. `copy_package_snapshot` now rebuilds `$TXN_SNAPSHOT` from `$PAYLOAD` and compares staged-vs-package hashes (`installer/root-admin.sh:388-415`), and focused tests reject regenerated stage/payload mutation. However, the CRITICAL finding above means root still executes the mutable stage service before those checks run.
3. **Durable fsync is real:** functionally restored but not safe. `durable_flush` now invokes Rust `root-util fsync` (`installer/root-admin.sh:200-207`) and Rust implements `fsync_path` with `sync_all` (`rust/apps/hyu-vpn-macos-service/src/main.rs:93-140`), but the pre-verification tool selection uses the untrusted stage binary.
4. **Helper status parsing strict exact schema-v1:** fixed. `root-admin.sh` routes helper status through `root-util helper-state` / `helper-repair-nonce` (`installer/root-admin.sh:227-238`), and the Rust utility uses the existing strict schema-v1 parser with bounded stdin (`rust/apps/hyu-vpn-macos-service/src/main.rs:93-177`). Targeted tests reject missing schema, extra keys, invalid tunnel values, and multiline status.
5. **HIP replacement functional and packaged/signed/arch-checked:** fixed for the prior static-stub blocker. `bin/gp-hip-report-native` is deleted, `scripts/package-macos.sh` builds/passes `hyu-vpn-hip`, `scripts/release_packaging.py:840-858` packages it as `runtime/gp-hip-report`, CI validates the mounted HIP artifact, and `rust/apps/hyu-vpn-hip/src/lib.rs:144-204` generates macOS HIP XML with identity fields and XML escaping. Targeted HIP tests pass and assert no cookie leakage.

## Validation Evidence

- `git diff --check 2de2822..1cfe6be` → pass.
- `python3 -m unittest -v tests.test_packaging tests.test_installer tests.test_launchd_config tests.test_macos_workflow` → **Ran 110 tests in 99.051s, OK**.
- Static/syntax gates: `python3 -m py_compile installer/manifest.py scripts/release_packaging.py scripts/package-release.py tests/test_installer.py tests/test_macos_workflow.py tests/test_packaging.py`, `/bin/zsh -n installer/root-admin.sh`, `bash -n scripts/package-macos.sh`, `plutil -lint launchd/com.hyu.vpn.service.plist.in`, `cargo fmt --all -- --check` → pass (`launchd/...: OK`).
- Targeted Rust root/health/HIP tests: `cargo test --locked -p hyu-vpn-hip --all-targets -- --nocapture` → HIP macOS CLI test passed; `cargo test --locked -p hyu-vpn-macos-service --all-targets root_util -- --nocapture` → **2 passed**; `cargo test --locked -p hyu-vpn-macos-service --all-targets health_cli -- --nocapture` → **2 passed**.
- Relevant Rust suite: `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → pass, including service runtime/helper/platform tests.
- Rust lint: `cargo clippy --locked -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-hip --all-targets -- -D warnings` → pass.
- Swift gates: `swift test --package-path macos --no-parallel` → exit 0; `swift run --package-path macos hyu-vpn-installer-harness </dev/null` → `HARNESS PASS hyu-vpn-installer-harness`.
- Direct pre-verification execution smoke: tampered staged service wrote a marker during `root-util fsync` before the root script failed with `hash mismatch: bin/hyu-vpn-macos-service`.

`lsp_diagnostics` / `ast_grep_search` tools are not available in this execution surface; I substituted compile, syntax, lint, static grep, direct exploit smoke, focused tests, Swift package checks, and relevant Rust suites.

## Recommendation

**REQUEST CHANGES.** Do not approve until the root/admin phase stops executing any mutable user-stage binary before the stage/package trust checks complete and regression coverage proves a tampered staged service cannot produce side effects before rejection.

# Task 7 Fix Round 3 Code Review — REQUEST CHANGES

Review scope: `f9332e4..2de2822` / `.superpowers/sdd/2026-08-08-hyu-vpn-macos-rust-backend/review-task7-fix3.diff` only, with the Task 7 brief/design, prior Task 7 findings, installer transaction/security design, current Rust health CLI, Swift installer, release packaging, mounted scanner, and native HIP runtime path rechecked.

## Verdict

**REQUEST CHANGES**

Fix round 3 correctly adds rollback tracking for the bootstrapped LaunchAgent and expands the forbidden-token scanner, but it introduces new load-bearing regressions: the shipped installer no longer contains a file the Swift installer still requires and still executes via `/usr/bin/python3`; the root transaction now trusts the mutable user stage instead of the locked package payload; transaction durability flushing was replaced by a no-op; helper status JSON validation was downgraded to regex/sed extraction; and the packaged HIP helper was replaced by a static XML stub rather than a functional native HIP collector.

## Files Reviewed

9 changed files:

- `.github/workflows/macos.yml`
- `bin/gp-hip-report-native`
- `installer/root-admin.sh`
- `packaging/README-lab.md`
- `scripts/release_packaging.py`
- `task-7-report.md`
- `tests/test_installer.py`
- `tests/test_macos_workflow.py`
- `tests/test_packaging.py`

Additional context read: `macos/Sources/HYUVPNInstallerApp/main.swift`, `bin/gp-hip-report`, Task 7 brief/design, launchd template, Rust service health implementation.

## Severity Summary

- CRITICAL: 0
- HIGH: 5
- MEDIUM: 0
- LOW: 0

## Findings

### [HIGH] Release payload omits `installer/manifest.py` while the production Swift installer still requires and runs it with `/usr/bin/python3`

**Files:** `scripts/release_packaging.py:62-72`, `scripts/release_packaging.py:848-852`, `macos/Sources/HYUVPNInstallerApp/main.swift:173-181`

**Issue:** Fix3 removes `installer/manifest.py` from `REQUIRED_PAYLOAD_FILES` and from `assemble_payload_from_repo`, but the production installer still does:

- `requireFile(".../installer/manifest.py")`
- `run(["/usr/bin/python3", ".../installer/manifest.py", ... "--verify-manifest"])`
- `run(["/usr/bin/python3", ".../installer/manifest.py", ... "--stage-user-payload"])`

So the assembled DMG is internally inconsistent: the installer app expects a shipped verifier/stager that the release builder no longer ships. This also means the production install path still contains direct `/usr/bin/python3`, contrary to the fix3 goal and mounted-scan intent.

**Risk:** A release artifact built from this change will fail before the root transaction (`installer/manifest.py` missing), or if the file is restored later, the production installer will still execute Python despite the claimed no-Python contract.

**Fix:** Move manifest verification/staging into Swift/Rust/shell that is actually shipped, or keep `installer/manifest.py` in the payload and explicitly document/allow it. Do not remove the file from packaging until `HYUVPNInstallerApp` no longer requires or executes it. Add a mounted-artifact test that launches the installer harness against the assembled payload layout and fails when required resources are absent.

### [HIGH] Root transaction no longer stages/verifies the exact locked package payload; tests now bless a regenerated user-stage service replacement

**Files:** `installer/root-admin.sh:349-359`, `tests/test_installer.py:580-608`

**Issue:** `copy_package_snapshot` no longer copies the locked package payload and re-stages it under root. It verifies only the top package manifest digest, copies `$STAGE` into `$TXN_SNAPSHOT`, and validates the stage manifest. The tests were changed to assert that a regenerated staged `bin/hyu-vpn-macos-service` is installed successfully (`"preverified replacement service"`). A direct smoke reproduced this: with a modified staged service and regenerated stage manifest/digest, root install exited 0 and installed the replacement service text.

**Risk:** This violates Task 7’s requirement that packaging/root install stage the exact release-built Rust service binary and exact manifest/hash. It reopens the user-stage trust boundary that the previous root package snapshot was designed to close. Root should not install a service binary merely because the user-stage manifest was regenerated; it should bind installation to the immutable package manifest and package file hashes.

**Fix:** Restore a root-owned package snapshot from the package payload and verify every package file against `manifest.json` before staging/installing, or implement an equivalent non-Python verifier. The root phase should reject a regenerated user-stage binary even if the stage manifest digest matches a new stage manifest. Restore regression coverage that mutating `stage/bin/hyu-vpn-macos-service` plus regenerating the stage manifest cannot override the package service.

### [HIGH] Transaction durability/fsync contract was removed

**File:** `installer/root-admin.sh:194`

**Issue:** `durable_flush` was replaced with a no-op (`durable_flush(){ :; }`). This function is still called around transaction-state, journal, path ledger, manifest, and backup writes, but now none of those writes are fsynced.

**Risk:** Task 7 explicitly calls for rollback/crash-window safety. Without durable flushing, a crash or power loss can lose `install-pending`, `txn-paths`, backup ledgers, or `complete`/`commit` markers after filesystem mutations have happened. That can prevent preinstall recovery from knowing what to restore or can falsely mark an incomplete transaction as complete.

**Fix:** Restore durable file and parent-directory fsync using a non-Python implementation (`/usr/bin/perl` is not an improvement if Python is forbidden; prefer a small shipped Rust helper/mode or carefully scoped native tool) or redesign the transaction to not claim crash durability. Add crash-window tests/contract checks that fail if `durable_flush` is a no-op.

### [HIGH] Helper status validation was downgraded from strict schema-v1 JSON to regex extraction

**Files:** `installer/root-admin.sh:203-218`

**Issue:** `helper_state` and `helper_repair_nonce` no longer parse JSON or enforce `schema_version == 1`. They extract the first matching `"state"` or `"session_nonce"` with `sed`/`grep`, accepting documents that are not valid schema-v1 helper status.

**Risk:** The installer’s stop/drain/repair safety depends on real helper status. A malformed, truncated, or non-schema helper response can now be treated as `stopped`/`repair-required`, allowing upgrade or repair cleanup to proceed with false evidence. This is the same masking-pattern class the review policy rejects: passing tests by weakening the primary contract instead of replacing Python JSON parsing with an equivalent strict parser.

**Fix:** Replace Python with an equivalent strict parser, not regex. Options: add a Rust status-validation helper/mode, use existing helper status contract in Swift/Rust, or constrain shell parsing to exact one-line JSON fields with schema, allowed keys, and nonce validation. Add tests proving missing schema, duplicate/extra malformed fields, multi-line output, and embedded fake `state` strings are rejected.

### [HIGH] Packaged HIP replacement is a static stub, not a functional native HIP collector

**Files:** `bin/gp-hip-report-native:1-5`, `scripts/release_packaging.py:852`

**Issue:** The release assembler now packages `bin/gp-hip-report-native` as `runtime/gp-hip-report`. That script always prints:

`<hip-report>...domain unknown...</hip-report>`

It does not consume OpenConnect HIP environment/context, include cookie identity/client addresses, collect macOS posture, preserve the native HIP XML shape, or run the existing sanitized HIP logic. Existing HIP tests still exercise the old Python `bin/gp-hip-report`, not the newly packaged replacement.

**Risk:** The shipped VPN connector can fail HIP authentication or send an incomplete/incorrect posture report. This is not a secure native replacement; it is a broad stub that masks the production Python removal by shipping nonfunctional behavior.

**Fix:** Implement a real native HIP reporter with parity tests against the existing sanitized/native-shape fixtures and OpenConnect invocation contract, or keep the existing HIP reporter until an equivalent replacement is ready and explicitly allowed by the packaging contract. Add packaging tests that execute the exact packaged `runtime/gp-hip-report` with fixture HIP environment and compare the expected sanitized native-shape XML.

## Prior Finding Recheck

1. **Rollback tracks bootstrap / bootout before restore:** improved. `ROOT_SERVICE_BOOTSTRAPPED` is set after kickstart and rollback calls bootout before file removal/restoration. Tests cover bootout failure blocking rollback completion. This specific prior blocker is fixed in structure.
2. **No production Python / scanner evasion:** not fixed. `root-admin.sh` no longer contains Python execution, but `HYUVPNInstallerApp` still requires and runs `/usr/bin/python3 installer/manifest.py`, while packaging removed that file.
3. **Real health CLI:** remains fixed. The Rust health CLI still uses the status-only framed schema-v1 health check and targeted tests pass.
4. **Mach-O service signing/validation:** remains fixed from fix2; service remains a mounted arch/signature target.
5. **Destination guards:** mostly retained; shell guard covers live `/` traversal without Python. No new live guard blocker found.
6. **Mounted scanner detects split tokens:** improved for literal/split text files, but it misses the Swift binary/source path because app Mach-O files are intentionally excluded and `main.swift` is not in the mounted payload as text. The scanner therefore cannot prove production installer Python absence by itself.

## Validation Evidence

- `git diff --check f9332e4..2de2822` → pass.
- Focused Task 7 gate: `python3 -m unittest -v tests.test_packaging tests.test_installer tests.test_launchd_config tests.test_macos_workflow` → **Ran 110 tests, OK**.
- Syntax/static: `python3 -m py_compile ...`, `/bin/zsh -n installer/root-admin.sh`, `plutil -lint launchd/com.hyu.vpn.service.plist.in`, `cargo fmt --all -- --check` → pass.
- Health CLI targeted Rust tests: `cargo test --locked -p hyu-vpn-macos-service --all-targets health_cli -- --nocapture` → **2 passed**.
- Framed health targeted Rust tests: `cargo test --locked -p hyu-vpn-macos-service --test service_runtime health_check -- --nocapture` → **4 passed**.
- Relevant Rust suite: `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → pass.
- Rust lint: `cargo clippy -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets -- -D warnings` → pass.
- Swift package: `swift test --package-path macos --no-parallel` → command exited 0.
- Full Python non-live suite: `python3 -m unittest discover -s tests -p 'test_*.py' -v` → **Ran 410 tests, OK (skipped=1)**.
- Direct proof: grep shows `macos/Sources/HYUVPNInstallerApp/main.swift` still contains `/usr/bin/python3` and `manifest.py`; direct staged-service replacement smoke installs the replacement when the stage manifest/digest is regenerated; `bin/gp-hip-report-native` outputs only the static unknown-domain XML.

`lsp_diagnostics` / `ast_grep_search` tools are not available in this execution surface; I substituted compile, syntax, lint, static greps, direct smokes, and targeted/full test gates.

## Recommendation

**REQUEST CHANGES.** Do not approve until the shipped installer/resource graph is internally consistent and genuinely Python-free (or the exception is explicit), root install again binds to the locked package binary/hash, transaction durability is restored, helper status parsing is strict schema-v1, and the packaged HIP reporter is a real functional replacement rather than a static stub.

# Task 7 Fix Round 4 Implementation Report

## Scope
Addressed all five HIGH fix3 findings without live install, sudo mutation, VPN connection, or network mutation. Production installer code no longer invokes Python; Python remains only in repository tests/tools.

## RED Evidence Captured
- Added root package/stage trust-boundary regressions, then ran:
  `python3 -m unittest -v tests.test_installer.RootAdminShellHarnessTests.test_regenerated_stage_manifest_is_rejected_by_locked_package_payload tests.test_installer.RootAdminShellHarnessTests.test_payload_concurrent_change_after_user_stage_is_rejected_by_package_manifest tests.test_installer.RootAdminShellHarnessTests.test_root_admin_static_security_contracts`
  - Initial result: `FAILED (failures=2)`; mutated regenerated stage was still not rejected cleanly and payload/stage verification still failed for the old reasons.
- Added native fsync/helper parser Rust utility tests and first ran with `--locked`:
  `cargo test --locked -p hyu-vpn-macos-service --test root_util -- --nocapture`
  - Initial result: lock/package metadata failure before implementation dependency metadata was updated, proving the new utility test path was not yet buildable.
- Added Swift/native installer and packaging assertions, then ran the focused Task 7 Python gate:
  `python3 -m unittest -v tests.test_packaging tests.test_installer tests.test_macos_workflow`
  - Initial result: `FAILED (failures=5)`, including stale Python manifest expectations, stage tamper executing the mutable stage utility, strict helper status fixture mismatches, and macOS workflow not yet including the HIP binary.

## Changes Made
- `macos/Sources/HYUVPNInstallerApp/main.swift` and `macos/Sources/HYUVPNInstallerCore/InstallerCore.swift`
  - Replaced production `installer/manifest.py` / `/usr/bin/python3` manifest verification and user staging with native Swift manifest verification and staging.
  - Kept root authorization argv unchanged except for using the natively-created stage and digest.
- `installer/root-admin.sh`
  - Restored root-owned package snapshot verification against the immutable package manifest and added stage-vs-package hash binding for mapped installer files.
  - Restored durable flush through a native shipped Rust utility (`hyu-vpn-macos-service root-util fsync`) for files and parent directories.
  - Replaced regex/sed helper status state parsing with `hyu-vpn-macos-service root-util helper-state` / `helper-repair-nonce`, which use the existing strict schema-v1 Rust parser.
- `rust/apps/hyu-vpn-macos-service/*`
  - Added `root-util fsync`, `root-util helper-state`, and `root-util helper-repair-nonce` subcommands plus regression tests for real fsync invocation and strict helper JSON rejection.
- `rust/apps/hyu-vpn-hip/*`, `scripts/package-macos.sh`, `scripts/package-release.py`, `scripts/release_packaging.py`, `.github/workflows/macos.yml`
  - Removed static `bin/gp-hip-report-native` stub and package the built Rust `hyu-vpn-hip` binary as `runtime/gp-hip-report`.
  - Added a macOS HIP generation path with identity parsing, XML escaping, Apple/macOS native-shape fields, client IP/IPv6/app-version fields, and no cookie leakage.
  - Added Mach-O arch/signature mounted validation for `runtime/gp-hip-report`.
- `tests/test_installer.py`, `tests/test_packaging.py`, `tests/test_macos_workflow.py`, Swift installer tests/harnesses
  - Added/updated regressions for Python-free native installer staging, immutable package binding, native fsync/parser contracts, HIP packaging, and CI/package graph consistency.

## Verification Evidence
- `python3 -m unittest -v tests.test_packaging tests.test_installer tests.test_macos_workflow` → `Ran 105 tests ... OK`.
- `swift test --package-path macos --no-parallel` → exit 0, build/test completed.
- `cargo fmt --all -- --check` → exit 0.
- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-hip --all-targets` → exit 0; includes `hyu-vpn-hip` macOS HIP test and `hyu-vpn-macos-service` root utility tests.
- `cargo clippy --locked -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-hip --all-targets -- -D warnings` → exit 0.
- `python3 -m py_compile scripts/release_packaging.py scripts/package-release.py installer/manifest.py tests/test_installer.py tests/test_packaging.py tests/test_macos_workflow.py` → exit 0.
- `/bin/zsh -n installer/root-admin.sh` and `bash -n scripts/package-macos.sh` → exit 0.
- `swift run --package-path macos hyu-vpn-installer-harness </dev/null` → `HARNESS PASS hyu-vpn-installer-harness`.
- `python3 -m unittest discover -s tests -p 'test_*.py' -v` → `Ran 410 tests ... OK (skipped=1)`.
- Static check: `grep -R "/usr/bin/python3\|manifest.py" -n macos/Sources/HYUVPNInstallerApp scripts/release_packaging.py scripts/package-macos.sh installer/root-admin.sh` shows no production Swift/root installer Python invocation; only release scanner token constants mention Python strings.

## Notes / Remaining Boundaries
- No live install, administrator authorization, launchctl mutation outside dry roots, VPN connection, route/DNS mutation, signing identity, notarization, or external artifact publishing was performed.
- `installer/manifest.py` is retained as a repository test/helper compatibility module, but production installer app and root transaction no longer execute it.

# Task 7 Fix Round 5 Implementation Report

## Scope
Addressed the single CRITICAL fix4 finding in the macOS root installer trust boundary. No live install, administrator authorization, launchctl mutation outside dry roots, VPN connection, route/DNS mutation, signing identity, notarization, or external artifact publishing was performed.

## RED Evidence Captured
- Added `RootAdminShellHarnessTests.test_tampered_stage_service_cannot_execute_root_util_before_rejection`, which tampers `stage/bin/hyu-vpn-macos-service` so its `root-util fsync` writes a marker before exiting successfully.
- Initial RED run before the fix:
  `python3 -m unittest -v tests.test_installer.RootAdminShellHarnessTests.test_tampered_stage_service_cannot_execute_root_util_before_rejection`
  - Result: `FAILED`; assertion showed the marker existed, proving the mutable user-stage service executed before the later `hash mismatch: bin/hyu-vpn-macos-service` rejection.

## Changes Made
- `installer/root-admin.sh`
  - Removed all `$STAGE/bin/hyu-vpn-macos-service` and `$PAYLOAD/hyu-vpn-macos-service` native utility candidates.
  - Added a root/private `ROOT_NATIVE_TOOL_DIR` and `ROOT_NATIVE_TOOL` under the installer state directory.
  - After copying and verifying the immutable package snapshot against the package manifest, copies only `$PACKAGE_SNAPSHOT/hyu-vpn-macos-service` into that root/private native-tool path and uses it for install-time `root-util fsync` and helper status parsing.
  - During install, `native_service_tools` returns only the verified root-native package copy; it does not fall back to pre-existing app-support service binaries before package/stage trust checks.
  - Retains the trusted native tool through commit/complete journal durability, then removes the temporary native-tool directory.
- `tests/test_installer.py`
  - Added the pre-verification stage-service side-effect regression.
  - Extended static root-admin contracts to assert the stage/payload service paths are absent from native tool selection and the root-native tool path is present.

## Verification Evidence
- RED before implementation: `python3 -m unittest -v tests.test_installer.RootAdminShellHarnessTests.test_tampered_stage_service_cannot_execute_root_util_before_rejection` → failed with marker present before rejection.
- Focused regression after implementation: `python3 -m unittest -v tests.test_installer.RootAdminShellHarnessTests.test_tampered_stage_service_cannot_execute_root_util_before_rejection tests.test_installer.RootAdminShellHarnessTests.test_root_admin_bootstraps_with_exact_admin_health_cli_then_commits_before_menu_boundary tests.test_installer.RootAdminShellHarnessTests.test_root_admin_real_health_cli_failure_rolls_back_and_recover_is_idempotent` → `Ran 3 tests ... OK`.
- Static contract regression: `python3 -m unittest -v tests.test_installer.RootAdminShellHarnessTests.test_root_admin_static_security_contracts tests.test_installer.RootAdminShellHarnessTests.test_tampered_stage_service_cannot_execute_root_util_before_rejection` → `Ran 2 tests ... OK`.
- Focused Task 7 Python gate: `python3 -m unittest -v tests.test_packaging tests.test_installer tests.test_macos_workflow` → `Ran 106 tests in 117.952s ... OK`.
- Syntax/static: `/bin/zsh -n installer/root-admin.sh`, `python3 -m py_compile tests/test_installer.py installer/manifest.py scripts/release_packaging.py scripts/package-release.py`, `git diff --check` → exit 0.
- Rust targeted/native utility and HIP gates: `cargo fmt --all -- --check`; `cargo test --locked -p hyu-vpn-macos-service --all-targets root_util -- --nocapture` → root util tests `2 passed`; `cargo test --locked -p hyu-vpn-hip --all-targets -- --nocapture` → macOS HIP CLI test passed.
- Rust relevant suite: `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-hip --all-targets` → exit 0, all listed package tests passed.
- Rust lint: `cargo clippy --locked -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-hip --all-targets -- -D warnings` → exit 0.
- Swift gates: `swift test --package-path macos --no-parallel` → exit 0; `swift run --package-path macos hyu-vpn-installer-harness </dev/null` → `HARNESS PASS hyu-vpn-installer-harness`.
- Full Python non-live suite: `python3 -m unittest discover -s tests -p 'test_*.py' -v` → `Ran 411 tests in 144.576s ... OK (skipped=1)`.
- Static grep: `grep -n 'native_service_tools\|ROOT_NATIVE_TOOL\|STAGE/bin/hyu-vpn-macos-service\|PAYLOAD/hyu-vpn-macos-service' installer/root-admin.sh` shows only `ROOT_NATIVE_TOOL`/native tool setup and no stage/payload service execution candidates.

## Notes / Remaining Boundaries
- The initial transaction-state write before package verification has no native tool and therefore does not execute any staged/payload binary. Once the verified root-private package tool exists, subsequent journal/ledger/state flushes use the native Rust fsync path.
- Uninstall/recovery may use an already installed app-support service only when it passes the trusted tool checks; install-time execution is restricted to the verified root-native package copy.
