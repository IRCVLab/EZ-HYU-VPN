# Task 8 Implementation Report

## Scope
Built and inspected the macOS arm64 DMG without installing it, without administrator authorization, without launching the installer, and without mutating launchd, routes, DNS, or network state.

## RED Evidence Captured
- Added RED tests in `tests/test_macos_workflow.py` requiring the standalone `scripts/macos-dmg-acceptance.sh` gate and its read-only/bounded DMG checks.
- Initial RED run before implementation:
  `python3 -m unittest -v tests.test_macos_workflow`
  - Result: `FAILED (failures=2)` because `scripts/macos-dmg-acceptance.sh` did not exist.

## Changes Made
- `scripts/macos-dmg-acceptance.sh`
  - Added a repeatable non-installing DMG acceptance gate.
  - Runs `hdiutil verify`, attaches with `hdiutil attach -readonly -nobrowse` to a fresh `/private/tmp/hyu-vpn-dmg-acceptance.XXXXXX` mount, and traps clean detach.
  - Verifies exact mounted manifest file set plus SHA-256, size, and mode identity.
  - Verifies deep/strict ad-hoc signatures and exact arm64 architecture for the menu app executable, installer app executable, Rust service, privileged helper, and packaged Rust HIP reporter.
  - Verifies launchd `ProgramArguments` executes `/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service` directly.
  - Recursively rejects production legacy backend/Python tokens in bounded mounted text payloads.
  - Does not launch the installer, call `sudo`, call `launchctl`, or mutate network configuration.
- `tests/test_macos_workflow.py`
  - Added static regression coverage for the acceptance script contract, exact artifact paths, manifest identity checks, and non-mutating boundaries.

## Artifact Evidence
- Package command:
  `SOURCE_COMPLIANCE_BUNDLE=$PWD/target/macos-input/SOURCE-COMPLIANCE-BUNDLE.tar.gz scripts/package-macos.sh`
  - Result: exit 0; produced `dist/macos/EZ-HYU-VPN-arm64.dmg`.
- Acceptance command:
  `scripts/macos-dmg-acceptance.sh dist/macos/EZ-HYU-VPN-arm64.dmg`
  - Result: exit 0; `hdiutil verify` reported the image checksum valid and the script printed `macos-dmg-acceptance: PASS .../dist/macos/EZ-HYU-VPN-arm64.dmg`.
- Artifact checksums:
  - `dist/macos/EZ-HYU-VPN-arm64.dmg` SHA-256: `14675e18518ac65fa4c3f283c51893d653a909a6f860f0dc1aef104f523bd68b`
  - `dist/macos/EZ-HYU-VPN-arm64.dmg.sha256` SHA-256: `2833dc552cff59fb37f484a727c8ddd4290c14361418870e6c5bd35592013fa4`
  - checksum file content: `14675e18518ac65fa4c3f283c51893d653a909a6f860f0dc1aef104f523bd68b  EZ-HYU-VPN-arm64.dmg`

## Verification Evidence
- `python3 -m unittest -v tests.test_macos_workflow` → `Ran 10 tests ... OK`.
- `python3 -m unittest -v tests.test_packaging tests.test_installer tests.test_launchd_config tests.test_macos_workflow` → `Ran 113 tests ... OK`.
- `git diff --check` → exit 0.
- `bash -n scripts/macos-dmg-acceptance.sh scripts/package-macos.sh` → exit 0.
- `python3 -m py_compile tests/test_macos_workflow.py scripts/release_packaging.py scripts/package-release.py installer/manifest.py` → exit 0.
- `cargo fmt --all -- --check` → exit 0.
- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-hip --all-targets` → exit 0.
- `cargo clippy --locked -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-hip --all-targets -- -D warnings` → exit 0.
- `swift test --package-path macos --no-parallel` → exit 0.
- Swift harnesses:
  - `swift run --package-path macos hyu-vpn-helper-test-harness </dev/null` → `HARNESS PASS 71 tests`.
  - `swift run --package-path macos hyu-vpn-menu-harness </dev/null` → `HARNESS PASS 40 tests`.
  - `swift run --package-path macos hyu-vpn-installer-harness </dev/null` → `HARNESS PASS hyu-vpn-installer-harness`.
  - `macos/Scripts/test-wrapperd-closed-stderr.sh </dev/null` → `PASS wrapperd closed stderr exits 70`.
- `python3 -m unittest discover -s tests -p 'test_*.py' -v` → `Ran 413 tests ... OK (skipped=1)`.

## Notes / Remaining Boundaries
- No install, `sudo`, `launchctl`, VPN connection, route/DNS mutation, network mutation, notarization, or publishing was performed.
- The workflow source bundle URL returned HTTP 404 locally, so `target/macos-input/SOURCE-COMPLIANCE-BUNDLE.tar.gz` was generated as ignored local build plumbing from the installed Homebrew runtime closure only to exercise DMG mechanics. It is not committed, not a publication artifact, and not source/legal compliance proof.
- Because the local source bundle contains placeholder source files, the generated local DMG must not be represented as publishable. Verified release source/legal provenance remains a release gate.

## Code Review Verdict

**Recommendation: REQUEST CHANGES**

### Review Scope
- Diff reviewed: `a3b9886..13949d6`
- Files reviewed: `scripts/macos-dmg-acceptance.sh`, `tests/test_macos_workflow.py`, `task-8-report.md`
- Spec inputs reviewed: `.superpowers/sdd/2026-08-08-hyu-vpn-macos-rust-backend/task-8-brief.md`, `docs/superpowers/specs/2026-08-08-hyu-vpn-macos-rust-backend-design.md`, `docs/superpowers/plans/2026-08-08-hyu-vpn-macos-rust-backend.md`, `.superpowers/sdd/2026-08-08-hyu-vpn-macos-rust-backend/progress.md`

### Severity Summary
- CRITICAL: 0
- HIGH: 2
- MEDIUM: 2
- LOW: 0

### Findings

#### [HIGH] Manifest identity check ignores symlinks and special files
- File: `scripts/macos-dmg-acceptance.sh:81-83`
- Issue: The manifest reconstruction skips every mounted path where `not path.is_file()` or `path.is_symlink()`. That means unmanifested symlinks, FIFOs, device nodes, sockets, or other non-regular entries can exist in the mounted DMG while `actual_manifest == expected_manifest` still passes. Task 8 explicitly requires exact mounted manifest identity, including symlink/special-file cases, and the design requires release artifacts to have deterministic public-artifact identity.
- Evidence: A temporary fixture using the script's Python identity logic printed `fixture_identity_block_passed=True` while `unmanifested_symlink_present=True` and `unmanifested_fifo_present=True`.
- Fix: Enumerate all directory entries with `lstat()`. Either reject any non-directory/non-regular entry outright, including symlinks, FIFOs, sockets, block/char devices, or extend the manifest schema to explicitly record and compare their type, target, mode, and metadata. The acceptance gate should fail on any unmanifested entry before reporting PASS. Add regression tests that build a mount-like fixture with unmanifested symlink and FIFO entries and prove the script rejects them.

#### [HIGH] Legacy/Python backend scan can be bypassed by path names and app executable locations
- File: `scripts/macos-dmg-acceptance.sh:122-131`
- Issue: The recursive scan checks selected text file contents, but it does not reject legacy backend path names. It also skips all files under `HYU VPN.app/Contents/MacOS/*` and `Install HYU VPN.app/Contents/MacOS/*` before checking for forbidden names. A DMG whose manifest includes an app-bundled `hyu-vpn-control`, `hyu-vpn-connect`, `hyu-vpn-service`, `hyu-vpn-native-client`, or `src/hyu_vpn` path can pass if the file content does not contain the forbidden token. This violates the Task 8 and design requirement that release artifacts contain no production Python backend paths, not just no matching text content.
- Evidence: A temporary fixture containing `HYU VPN.app/Contents/MacOS/hyu-vpn-control` passed the script's identity block, and the scan classified that legacy path as skipped by the app `Contents/MacOS` exemption.
- Fix: Check every relative path string against the forbidden legacy path/token list before any content-type or app-executable exemptions. Keep narrow binary-content exemptions only after path rejection. Add regression tests for legacy names in app bundles, nested directories, binary-looking files, and manifest-approved legacy paths.

#### [MEDIUM] Cleanup failures are suppressed after PASS, so clean detach is not enforced
- File: `scripts/macos-dmg-acceptance.sh:28-35`, `scripts/macos-dmg-acceptance.sh:135`
- Issue: `cleanup()` runs from the EXIT trap, but `hdiutil detach` errors are redirected and ignored with `|| true`; the script prints PASS before cleanup runs. If detach fails because the mount is busy or hdiutil returns an error, the acceptance command can still exit successfully and leave a mounted read-only DMG/temp directory behind. Task 8 requires clean detach.
- Evidence: Code inspection shows detach failure cannot affect the command status, and the successful local run only proves the happy path.
- Fix: Track the original exit status, retry detach a few times, use the device identifier returned by `hdiutil attach` where possible, and make cleanup failure visible. On a success path, detach before printing PASS or arrange the EXIT trap to convert a successful run into failure if detach never succeeds. Add a focused test with fake `hdiutil detach` failure to prove the script does not report PASS.

#### [MEDIUM] Parsing/output is not consistently bounded for adversarial mounted payloads
- File: `scripts/macos-dmg-acceptance.sh:71-92`, `scripts/macos-dmg-acceptance.sh:130-131`
- Issue: The Python manifest comparison reads each mounted file fully into memory, and the legacy scan can print matching grep lines from mounted text files without an output cap. This is acceptable for the current small local fixture but does not satisfy the brief's bounded parsing/output requirement for arbitrary DMG input under allowed temp paths.
- Evidence: The implementation uses `path.read_bytes()` for every regular file and plain `grep -E` without `-q`, byte limits, or sanitized diagnostics.
- Fix: Compare hashes by streaming chunks with a maximum per-file/total byte budget derived from the manifest, validate manifest sizes before reads, and use quiet/sanitized grep checks (`grep -Iq`/bounded Python scanning) that report only the relative path and token class, not mounted file contents.

### Positive Evidence
- Input/path guard rejects missing args, symlink DMG paths, non-regular DMG paths, and DMGs outside repo `dist` or temp roots (`scripts/macos-dmg-acceptance.sh:5-22`).
- The script uses `hdiutil verify` and read-only/no-browse attach, and contains no installer launch, `sudo`, `launchctl`, `networksetup`, `scutil --nc`, `route add`, or `ifconfig` calls (`scripts/macos-dmg-acceptance.sh:37-39`, `scripts/macos-dmg-acceptance.sh:109-131`).
- Required code-signing checks and exact arm64 checks are present for the app executables, Rust service, helper, and HIP reporter (`scripts/macos-dmg-acceptance.sh:109-120`).
- Launchd parsing checks that rendered `ProgramArguments` executes `/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service` directly (`scripts/macos-dmg-acceptance.sh:100-106`).
- `task-8-report.md` correctly states that the placeholder source-compliance bundle and generated local DMG are local, ignored, non-publishable build plumbing and not release/source/legal compliance proof.

### Validation Performed During Review
- `bash -n scripts/macos-dmg-acceptance.sh` → pass.
- `python3 -m py_compile tests/test_macos_workflow.py` → pass.
- `python3 -m unittest -v tests.test_macos_workflow` → `Ran 10 tests ... OK`.
- `scripts/macos-dmg-acceptance.sh dist/macos/EZ-HYU-VPN-arm64.dmg` → PASS for the current local non-publishable DMG; no `hyu-vpn-dmg-acceptance` mount/temp leftover was observed afterward.
- Static suspicious-pattern scan was reviewed for installer/sudo/launchctl/network mutation calls; none were found in the acceptance script.
- Focused temporary fixture proved the manifest/symlink-special and legacy-path evasion cases above.
- `shellcheck` was not installed, so shell static analysis was limited to `bash -n` plus manual review.

### Release Boundary
The existing report language is acceptable: it explicitly treats `target/macos-input/SOURCE-COMPLIANCE-BUNDLE.tar.gz` and `dist/macos/EZ-HYU-VPN-arm64.dmg` as local, ignored, non-publishable artifacts. Keep that language until a real source/legal provenance bundle and public download verification gate exist.

## Fix Round 1 Implementation Report

### Scope
Addressed all four Task 8 review findings in the reusable DMG acceptance gate. The fix remains read-only and non-installing: no installer launch, no `sudo`, no `launchctl`, no VPN connection, and no route/DNS/network mutation.

### RED Evidence Captured
- Added executable fixture-based tests in `tests/test_macos_workflow.py` using fake `hdiutil`, `codesign`, `lipo`, and `file` commands around a mount-like payload fixture.
- Initial RED run against the pre-fix script:
  `python3 -m unittest -v tests.test_macos_workflow`
  - Result: `FAILED (failures=4, errors=1)` before implementation.
  - Intended failures showed the script accepted an unmanifested symlink, accepted a manifest-approved `HYU VPN.app/Contents/MacOS/hyu-vpn-control` path, printed PASS despite detach failure, and leaked raw forbidden-content output from grep. The one fixture reuse error was fixed before GREEN.

### Changes Made
- `scripts/macos-dmg-acceptance.sh`
  - Replaced `Path.rglob(...).is_file()` enumeration with `os.walk(..., followlinks=False)` plus `os.lstat()` checks.
  - Rejects symlinks and all non-regular/non-directory entries, including FIFO/socket/device/special entries, with sanitized `special-entry:<relative-path>` diagnostics.
  - Requires the exact manifest regular-file set; unmanifested regular files fail and missing manifested files fail through file-set mismatch.
  - Checks every relative path name, including app `Contents/MacOS` paths and opaque binary paths, for legacy/Python backend token categories before any content/binary exemption.
  - Replaced unbounded `read_bytes()` hashing with streamed SHA-256 and manifest-enforced per-file/total size caps (`HYU_DMG_ACCEPTANCE_MAX_FILE_BYTES` and `HYU_DMG_ACCEPTANCE_MAX_TOTAL_BYTES` retain bounded defaults and give tests a smaller cap surface).
  - Replaced raw `grep` output with bounded Python content scanning that reports only sanitized error code, relative path, and token category; no matching line contents are printed.
  - Enforces clean detach as a success condition with three bounded retries. PASS is printed only after detach succeeds. Cleanup failures during a primary validation failure are reported as sanitized cleanup errors while preserving the primary nonzero exit status.
- `tests/test_macos_workflow.py`
  - Added fixture execution coverage for unmanifested symlink/FIFO rejection, legacy path token rejection before binary exemption, detach failure as command failure/no PASS, sanitized forbidden-content diagnostics, and file-size cap rejection.

### Fix Round Verification Evidence
- `python3 -m unittest -v tests.test_macos_workflow` → `Ran 15 tests ... OK`.
- `scripts/macos-dmg-acceptance.sh dist/macos/EZ-HYU-VPN-arm64.dmg` → exit 0; `hdiutil verify` reported image checksum valid and the script printed `macos-dmg-acceptance: PASS .../dist/macos/EZ-HYU-VPN-arm64.dmg`.
- `git diff --check` → exit 0.
- `bash -n scripts/macos-dmg-acceptance.sh scripts/package-macos.sh` → exit 0.
- `python3 -m py_compile tests/test_macos_workflow.py scripts/release_packaging.py scripts/package-release.py installer/manifest.py` → exit 0.
- `python3 -m unittest -v tests.test_packaging tests.test_installer tests.test_launchd_config tests.test_macos_workflow` → `Ran 118 tests ... OK`.
- `cargo fmt --all -- --check` → exit 0.
- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-hip --all-targets` → exit 0.
- `cargo clippy --locked -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-hip --all-targets -- -D warnings` → exit 0.
- `swift test --package-path macos --no-parallel` → exit 0.
- Swift harnesses:
  - `swift run --package-path macos hyu-vpn-helper-test-harness </dev/null` → `HARNESS PASS 71 tests`.
  - `swift run --package-path macos hyu-vpn-menu-harness </dev/null` → `HARNESS PASS 40 tests`.
  - `swift run --package-path macos hyu-vpn-installer-harness </dev/null` → `HARNESS PASS hyu-vpn-installer-harness`.
  - `macos/Scripts/test-wrapperd-closed-stderr.sh </dev/null` → `PASS wrapperd closed stderr exits 70`.
- `python3 -m unittest discover -s tests -p 'test_*.py' -v` → `Ran 418 tests ... OK (skipped=1)`.

### Artifact Evidence
- Existing local non-publishable DMG inspected after fix:
  - `dist/macos/EZ-HYU-VPN-arm64.dmg` SHA-256: `14675e18518ac65fa4c3f283c51893d653a909a6f860f0dc1aef104f523bd68b`
  - `dist/macos/EZ-HYU-VPN-arm64.dmg.sha256` SHA-256: `2833dc552cff59fb37f484a727c8ddd4290c14361418870e6c5bd35592013fa4`
  - checksum file content: `14675e18518ac65fa4c3f283c51893d653a909a6f860f0dc1aef104f523bd68b  EZ-HYU-VPN-arm64.dmg`

### Notes / Remaining Boundaries
- The inspected DMG remains a local, ignored, non-publishable artifact because it was built with ignored local Task 8 source-bundle plumbing after the CI source bundle URL returned 404. It is not release/source/legal compliance proof.
- Verified release source/legal provenance remains a release gate.

## Fix Round 1 Code Review Verdict

**Recommendation: REQUEST CHANGES**

### Review Scope
- Diff reviewed: `13949d6..42bf94e`
- Packaged diff reviewed: `.superpowers/sdd/2026-08-08-hyu-vpn-macos-rust-backend/review-task8-fix1.diff`
- Files reviewed: `scripts/macos-dmg-acceptance.sh`, `tests/test_macos_workflow.py`, `task-8-report.md`
- Prior findings rechecked: symlink/special manifest identity, path-first legacy/Python rejection, clean bounded detach/cleanup with primary-error precedence, bounded streaming parsing and sanitized output.

### Severity Summary
- CRITICAL: 0
- HIGH: 1
- MEDIUM: 0
- LOW: 0

### Finding

#### [HIGH] Successful acceptance still leaves `/private/tmp/hyu-vpn-dmg-acceptance.*` directories behind
- File: `scripts/macos-dmg-acceptance.sh:32`, `scripts/macos-dmg-acceptance.sh:41-43`, `scripts/macos-dmg-acceptance.sh:272-275`
- Issue: `cleanup_detach()` redirects detach stderr to `$MOUNT_PARENT/detach.err` on every detach attempt, including successful detaches, but neither `cleanup_detach()` nor `cleanup_dirs()` removes that file. As a result, `rmdir "$MOUNT_PARENT"` fails after a successful detach, the script still prints `PASS`, and the acceptance run leaves a temp directory behind. This means the prior cleanup/detach finding is not fully closed: detach is required before PASS, but cleanup is not clean or reliable.
- Evidence: A direct real-DMG run returned `0` and printed `macos-dmg-acceptance: PASS`, but before/after tracking showed `new_count 1` with a new `/private/tmp/hyu-vpn-dmg-acceptance.FBZb0z` directory containing `detach.err`. A successful fake-tool fixture run likewise returned `0` and left one new acceptance temp directory.
- Fix: Remove or truncate/delete `$MOUNT_PARENT/detach.err` after a successful detach before `cleanup_dirs`, or write detach diagnostics to a shell variable/temporary file that is always removed on success. Add a regression assertion that a successful fixture and real-style happy path leave no new `/private/tmp/hyu-vpn-dmg-acceptance.*` directories before reporting PASS.

### Prior Finding Recheck
- **Symlink/special/unmanifested entries:** closed for the tested fixture cases. Direct fixture runs rejected `unmanifested-link` and `unmanifested-fifo` with sanitized `special-entry` diagnostics and no leaked target path.
- **Relative path scanned before binary exemption:** closed for the tested fixture case. A manifest-approved `HYU VPN.app/Contents/MacOS/hyu-vpn-control` path failed with `forbidden-token:path:legacy-backend` before app-binary content exemption.
- **Primary-error precedence:** closed for the tested validation-failure case. A symlink validation failure plus simulated detach failure preserved `special-entry` and reported sanitized `cleanup-failed:detach` without leaking fake detach stderr. Note: a success-path detach failure currently reports `cleanup-failed:detach` twice because the explicit detach failure triggers the EXIT trap while `attached=1`; this is noisy but bounded and not the blocking issue above.
- **Bounded streaming parsing/sanitized output:** closed for the tested fixture cases. Large fixture content hit `size-limit:file`; forbidden content reported only `forbidden-token:content:python-runtime:README-lab.md` and did not print the raw secret line or `/usr/bin/python3` token.
- **Non-mutation/path guards:** no regression found in the acceptance script. Static scan found `hdiutil attach -readonly -nobrowse`, allowed temp/dist path guards, and no installer launch, `sudo`, `launchctl`, `networksetup`, `scutil --nc`, `route add`, `ifconfig`, curl, or network mutation calls in `scripts/macos-dmg-acceptance.sh`.
- **Local artifact boundary:** still acceptable. The report continues to state that the placeholder source-compliance bundle and local DMG are ignored, local, non-publishable artifacts and not source/legal compliance proof.

### Validation Performed During Fix Round 1 Re-review
- `bash -n scripts/macos-dmg-acceptance.sh scripts/package-macos.sh` → pass.
- `python3 -m py_compile tests/test_macos_workflow.py` → pass.
- `python3 -m unittest -v tests.test_macos_workflow` → `Ran 15 tests ... OK`.
- `scripts/macos-dmg-acceptance.sh dist/macos/EZ-HYU-VPN-arm64.dmg` → exit 0 / PASS for the local non-publishable DMG, but left a new `/private/tmp/hyu-vpn-dmg-acceptance.*` directory containing `detach.err`.
- Direct executable fixtures re-run manually for symlink, FIFO, legacy app path, forbidden content, file-size cap, primary error plus detach failure, and success detach failure.
- `git diff --check` → pass.
- `python3 -m unittest -v tests.test_packaging tests.test_installer tests.test_launchd_config tests.test_macos_workflow` → `Ran 118 tests ... OK`.
- `shellcheck`/LSP diagnostics were unavailable in this environment; shell syntax, Python compile, static pattern scans, executable fixtures, and the direct DMG run were used as the review validation substitutes.

## Fix Round 2 Implementation Report

### Scope
Closed the remaining cleanup leak where successful acceptance left `/private/tmp/hyu-vpn-dmg-acceptance.*` directories containing `detach.err`. The acceptance gate remains read-only and non-installing: no installer launch, no `sudo`, no `launchctl`, no VPN connection, and no route/DNS/network mutation.

### RED Evidence Captured
- Added `test_macos_dmg_acceptance_success_leaves_no_temp_acceptance_dirs`, an executable fake-acceptance regression that records matching `/private/tmp/hyu-vpn-dmg-acceptance.*` directories before and after a successful run.
- Initial RED run before the fix:
  `python3 -m unittest -v tests.test_macos_workflow.MacOSWorkflowTests.test_macos_dmg_acceptance_success_leaves_no_temp_acceptance_dirs`
  - Result: `FAILED`; the test observed one new directory such as `/private/tmp/hyu-vpn-dmg-acceptance.pzMj8J` after a successful PASS.

### Changes Made
- `scripts/macos-dmg-acceptance.sh`
  - Removes `$MOUNT_PARENT/detach.err` immediately after successful detach.
  - Also removes any stale `detach.err` in `cleanup_dirs` before removing mount/temp directories.
  - Keeps failed-detach diagnostics sanitized (`cleanup-failed:detach`) and keeps the EXIT trap cleanup path active.
- `tests/test_macos_workflow.py`
  - Added the successful-cleanup no-new-temp-dir regression.
  - Re-ran primary-error-plus-cleanup-failure and success-detach-failure tests to preserve precedence and sanitized diagnostics.

### Fix Round 2 Verification Evidence
- Targeted RED before implementation: `python3 -m unittest -v tests.test_macos_workflow.MacOSWorkflowTests.test_macos_dmg_acceptance_success_leaves_no_temp_acceptance_dirs` → failed with one new temp directory.
- Targeted GREEN after implementation: `python3 -m unittest -v tests.test_macos_workflow.MacOSWorkflowTests.test_macos_dmg_acceptance_success_leaves_no_temp_acceptance_dirs tests.test_macos_workflow.MacOSWorkflowTests.test_macos_dmg_acceptance_preserves_primary_error_while_reporting_cleanup_failure tests.test_macos_workflow.MacOSWorkflowTests.test_macos_dmg_acceptance_requires_clean_detach_before_pass` → `Ran 3 tests ... OK`.
- `python3 -m unittest -v tests.test_macos_workflow` → `Ran 16 tests ... OK`.
- `git diff --check` → exit 0.
- `bash -n scripts/macos-dmg-acceptance.sh scripts/package-macos.sh` → exit 0.
- `python3 -m py_compile tests/test_macos_workflow.py scripts/release_packaging.py scripts/package-release.py installer/manifest.py` → exit 0.
- `python3 -m unittest -v tests.test_packaging tests.test_installer tests.test_launchd_config tests.test_macos_workflow` → `Ran 119 tests ... OK`.
- Real local DMG acceptance with explicit temp-dir tracking:
  - `scripts/macos-dmg-acceptance.sh dist/macos/EZ-HYU-VPN-arm64.dmg` → exit 0 / PASS.
  - before/after tracking of `/private/tmp/hyu-vpn-dmg-acceptance.*` → `new temp dirs: []`.

### Artifact Evidence
- Existing local non-publishable DMG inspected after fix round 2:
  - `dist/macos/EZ-HYU-VPN-arm64.dmg` SHA-256: `14675e18518ac65fa4c3f283c51893d653a909a6f860f0dc1aef104f523bd68b`
  - `dist/macos/EZ-HYU-VPN-arm64.dmg.sha256` SHA-256: `2833dc552cff59fb37f484a727c8ddd4290c14361418870e6c5bd35592013fa4`
  - checksum file content remains: `14675e18518ac65fa4c3f283c51893d653a909a6f860f0dc1aef104f523bd68b  EZ-HYU-VPN-arm64.dmg`

### Notes / Remaining Boundaries
- The inspected DMG remains local, ignored, and non-publishable because it was built with ignored local Task 8 source-bundle plumbing after the CI source bundle URL returned 404. It is not release/source/legal compliance proof.
- Verified release source/legal provenance remains a release gate.

## Fix Round 2 Code Review Verdict

**Recommendation: APPROVE**

### Review Scope
- Diff reviewed: `42bf94e..653f0f3`
- Packaged diff reviewed: `.superpowers/sdd/2026-08-08-hyu-vpn-macos-rust-backend/review-task8-fix2.diff`
- Files reviewed: `scripts/macos-dmg-acceptance.sh`, `tests/test_macos_workflow.py`, `task-8-report.md`
- Rechecked: successful-run temp-dir leak, prior symlink/special manifest rejection, path-first legacy/Python rejection, clean detach/no PASS on detach failure, primary-error precedence, bounded streaming parsing, sanitized output, non-mutation/path guards, and local non-publishable DMG boundary.

### Severity Summary
- CRITICAL: 0
- HIGH: 0
- MEDIUM: 0
- LOW: 0

### Prior Finding Closure
- **Successful-run temp-dir leak:** closed. The script now removes `$MOUNT_PARENT/detach.err` after successful detach and again before directory removal (`scripts/macos-dmg-acceptance.sh:32-45`). A before/after real DMG acceptance run returned exit 0 / PASS and produced `new_temp_dirs []`.
- **Symlink/special/unmanifested entries:** remains closed. Direct fixture rechecks rejected unmanifested symlink and FIFO with sanitized `special-entry` diagnostics and no PASS.
- **Relative paths before binary exemption:** remains closed. A manifest-approved `HYU VPN.app/Contents/MacOS/hyu-vpn-control` fixture failed with `forbidden-token:path:legacy-backend` before any app-binary content exemption.
- **Clean detach / no PASS on detach failure / primary-error precedence:** remains closed for PASS gating. Success with simulated detach failure returned nonzero and no PASS. Validation failure plus detach failure preserved the primary `special-entry` error and added sanitized `cleanup-failed:detach`. Simulated detach-failure cases necessarily leave fake mount temp state, but they are failing paths and do not claim acceptance success.
- **Bounded parsing and sanitized output:** remains closed. Fixture rechecks produced `size-limit:file` for a capped large file and `forbidden-token:content:python-runtime:README-lab.md` without printing the raw secret line or `/usr/bin/python3` token.
- **Non-mutation/path guards:** no regression found. Static scan of `scripts/macos-dmg-acceptance.sh` found read-only/no-browse attach, allowed repo-dist/temp path guards, and no installer launch, `sudo`, `launchctl`, `networksetup`, `scutil --nc`, `route add`, `ifconfig`, curl, or network mutation calls.
- **Local artifact boundary:** remains acceptable. The report continues to state that the placeholder source-compliance bundle and local DMG are local, ignored, non-publishable artifacts and not release/source/legal compliance proof.

### Validation Performed During Fix Round 2 Re-review
- `bash -n scripts/macos-dmg-acceptance.sh scripts/package-macos.sh` → pass.
- `python3 -m py_compile tests/test_macos_workflow.py` → pass.
- `python3 -m unittest -v tests.test_macos_workflow` → `Ran 16 tests ... OK`.
- Direct real local DMG acceptance with before/after temp-dir tracking:
  - command: `scripts/macos-dmg-acceptance.sh dist/macos/EZ-HYU-VPN-arm64.dmg`
  - result: exit 0 / PASS
  - temp-dir result: `new_temp_dirs []`
- Direct fixture rechecks:
  - success → exit 0 / PASS / `new_temp_count=0`
  - symlink → exit 1 / `special-entry:unmanifested-link` / no PASS
  - FIFO → exit 1 / `special-entry:unmanifested-fifo` / no PASS
  - legacy app path → exit 1 / `forbidden-token:path:legacy-backend` / no PASS
  - forbidden content → exit 1 / sanitized `forbidden-token:content:python-runtime:README-lab.md` / no raw token or secret line
  - large cap → exit 1 / `size-limit:file:large-safe-text.txt`
  - validation failure plus detach failure → exit 1 / primary `special-entry` preserved plus sanitized cleanup failure / no PASS
  - successful validation plus detach failure → exit 1 / sanitized cleanup failure / no PASS
- `git diff --check` → pass.
- `shellcheck`/LSP diagnostics were unavailable in this environment; shell syntax, Python compile, static pattern scan, executable fixtures, and the direct DMG run were used as review validation substitutes.

### Release Boundary
Approval is scoped to the Task 8 deterministic, non-installing, local artifact inspection gate. The inspected DMG remains local and non-publishable until verified source/legal provenance and public release gates are satisfied.
