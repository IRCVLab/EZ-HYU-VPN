# HYU VPN Menu Bar App Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an internal-lab DMG containing a native macOS menu bar controller and a least-privilege lifecycle backend that shows server session expiry and eliminates orphaned root OpenConnect, stale-route/DNS, OTP-reuse, and native-client conflict failures.

**Architecture:** Preserve the validated Python authentication/HIP implementation behind a user LaunchAgent, add a compiled root-owned Swift helper with a fixed foreground pipe contract, record sanitized service state in an atomic JSON document, and expose control through a native AppKit menu bar application. Package the app, backend, helper, installer, and uninstaller into an ad-hoc-signed checksum-published DMG; keep the current working service untouched until a controlled migration gate.

**Tech Stack:** Python 3 standard library, Swift 6/AppKit/Foundation/Darwin, OpenConnect, oathtool, launchd, sudoers, Keychain CLI, unittest, XCTest, shell integration tests, codesign, and hdiutil.

**Design:** `docs/superpowers/specs/2026-08-04-hyu-vpn-menubar-design.md`

---

## File structure

### Python backend

- Create `src/hyu_vpn/status.py`: sanitized status schema, expiry parsing, atomic mode-0600 storage.
- Create `src/hyu_vpn/control.py`: fixed user control CLI.
- Create `src/hyu_vpn/network.py`: network readiness and owned-session-aware conflict evidence.
- Modify `src/hyu_vpn/otp.py`: cross-process TOTP counter guard without storing OTP values.
- Modify `src/hyu_vpn/connector.py`: helper protocol, event parsing, sanitized output, privileged stop.
- Modify `src/hyu_vpn/supervisor.py`: explicit state machine and control state.
- Create `bin/hyu-vpn-control`.
- Create `src/hyu_vpn/native_client.py`: detect and reversibly suppress only conflicting GlobalProtect automatic launch behavior.

### Privileged lifecycle

- Create `macos/Package.swift`.
- Create `macos/Sources/HYUVPNPrivilegedHelper/main.swift`.
- Create `macos/Sources/HYUVPNPrivilegedHelper/SessionIdentity.swift`.
- Create `macos/Sources/HYUVPNPrivilegedHelper/ProcessRunner.swift`.
- Create `macos/Sources/HYUVPNPrivilegedHelper/NetworkLedger.swift`.
- Create `privileged/hyu-vpnc-wrapper`.
- Create `privileged/com.hyu.vpn.sudoers`.

### Menu app

- Create `macos/Sources/HYUVPNMenuApp/main.swift`.
- Create `macos/Sources/HYUVPNMenuApp/MenuController.swift`.
- Create `macos/Sources/HYUVPNMenuApp/StatusModel.swift`.
- Create `macos/Sources/HYUVPNMenuApp/ControlClient.swift`.
- Create `macos/Resources/Info.plist`.

### Install/package

- Create `installer/install.sh`, `installer/uninstall.sh`, and `installer/manifest.py`.
- Create `installer/Install HYU VPN.command` and `installer/Uninstall HYU VPN.command` as fixed, shell-free-path launchers into the verified payload.
- Create `launchd/com.hyu.vpn.service.plist.in`.
- Create `launchd/com.hyu.vpn.menubar.plist.in`.
- Create `scripts/build-app.sh` and `scripts/build-dmg.sh`.
- Create `packaging/README-lab.md`.

### Tests

- Create `tests/test_status.py`, `tests/test_control.py`, `tests/test_network.py`, `tests/test_native_client.py`, `tests/test_installer.py`, and `tests/test_packaging.py`.
- Modify connector, supervisor, and privacy tests.
- Create helper and menu XCTest targets under `macos/Tests/`.
- Create `tests/menu_live_acceptance.sh` and `docs/menu-live-test-report.md`.

## Task 0: Prove the local build and packaging toolchain

**Files:** Create `tests/test_build_preflight.py`; create `scripts/preflight.sh`; create a minimal test-only bundle fixture under `tests/fixtures/app-bundle/`.

- [ ] Write failing tests for Swift 6 availability, AppKit compilation, supported host architecture, `codesign`, `hdiutil`, `plutil`, `security`, `visudo`, and deterministic discovery of Homebrew dependencies.
- [ ] Verify RED when the preflight implementation is absent.
- [ ] Implement a read-only preflight that produces machine-readable capability metadata and never changes the current VPN or system configuration.
- [ ] Add failing app-bundle fixture tests for `Contents/MacOS`, `Contents/Resources`, `Info.plist`, `LSUIElement=true`, bundle identifier, version, executable name, and ad-hoc signature verification.
- [ ] Implement the minimal bundle assembler primitive used later by Task 6 and Task 8.
- [ ] Run `python3 -m unittest -v tests.test_build_preflight` and verify GREEN.
- [ ] Commit `build: verify macOS menu app toolchain`.

## Task 1: Lock the sanitized status and expiry contract

**Files:** Create `tests/test_status.py`; create `src/hyu_vpn/status.py`.

- [ ] Write failing tests for exact allowed fields, state enumeration, ISO-8601 timestamps, unknown expiry, malformed/oversized documents, atomic writes, directory mode 0700, and file mode 0600.
- [ ] Run `python3 -m unittest -v tests.test_status` and verify RED because the module is missing.
- [ ] Implement immutable status values and an atomic temp-file/fsync/os.replace store with no secret-bearing fields.
- [ ] Add failing parser tests for the real `Session authentication will expire at Tue, 04 Aug 2026 21:59:30 KST` event, split chunks, duplicates, hostile text, missing values, and clock rollover.
- [ ] Implement the bounded event parser and countdown source.
- [ ] Run `python3 -m unittest -v tests.test_status tests.test_security_privacy` and verify GREEN.
- [ ] Commit `feat: add sanitized VPN status protocol`.

## Task 2: Prevent OTP reuse and unstable-network retries

**Files:** Modify `src/hyu_vpn/otp.py`; create `src/hyu_vpn/network.py`, `src/hyu_vpn/native_client.py`, `tests/test_network.py`, and `tests/test_native_client.py`; modify connector and supervisor tests.

- [ ] Write failing tests for a cross-process counter guard that persists only the TOTP time-step counter, atomically and mode 0600.
- [ ] Prove a new process waits for a later counter without persisting the OTP or seed.
- [ ] Implement the guard for portal and gateway challenges.
- [ ] Write failing network tests requiring repeated usable default-route and DNS probes, waiting during sleep/wake, distinguishing a helper-owned utun from native GlobalProtect, and suppressing only a real foreign session.
- [ ] Implement `NetworkReadiness` and owned-session conflict evidence.
- [ ] Write failing native-client tests that identify only GlobalProtect automatic launch mechanisms, snapshot their exact prior state, disable them without uninstalling or terminating a manual recovery client, refuse ambiguous/user-modified state, and restore exactly the recorded state during uninstall or rollback.
- [ ] Implement reversible native automatic-launch suppression with a user-readable record and no overlap: a real native connected/connecting state always blocks OpenConnect, while manual native recovery remains available when the HYU service is disabled.
- [ ] Run `python3 -m unittest -v tests.test_network tests.test_native_client tests.test_connector tests.test_supervisor`.
- [ ] Commit `fix: serialize OTP and network reconnect state`.

## Task 3: Implement the privileged helper

**Files:** Create the Swift helper sources, `macos/Package.swift`, and `macos/Tests/HYUVPNPrivilegedHelperTests/`.

- [ ] Write failing command-surface tests allowing only exact start, stop, status, and repair forms; reject extra args, path overrides, symlinks, user-writable parents, malformed stdin headers, and console-UID mismatch.
- [ ] Run `cd macos && swift test --filter HYUVPNPrivilegedHelperTests` and verify RED.
- [ ] Implement root-owned configuration plus PID, PGID, birth time, nonce, UID, fixed portal, executable identity, launch timestamp, and a compiling opaque ledger-path/session-nonce interface; Task 4 owns ledger contents and repair semantics.
- [ ] Add failing harmless-child tests for inherited stdin/stdout, private username header consumption, process-group ownership, channel-loss SIGTERM, bounded stop, and unrelated-PID rejection.
- [ ] Implement posix_spawn monitoring, root-owned locking, and foreground lifecycle.
- [ ] Add stale PID, forced PID reuse, birth-time mismatch, nonce mismatch, and executable mismatch tests.
- [ ] Implement strict stop/status behavior and run `cd macos && swift test` with warnings treated as errors.
- [ ] Commit `feat: add least privilege VPN lifecycle helper`.

## Task 4: Own route and DNS changes per session

**Files:** Create `privileged/hyu-vpnc-wrapper`; modify `NetworkLedger.swift`; add Swift and integration fixtures.

- [ ] Write failing ledger tests for before/applied/after route tuples, resolver/search-domain values, service ID, default interface, tunnel interface, and nonce.
- [ ] Implement the root-owned wrapper and atomic session ledger around the resolved upstream vpnc script.
- [ ] Add adversarial tests rejecting mismatched gateway/interface/service/nonce, post-start network changes, pre-reboot snapshots, unrelated VPN routes, and resolver changes by another actor.
- [ ] Implement match-before-repair and `repair-required` without raw SystemConfiguration edits.
- [ ] Run `cd macos && swift test`.
- [ ] Commit `feat: ledger VPN route and DNS changes`.

## Task 5: Integrate helper, status events, and service state

**Files:** Modify connector and supervisor; create `src/hyu_vpn/control.py`, `bin/hyu-vpn-control`, and `tests/test_control.py`.

- [ ] Write failing helper-protocol tests requiring username header then password/OTP stdin, fixed `sudo -n helper start`, separate helper stop, session event parsing, and no raw persistent log.
- [ ] Implement the helper client and sanitized event sink.
- [ ] Write failing state-machine/control tests for enable, connect, disconnect-and-disable, reconnect, retry countdown, network wait, helper failure, teardown failure, and repair-required.
- [ ] Implement disabled, waiting-for-network, connecting, connected, disconnecting, backoff, and error states plus fixed control CLI actions.
- [ ] Run `python3 -m unittest discover -s tests -v`.
- [ ] Commit `feat: control VPN through verified service state`.

## Task 6: Build the AppKit menu bar application

**Files:** Create the menu Swift sources, resources, and `macos/Tests/HYUVPNMenuAppTests/`.

- [ ] Write failing status decoding, countdown, and menu-state tests for connected, connecting, backoff, disabled, error, unknown/expired expiry, corrupted files, and schema mismatch.
- [ ] Implement status decoding and a fixed executable control client that never invokes a shell.
- [ ] Implement NSStatusItem and menus using template SF Symbols: shield.lefthalf.filled, arrow.triangle.2.circlepath, clock.arrow.circlepath, shield.slash, and exclamationmark.shield.
- [ ] Show remaining duration in the menu-bar title only while connected.
- [ ] Add menu action and notification-preference tests; expiry notifications are off by default and schedule only known 10-minute/1-minute thresholds.
- [ ] Run `cd macos && swift test && swift build -c release`.
- [ ] Commit `feat: add HYU VPN menu bar controller`.

## Task 7: Create transactional installer and uninstaller

**Files:** Create installer files, `.command` launchers, sudoers template, LaunchAgent templates, and `tests/test_installer.py`.

- [ ] Write failing tests for exact root/user ownership and modes, no symlink traversal, absolute dependency paths, hash verification before sudo, exact sudoers commands, and no secrets in arguments/files.
- [ ] Write failing `.command` launcher tests proving paths with spaces are handled without `eval`, the embedded payload is verified before execution, and exactly one documented administrator-authentication phase is used.
- [ ] Implement dry-run installation with Apple silicon `/opt/homebrew` and Intel `/usr/local` resolution persisted in root-owned config.
- [ ] Add Keychain tests for create, update, unchanged-existing-item, non-echo input, failed-transaction removal of only newly created items, and explicit uninstall choice before credential removal.
- [ ] Add a rollback matrix injecting failure around helper install, sudoers validation, app copy, LaunchAgent bootstrap, Keychain creation, native GlobalProtect automatic-launch suppression, and live-helper migration.
- [ ] Implement idempotent reverse-order rollback and validate sudoers with `visudo -c` before activation.
- [ ] Run `python3 -m unittest -v tests.test_installer` and `bash -n installer/*.sh privileged/hyu-vpnc-wrapper`.
- [ ] Commit `feat: install HYU VPN transactionally`.

## Task 8: Build and verify the DMG

**Files:** Create build scripts, lab README, and `tests/test_packaging.py`.

- [ ] Write failing tests requiring the app, helper, install/uninstall commands, README, manifest, version, architecture metadata, ad-hoc signature, and external SHA-256 checksum.
- [ ] Implement release builds, app bundle assembly, nested-first ad-hoc signing, DMG creation, checksum generation, `codesign --verify --deep --strict`, and `hdiutil verify`.
- [ ] Build a universal binary when both architectures are available; otherwise fail or label the DMG explicitly as single-architecture.
- [ ] Mount the DMG read-only and validate its exact contents.
- [ ] Commit `build: package HYU VPN internal DMG`.

## Task 9: Adversarial review and controlled migration

**Files:** Create `tests/menu_live_acceptance.sh`, `docs/menu-live-test-report.md`, and update `README.md`.

- [ ] Add a dry-run migration snapshot for the post-reboot network baseline, current service, routes, DNS, installed files, and helper identity without changing the tunnel.
- [ ] Run all Python tests, Swift tests, compileall, bash syntax checks, plist validation, signature/DMG checks, and `git diff --check`.
- [ ] Obtain independent zero-Critical/Important security review for privilege boundaries, secrets, PID signaling, network ledger, installer rollback, and menu command injection.
- [ ] During one announced sudo window, install the reviewed helper while preserving the current connection until rollback is ready.
- [ ] Prove one full cycle: helper stop, zero root OpenConnect, restored routes/DNS/internet, LaunchAgent reconnect, HIP/ESP/protected traffic/general internet/DNS, menu/backend expiry equality, one reconnect, and one final stable service-owned session.
- [ ] Exercise the live network-change matrix: sleep/wake while connected, sleep/wake during teardown, Wi-Fi service change during a session, and an unrelated resolver change. Each case must restore only owned deltas or stop at `repair-required`, never overwrite the newer network state, and never spin/reuse an OTP.
- [ ] Prove GlobalProtect automatic launch remains suppressed while HYU automatic mode is enabled, a real native connected/connecting state blocks OpenConnect, manual recovery remains usable when HYU is disabled, and uninstall/rollback restores the exact prior automatic-launch state.
- [ ] Build the final DMG and checksum, record only sanitized evidence, and commit `docs: record HYU VPN menu app acceptance`.

## Task 10: Validate a clean internal-lab install and uninstall

**Files:** Create `tests/clean_lab_acceptance.sh`; create `docs/clean-lab-test-report.md`; update `packaging/README-lab.md` and release notes.

- [ ] Make the clean-lab script fail closed unless it starts from a recorded absence of HYU VPN package artifacts and captures the host architecture/macOS version without secrets.
- [ ] On a secondary clean lab Mac, verify the published checksum, perform the documented Gatekeeper **Open** flow, run `Install HYU VPN.command`, and prove there is only one administrator-authentication phase.
- [ ] Prove menu launch, Keychain-backed connection, expiry display, disconnect, reconnect, automatic reconnect after a simulated network interruption, protected traffic, general internet/DNS, and zero native/OpenConnect overlap.
- [ ] Run `Uninstall HYU VPN.command`, exercise both Keychain-retain and explicit-Keychain-remove choices, and prove helper, app, LaunchAgents, sudoers fragment, support files, processes, routes, DNS changes, and native automatic-launch suppression state are removed/restored exactly.
- [ ] Attach sanitized evidence to `docs/clean-lab-test-report.md`; do not publish or call the DMG release-complete until this secondary-Mac gate passes.
- [ ] Commit `docs: validate clean lab DMG lifecycle`.

## Verification commands

- `python3 -m unittest discover -s tests -v`
- `scripts/preflight.sh --json`
- `(cd macos && swift test)`
- `python3 -m compileall -q src bin tests installer`
- `bash -n installer/*.sh privileged/hyu-vpnc-wrapper scripts/*.sh tests/menu_live_acceptance.sh`
- `plutil -lint launchd/*.plist*`
- `codesign --verify --deep --strict <app>`
- `hdiutil verify <dmg>`
- `git diff --check`

## Stop conditions

- Do not modify or stop the currently stable service until Tasks 1-8 pass offline and the reviewed privileged installer is ready.
- Abort live migration before touching the active session if helper identity, sudoers, manifest, rollback, or network baseline checks fail.
- Never delete files under `/Library/Preferences/SystemConfiguration`.
- Do not claim release completion until the controlled network-change matrix, clean secondary-lab-Mac install/uninstall cycle, and mounted-DMG checks pass.
