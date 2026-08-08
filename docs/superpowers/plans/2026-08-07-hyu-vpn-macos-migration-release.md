# HYU VPN macOS Migration and Cross-Platform Release Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate the validated Rust daemon with the existing macOS Swift menu-bar app, preserve safe rollback, and publish verified artifacts for all supported platforms.

**Architecture:** A macOS adapter composes the shared Rust daemon with the existing privileged helper and encrypted credential files. Swift moves to the versioned Unix-socket protocol only after cross-language and live-behavior parity succeeds.

**Tech Stack:** Rust, Swift 6, AppKit, launchd, existing privileged helper, GitHub Actions/Releases.

## Global Constraints

- Preserve the current working DMG and Python backend until Rust parity passes.
- Keep the existing macOS native UI and V icon.
- Do not reintroduce Keychain credential access prompts.
- Never mutate unowned routes, DNS, interfaces, or foreign VPN state.

---

### Task 1: macOS Rust platform adapter

**Files:**
- Create: `rust/crates/hyu-vpn-platform-macos/Cargo.toml`
- Create: `rust/crates/hyu-vpn-platform-macos/src/lib.rs`
- Create: `rust/crates/hyu-vpn-platform-macos/src/network.rs`
- Create: `rust/crates/hyu-vpn-platform-macos/src/helper.rs`
- Create: `rust/crates/hyu-vpn-platform-macos/src/storage.rs`
- Create: `rust/crates/hyu-vpn-platform-macos/tests/macos_adapters.rs`

**Interfaces:**
- Implements core ports using the existing helper protocol, current encrypted files, and macOS route/DNS evidence.

- [ ] Port existing fixture and adversarial tests for route ownership, helper repair, credential compatibility, native GlobalProtect conflict, sleep/wake, and child cleanup.
- [ ] Implement adapters without changing the installed helper contract.
- [ ] Run Rust adapters beside the complete Python and Swift suites.
- [ ] Commit with `git commit -m "Add macOS adapters for Rust VPN daemon"`.

### Task 2: Swift IPC client and controlled backend switch

**Files:**
- Create: `macos/Sources/HYUVPNMenuCore/RustProtocol.swift`
- Create: `macos/Sources/HYUVPNMenuApp/RustServiceAdapter.swift`
- Modify: `macos/Sources/HYUVPNMenuApp/SystemAdapters.swift`
- Modify: `macos/Sources/HYUVPNMenuApp/AppDelegate.swift`
- Modify: `macos/Tests/HYUVPNMenuAppTests/HYUVPNMenuAppTests.swift`

**Interfaces:**
- Consumes protocol version 1 through an owner-only Unix socket.
- Preserves the current menu state and credential transaction contracts.

- [ ] Write Swift tests for every response fixture, unavailable/incompatible daemon behavior, timeouts, credential replacement, OTP, and secret-free diagnostics.
- [ ] Implement the IPC adapter behind a backend selector that defaults to Python until packaging flips it.
- [ ] Run Swift, Rust, and Python suites.
- [ ] Commit with `git commit -m "Connect macOS menu app to Rust service"`.

### Task 3: macOS package migration and rollback

**Files:**
- Modify: `scripts/release_packaging.py`
- Modify: `installer/root-admin.sh`
- Modify: `macos/Sources/HYUVPNInstallerApp/main.swift`
- Modify: `launchd/com.hyu.vpn.service.plist.in`
- Modify: `tests/test_packaging.py`
- Modify: `tests/test_installer.py`

**Interfaces:**
- Installs the Rust daemon and records a package-versioned backend marker while retaining one-release Python rollback payload.

- [ ] Add failing installer/package tests for Rust binary manifests, architecture, signature, backend marker, upgrade from v0.1.0, credential preservation, rollback, uninstall, and no duplicate services.
- [ ] Update the package transaction to stage, verify, activate, health-check, and roll back the daemon atomically.
- [ ] Build and install the DMG on a clean test account, then exercise connect, Wi-Fi movement, expiry simulation, credential replacement, login launch, quit, upgrade, and uninstall.
- [ ] Commit with `git commit -m "Migrate macOS package to Rust service"`.

### Task 4: Unified CI and release metadata

**Files:**
- Create: `.github/workflows/cross-platform.yml`
- Create: `scripts/release-manifest.py`
- Modify: `README.md`
- Modify: `packaging/THIRD_PARTY_NOTICES.txt`
- Modify: `packaging/SOURCE-OFFER.txt`

**Interfaces:**
- Produces a versioned manifest with SHA-256 for DMG, Windows installer, and Ubuntu DEB.

- [ ] Add required CI jobs for all platform unit, UI, packaging, secret-scan, and installer lifecycle tests.
- [ ] Generate per-platform checksums and a machine-readable release manifest.
- [ ] Update README with three graphical installation sections and the same automatic-reconnect explanation.
- [ ] Verify notices and source-offer coverage for every packaged OpenConnect/runtime artifact.
- [ ] Commit with `git commit -m "Add cross-platform release pipeline"`.

### Task 5: Final acceptance and release

**Files:**
- Create: `docs/release-checklist.md`
- Create: `tests/reconnect_acceptance_contract.md`

**Interfaces:**
- Produces an evidence checklist and release-ready artifacts; no platform is labeled production-ready without live platform evidence.

- [ ] Run all deterministic suites and package inspections on CI.
- [ ] On each platform, install through the GUI and validate credential collection, tray controls, OTP, login launch, session-expiry reconnect, physical-network loss, changed-network recovery within ten seconds, and clean uninstall.
- [ ] Verify every artifact checksum and code signature where signing credentials are available.
- [ ] Publish a prerelease containing only platforms with completed live evidence; keep any unverified artifact labeled experimental.
- [ ] Commit with `git commit -m "Document cross-platform release acceptance"`.
