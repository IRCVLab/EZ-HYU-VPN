# HYU VPN Legacy Eradication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve the verified Rust/Swift v0.2.5 behavior while removing every known Python/native-client/old-installer residue and making future macOS installs erase the same residue transactionally.

**Architecture:** The Rust services and Swift macOS applications remain the only production implementation. The privileged installer owns an exact, allowlisted, rollback-safe legacy migration; the menu resets the Rust TOTP counter names; vendor GlobalProtect is removed only through its bundled uninstaller. Network settings under `/Library/Preferences/SystemConfiguration` are never modified.

**Tech Stack:** Rust, Swift/AppKit, zsh installer transaction, Python unittest build tooling.

**Spec:** Current verified v0.2.5 behavior and `docs/release-checklist-macos-rust.md`.

## Global Constraints

- Keep the current credential files and current Rust/Swift application behavior.
- Do not delete or rewrite macOS `SystemConfiguration` plists.
- Do not disable Wi-Fi during validation.
- Do not execute a repair-required legacy helper.
- Preserve rollback until the new helper, service, application, and sudoers pass health checks.
- No new dependencies.

---

### Task 1: Lock Current Behavior and Legacy Migration Contract

**Files:**
- Modify: `tests/test_installer.py`
- Modify: `macos/Tests/HYUVPNMenuAppTestHarness/main.swift`

- [ ] Add a failing dry-root installer test containing every known legacy system/user path and assert successful install removes them.
- [ ] Add rollback assertions proving an injected install failure restores all moved legacy paths.
- [ ] Change the menu TOTP reset contract from `totp-counter.json(.lock)` to the Rust macOS names `totp-counter(.lock)` and verify the old JSON file is not touched by current code.
- [ ] Run the targeted tests and record the expected failures before implementation.

### Task 2: Delete Legacy Runtime Source

**Files:**
- Delete: `src/hyu_vpn/`
- Delete: `bin/gp-hip-report`, `bin/hyu-vpn-connect`, `bin/hyu-vpn-control`, `bin/hyu-vpn-native-client`, `bin/hyu-vpn-service`
- Delete: `launchd/local.hyu-openconnect.plist`
- Delete: Python-backend-only live acceptance scripts and unit tests.
- Modify: remaining packaging/static tests that intentionally verify absence of these paths.

- [ ] Delete the obsolete Python production implementation and its direct tests.
- [ ] Keep `installer/manifest.py` and packaging Python modules because they are build tools, not installed runtime.
- [ ] Verify Linux, Windows, and macOS packages still build from Rust applications.

### Task 3: Add Transactional Legacy Erasure

**Files:**
- Modify: `installer/root-admin.sh`
- Modify: `tests/test_installer.py`
- Modify: `macos/Sources/HYUVPNMenuApp/SystemAdapters.swift`
- Modify: `macos/Tests/HYUVPNMenuAppTestHarness/main.swift`

- [ ] Add an exact migration allowlist for old binaries, Python source, backup directories, old runtime directories, legacy sudoers, and retired user state files.
- [ ] Move each existing residue into the transaction backup before replacement so failure restores it.
- [ ] Permanently delete the transaction backup only after install commit and health checks.
- [ ] Permit repair only through the package helper whose SHA-256 matches the installed helper.
- [ ] Point menu TOTP reset to `totp-counter` and `totp-counter.lock`.

### Task 4: Remove Machine Residue Safely

**Files/paths:**
- Remove after verified migration: old HYU VPN home installers/DMGs, `~/.cache/hyu-openconnect`, retired sudoers and installed backup/runtime paths.
- Remove GlobalProtect with `/Applications/GlobalProtect.app/Contents/Resources/uninstall_gp.sh` under one macOS administrator authorization.

- [ ] Snapshot route, DNS, helper state, and public Internet before mutation.
- [ ] Reinstall with automatic reconnect disabled so the migration runs without starting VPN.
- [ ] Verify route/DNS/public Internet are unchanged and legacy paths are absent.
- [ ] Run the vendor GlobalProtect uninstaller only while HYU VPN is safely disabled, then verify public Internet again.
- [ ] Remove user-owned obsolete installers/caches with an exact path allowlist.

### Task 5: Quality Gates and Final Always-On Verification

**Files:**
- Rebuild: `dist/macos/EZ-HYU-VPN-arm64.dmg`

- [ ] Run Swift helper/menu/installer harnesses.
- [ ] Run targeted Rust format, clippy, and tests.
- [ ] Run remaining Python packaging/installer tests and static absence scans.
- [ ] Build and read-only validate the DMG plus dry-root rollback evidence.
- [ ] Perform one guarded external-network connection cycle, verify HIP/internal reachability/public Internet, then leave automatic reconnect enabled.
- [ ] Confirm the worktree is clean and report the final DMG SHA-256.
