# HYU VPN Menu OTP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore permanent menu usability, make Launch at Login registerable after a fresh install, remove Diagnostics, and add live click-to-copy TOTP.

**Architecture:** Keep TOTP math as a pure `HYUVPNMenuCore` value generator, encrypted credential access in `HYUVPNMenuAppSupport`, and AppKit timer/pasteboard work in `AppDelegate`. Preserve the existing `SMAppService` adapter and change only the observed pre-registration `.notFound` projection.

**Tech Stack:** Swift 6, AppKit, ServiceManagement, CryptoKit, Swift Testing, existing executable harnesses.

## Global Constraints

- Do not use Keychain, Security.framework, `/usr/bin/security`, or a new dependency.
- Never log, display, or copy the TOTP setup seed.
- Do not modify `totp-counter.json` from the menu OTP display.
- Keep the menu responsive while its one-second countdown updates.

---

### Task 1: Login item recovery and Diagnostics removal

**Files:**
- Modify: `macos/Sources/HYUVPNMenuApp/SystemAdapters.swift`
- Modify: `macos/Sources/HYUVPNMenuApp/AppDelegate.swift`
- Modify: `macos/Sources/HYUVPNMenuCore/MenuCore.swift`
- Test: `macos/Tests/HYUVPNMenuAppTestHarness/main.swift`

**Interfaces:**
- Consumes: `LoginItemController.project(status:)` and the existing AppKit menu builder.
- Produces: `.notFound` maps to `.disabled`; the live menu has no Diagnostics item or modal action.

- [ ] **Step 1: Write failing tests**

Change the login projection expectation to `.disabled`, require an enabled `Launch at Login` model, and require the live menu contract to omit Diagnostics.

- [ ] **Step 2: Run the menu harness and verify RED**

Run: `swift run --package-path macos hyu-vpn-menu-harness`

Expected: failures for the old unavailable projection and existing Diagnostics menu source.

- [ ] **Step 3: Implement the minimum behavior**

Map `.notFound` to `.disabled`; remove `MenuAction.diagnostics`, `addDiagnosticsAction`, `showDiagnostics`, `diagnosticsText`, and its menu insertion.

- [ ] **Step 4: Run the menu harness and verify GREEN**

Run: `swift run --package-path macos hyu-vpn-menu-harness`

Expected: all menu harness tests pass.

### Task 2: Pure TOTP generation

**Files:**
- Create: `macos/Sources/HYUVPNMenuCore/TOTPDisplay.swift`
- Test: `macos/Tests/HYUVPNMenuAppTests/HYUVPNMenuAppTests.swift`

**Interfaces:**
- Produces: `TOTPDisplaySnapshot(code: String, secondsRemaining: Int)` and `TOTPDisplayGenerator.snapshot(seed: String, at: Date) throws -> TOTPDisplaySnapshot`.

- [ ] **Step 1: Write failing known-vector tests**

Assert seed `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` at Unix time `0` returns code `755224`, countdown `30`; time `59` returns `287082`, countdown `1`; malformed Base32 throws.

- [ ] **Step 2: Run the focused Swift tests and verify RED**

Run: `swift test --package-path macos --filter TOTP`

Expected: compile failure because the generator does not exist.

- [ ] **Step 3: Implement Base32 and RFC 6238**

Decode strict uppercase RFC 4648 Base32, construct the 64-bit big-endian 30-second counter, use `HMAC<Insecure.SHA1>`, dynamically truncate, and zero-pad modulo 1,000,000.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `swift test --package-path macos --filter TOTP`

Expected: known vectors and boundary behavior pass.

### Task 3: Encrypted provider and AppKit menu integration

**Files:**
- Modify: `macos/Sources/HYUVPNMenuApp/SystemAdapters.swift`
- Modify: `macos/Sources/HYUVPNMenuApp/AppDelegate.swift`
- Test: `macos/Tests/HYUVPNMenuAppTestHarness/main.swift`

**Interfaces:**
- Consumes: `EncryptedCredentialStore.read(.totpSeed)` and `TOTPDisplayGenerator.snapshot(seed:at:)`.
- Produces: `SystemMenuTOTPProvider.snapshot(at:) -> TOTPDisplaySnapshot?`, a live OTP menu item, and `copyOTP(_:)`.

- [ ] **Step 1: Write failing provider and menu behavior tests**

Require correct encrypted-seed output, unchanged `totp-counter.json`, an OTP menu action, a common-mode one-second timer, and pasteboard copying of only `representedObject`'s six digits.

- [ ] **Step 2: Run the menu harness and verify RED**

Run: `swift run --package-path macos hyu-vpn-menu-harness`

Expected: failures because the provider and menu item do not exist.

- [ ] **Step 3: Implement the provider, timer, item, and copy action**

Read the seed through the encrypted store, update one retained `NSMenuItem` every second on the main/common run loop, and copy only a validated six-digit string through `NSPasteboard.general`.

- [ ] **Step 4: Run the menu harness and verify GREEN**

Run: `swift run --package-path macos hyu-vpn-menu-harness`

Expected: all tests pass with no secret output.

### Task 4: Full verification and release

**Files:**
- Modify only if a verification failure identifies a defect.

**Interfaces:**
- Produces: a verified replacement `~/HYU-VPN-latest.dmg` and installed runtime evidence.

- [ ] **Step 1: Run all tests**

Run Swift tests plus installer/menu/helper harnesses and `python3 -m unittest discover -s tests -p 'test_*.py'`.

- [ ] **Step 2: Run release and legacy-path checks**

Build release, reject Keychain/Security CLI patterns, package the next version, verify manifest, DMG, signatures, architecture, and checksum.

- [ ] **Step 3: Reinstall and inspect live menu**

Verify connected state, enabled Disconnect/Quit, checked Launch at Login, no Diagnostics item, a changing OTP countdown, and successful explicit copy without reading clipboard contents in automation.

- [ ] **Step 4: Commit implementation**

Commit source, tests, and release documentation with a focused message.
