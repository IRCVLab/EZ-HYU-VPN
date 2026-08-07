# HYU VPN Update Notifications Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add fail-silent, manual update notifications to the macOS menu app beginning with v0.1.1.

**Architecture:** `HYUVPNMenuCore` owns strict version/feed validation and an injected asynchronous checker. `HYUVPNMenuApp` schedules checks, renders the offer, remembers the last announced version, and opens only the allowlisted release URL. Bundle assembly injects the current version and feed policy.

**Tech Stack:** Swift 6, Foundation, AppKit, Swift Testing, shell bundle assembly, Python unittest packaging tests.

## Global Constraints

- No new dependencies.
- Update failures never alter VPN state or controls.
- HTTPS only, strict JSON, bounded response, explicit host/path allowlist.
- No GitHub token, credentials, automatic download, or automatic install.
- v0.1.0 users require a one-time manual announcement.

---

### Task 1: Strict update feed core

**Files:**
- Create: `macos/Sources/HYUVPNMenuCore/UpdateCheck.swift`
- Modify: `macos/Tests/HYUVPNMenuAppTests/HYUVPNMenuAppTests.swift`

**Interfaces:**
- Produces: `SemanticVersion`, `UpdateFeedDecoder`, `UpdatePolicy`, `UpdateOffer`, `UpdateChecking`.

- [ ] Add tests for semantic ordering, strict schema, size bounds, HTTPS/host/path policy, and suppression of equal/older versions.
- [ ] Run `swift test --package-path macos --filter UpdateCheckTests` and verify RED because update types do not exist.
- [ ] Implement the smallest pure core that makes the tests pass.
- [ ] Re-run the filtered tests and `swift test --package-path macos`.
- [ ] Commit the tested core.

### Task 2: Isolated network checker

**Files:**
- Modify: `macos/Sources/HYUVPNMenuCore/UpdateCheck.swift`
- Modify: `macos/Tests/HYUVPNMenuAppTests/HYUVPNMenuAppTests.swift`

**Interfaces:**
- Consumes: `UpdatePolicy`, `UpdateFeedDecoder`.
- Produces: `HTTPSUpdateChecker.check(completion:)` returning `UpdateOffer?` without throwing into app state.

- [ ] Add an injected data-loader test covering valid data and fail-silent loader/parser errors.
- [ ] Verify RED for the missing checker.
- [ ] Implement a single-flight checker and ephemeral production loader with 10-second request/resource timeout, no cookies, and no cache.
- [ ] Verify filtered and full Swift tests.
- [ ] Commit the checker.

### Task 3: Menu and one-time notification wiring

**Files:**
- Modify: `macos/Sources/HYUVPNMenuApp/AppDelegate.swift`
- Modify: `macos/Tests/HYUVPNMenuAppTestHarness/main.swift`

**Interfaces:**
- Consumes: `UpdateChecking`, `UpdateOffer`.
- Produces: `Update Available: vX.Y.Z…` menu action and one AppKit alert per version.

- [ ] Add harness source-contract tests for startup scheduling, six-hour cadence, update menu row, allowlisted open action, and remembered alert version.
- [ ] Verify the harness fails before wiring exists.
- [ ] Wire an initial delayed check, six-hour timer, menu rebuilding, `NSWorkspace.open`, and version-keyed `UserDefaults` alert suppression.
- [ ] Verify menu harness and full Swift suite.
- [ ] Commit app wiring.

### Task 4: Versioned bundle and release verification

**Files:**
- Modify: `macos/Scripts/assemble-menu-app.sh`
- Modify: `macos/Scripts/assemble-installer-app.sh`
- Modify: `tests/test_packaging.py`
- Modify: `README.md`

**Interfaces:**
- Produces: app bundles containing v0.1.1 and explicit feed policy keys.

- [ ] Add packaging tests that reject invalid versions and assert `CFBundleShortVersionString`, `CFBundleVersion`, feed URL, allowed host, and allowed path.
- [ ] Verify RED against current assembly scripts.
- [ ] Extend both assembly scripts with a validated version input; add menu updater bundle keys without embedding secrets.
- [ ] Document manual v0.1.0 migration and future in-app notices.
- [ ] Run all Python tests, Swift tests/harnesses, shell syntax checks, release build, DMG mount validation, and installed status verification.
- [ ] Commit release wiring.
