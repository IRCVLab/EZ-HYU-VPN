# HYU VPN Control-Tower Menu Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the expiry-oriented HYU VPN menu with a minimal native control tower that auto-connects on launch, safely disconnects on quit, resets credentials through GUI-only Keychain APIs, and controls launch-at-login through `SMAppService.mainApp`.

**Architecture:** Keep the Python supervisor and privileged network boundary unchanged. Move pure presentation, input validation, and operation state machines into `HYUVPNMenuCore`; keep AppKit, Security.framework, ServiceManagement, and application termination adapters in `HYUVPNMenuApp`. Migrate only the menu app from its legacy LaunchAgent to `SMAppService.mainApp`; the backend service LaunchAgent remains the lifecycle owner.

**Tech Stack:** Swift 6, AppKit, Security.framework, ServiceManagement, Swift Testing plus executable Swift harnesses, Python 3 standard-library tests, zsh installer scripts, launchd.

## Global Constraints

- Minimum supported platform is macOS 14.
- The app is internal-lab, ad-hoc signed, and must explicitly validate `SMAppService.mainApp` on the target Mac.
- App launch requests `connect`; explicit Disconnect pauses until Connect/Reconnect/relaunch; Quit disconnects before termination.
- Session-expiry/countdown/duration UI and expiry notifications are removed, but backend expiry parsing remains intact.
- Password and TOTP values never enter argv, environment variables, logs, status JSON, diagnostics, notifications, or persistent temporary files.
- Password and TOTP confirmation are mandatory; blank TOTP pair retains the current seed.
- No privileged-helper, route, DNS, or SystemConfiguration behavior changes are in scope.
- No new dependencies.
- `.omx/` remains untracked and must never be committed.

---

## File Structure

- Modify `macos/Sources/HYUVPNMenuCore/MenuCore.swift`: retain status decoding/watching and secure control execution; replace expiry-oriented presentation/menu models and delete notification machinery.
- Create `macos/Sources/HYUVPNMenuCore/ControlTowerCore.swift`: pure credential validation, login-item presentation, startup retry policy, and in-flight operation state.
- Replace `macos/Sources/HYUVPNMenuApp/main.swift`: argument gate plus app bootstrap only.
- Create `macos/Sources/HYUVPNMenuApp/AppDelegate.swift`: status item, menu construction, connect/disconnect/reconnect, diagnostics, startup connect, and termination coordination.
- Create `macos/Sources/HYUVPNMenuApp/CredentialResetController.swift`: native credential form and asynchronous reset flow.
- Create `macos/Sources/HYUVPNMenuApp/SystemAdapters.swift`: Security.framework Keychain transaction and ServiceManagement login-item adapter.
- Modify `macos/Tests/HYUVPNMenuAppTests/HYUVPNMenuAppTests.swift`: pure Swift coverage for new models/validation/policies.
- Modify `macos/Tests/HYUVPNMenuAppTestHarness/main.swift`: visible behavioral gate for menu, startup, quit, credential rollback, login status, and secret redaction.
- Modify `installer/install.sh`, `installer/uninstall.sh`, `installer/root-admin.sh`, `installer/manifest.py`: default-on preference, legacy menu-LaunchAgent retirement, app launch, login-item unregister, and single-owner install state.
- Delete `launchd/com.hyu.vpn.menubar.plist.in`: no dual login mechanism.
- Modify `tests/test_installer.py` and `tests/test_packaging.py`: migration and payload regression coverage.
- Modify `docs/superpowers/specs/2026-08-04-hyu-vpn-menubar-design.md` only to link to the superseding control-tower spec if a generated release document still treats it as current.

---

### Task 1: Minimal state presentation and dynamic menu model

**Files:**
- Modify: `macos/Sources/HYUVPNMenuCore/MenuCore.swift:257-385,512-555,748-end`
- Test: `macos/Tests/HYUVPNMenuAppTests/HYUVPNMenuAppTests.swift:70-140`
- Test: `macos/Tests/HYUVPNMenuAppTestHarness/main.swift:100-190,210-225,240-520`

**Interfaces:**
- Produces `MenuPresentation(statusItemTitle:primaryText:detailText:symbolName:)` with an always-empty status-item title.
- Produces `MenuAction.currentState`, `.primaryConnection`, `.disconnect`, `.resetCredentials`, `.launchAtLogin`, `.diagnostics`, `.quit`.
- Produces `MenuModel.make(status:diagnostics:launchAtLogin:)`.
- Deletes `NotificationPreference`, `NotificationPlanner`, `AsyncNotificationCoordinator`, and notification-store/client protocols.

- [ ] **Step 1: Replace expiry-oriented test expectations with the approved icon/copy matrix**

```swift
let expected: [(VPNConnectionState, String, String)] = [
    (.connected, "checkmark.shield.fill", "Connected"),
    (.connecting, "arrow.triangle.2.circlepath", "Connecting…"),
    (.disconnecting, "shield.slash", "Disconnecting…"),
    (.disabled, "shield.slash", "Disconnected"),
    (.waitingForNetwork, "wifi.exclamationmark", "Waiting for Network"),
    (.backoff, "clock.arrow.circlepath", "Reconnecting…"),
    (.error, "exclamationmark.shield.fill", "Needs Attention"),
]
for (state, symbol, title) in expected {
    let view = MenuPresenter.present(status(state: state))
    #expect(view.statusItemTitle.isEmpty)
    #expect(view.symbolName == symbol)
    #expect(view.primaryText == title)
}
```

- [ ] **Step 2: Add failing menu-model tests for one dynamic primary action and no expiry actions**

```swift
let connected = MenuModel.make(status: status(state: .connected), diagnostics: "", launchAtLogin: .enabled)
#expect(connected[.primaryConnection]?.title == "Reconnect")
#expect(connected[.primaryConnection]?.command == .reconnect)
#expect(connected[.disconnect]?.isEnabled == true)
#expect(connected[.launchAtLogin]?.isChecked == true)
#expect(MenuAction.allCases == [.currentState, .primaryConnection, .disconnect, .resetCredentials, .launchAtLogin, .diagnostics, .quit])
```

- [ ] **Step 3: Run the focused tests and confirm they fail for the old countdown/menu model**

Run:

```bash
cd macos
swift test --filter HYUVPNMenuAppTests
swift run hyu-vpn-menu-harness
```

Expected: assertion or compile failures referencing old `countdownText`, expiry actions, or notification types.

- [ ] **Step 4: Implement the minimal presentation and menu model**

```swift
public struct MenuPresentation: Equatable, Sendable {
    public let statusItemTitle: String
    public let primaryText: String
    public let detailText: String
    public let symbolName: String
}

public enum MenuAction: CaseIterable, Hashable, Sendable {
    case currentState, primaryConnection, disconnect
    case resetCredentials, launchAtLogin, diagnostics, quit
}
```

Map connected to `.reconnect`; map disabled/error to `.connect`; keep primary disabled during connecting/disconnecting/waiting; map backoff to `Reconnect Now`. Remove expiry/duration formatting and every notification planner/store/coordinator type.

- [ ] **Step 5: Run focused tests and harness**

Run:

```bash
cd macos
swift test --filter HYUVPNMenuAppTests
swift run hyu-vpn-menu-harness
```

Expected: all updated presentation/menu tests pass and harness ends with `HARNESS PASS`.

- [ ] **Step 6: Commit Task 1**

```bash
git add macos/Sources/HYUVPNMenuCore/MenuCore.swift macos/Tests/HYUVPNMenuAppTests/HYUVPNMenuAppTests.swift macos/Tests/HYUVPNMenuAppTestHarness/main.swift
git -c user.name=shchoi00 -c user.email=shchoi00@hanyang.ac.kr commit -m "feat: simplify VPN menu state presentation"
```

---

### Task 2: Pure lifecycle, login-item, and credential validation core

**Files:**
- Create: `macos/Sources/HYUVPNMenuCore/ControlTowerCore.swift`
- Test: `macos/Tests/HYUVPNMenuAppTests/HYUVPNMenuAppTests.swift`
- Test: `macos/Tests/HYUVPNMenuAppTestHarness/main.swift`

**Interfaces:**
- Produces `LoginItemState` with `.enabled`, `.disabled`, `.approvalRequired`, `.unavailable(code:)`.
- Produces `StartupConnectPolicy` with 30 one-second attempts limited to transient `CONTROL_UNAVAILABLE`/launch failures.
- Produces `OperationGate.begin(_:) -> Bool` and `finish(_:)` for duplicate suppression.
- Produces `CredentialResetInput`, `ValidatedCredentials`, `CredentialValidationError`, and `CredentialValidator.validate(_:)`.
- Produces `CredentialStore` and `TOTPStateResetting` protocols plus `CredentialTransaction.apply(_:)` with rollback.

- [ ] **Step 1: Add failing credential validation tests**

```swift
let good = CredentialResetInput(
    username: "shchoi00",
    password: "correct horse",
    passwordConfirmation: "correct horse",
    totpSeed: "jbsw y3dp-ehpk3pxp",
    totpSeedConfirmation: "JBSWY3DPEHPK3PXP"
)
let validated = try CredentialValidator.validate(good)
#expect(validated.normalizedTOTPSeed == "JBSWY3DPEHPK3PXP")

#expect(throws: CredentialValidationError.passwordMismatch) {
    try CredentialValidator.validate(input(password: "one", confirmation: "two"))
}
#expect(try CredentialValidator.validate(input(totp: "", totpConfirmation: "")).normalizedTOTPSeed == nil)
```

- [ ] **Step 2: Add failing transaction rollback and secret-redaction tests**

Use a fake store with existing username/password/TOTP values. Inject failure on the third write and assert the first two values are restored, no reconnect callback occurs, and returned errors contain stable codes without submitted values.

- [ ] **Step 3: Add failing startup and operation-gate tests**

```swift
var policy = StartupConnectPolicy()
#expect(policy.next(after: .transientFailure) == .retry(after: 1))
for _ in 1..<30 { _ = policy.next(after: .transientFailure) }
#expect(policy.next(after: .transientFailure) == .stop)
#expect(policy.next(after: .success) == .stop)

var gate = OperationGate()
#expect(gate.begin(.disconnect))
#expect(!gate.begin(.quit))
gate.finish(.disconnect)
#expect(gate.begin(.quit))
```

- [ ] **Step 4: Run focused tests and confirm failure**

Run:

```bash
cd macos
swift test --filter HYUVPNMenuAppTests
swift run hyu-vpn-menu-harness
```

Expected: missing new core types.

- [ ] **Step 5: Implement validation and transactional protocols without platform frameworks**

```swift
public struct ValidatedCredentials: Sendable {
    public let username: String
    public let password: String
    public let normalizedTOTPSeed: String?
}

public protocol CredentialStore: AnyObject {
    func read(_ key: CredentialKey) throws -> String?
    func write(_ value: String, for key: CredentialKey) throws
    func remove(_ key: CredentialKey) throws
}
```

Normalize TOTP exactly as the design specifies. Implement rollback in reverse write order. Return stable enum errors only.

- [ ] **Step 6: Implement login presentation, startup retry, and operation gate**

Keep these types deterministic and scheduler-free so AppKit owns timers while tests prove the decisions.

- [ ] **Step 7: Run focused tests and harness**

Run:

```bash
cd macos
swift test --filter HYUVPNMenuAppTests
swift run hyu-vpn-menu-harness
```

Expected: all new pure-core cases pass.

- [ ] **Step 8: Commit Task 2**

```bash
git add macos/Sources/HYUVPNMenuCore/ControlTowerCore.swift macos/Tests/HYUVPNMenuAppTests/HYUVPNMenuAppTests.swift macos/Tests/HYUVPNMenuAppTestHarness/main.swift
git -c user.name=shchoi00 -c user.email=shchoi00@hanyang.ac.kr commit -m "feat: add control tower lifecycle models"
```

---

### Task 3: AppKit menu, safe quit, diagnostics, and startup auto-connect

**Files:**
- Replace: `macos/Sources/HYUVPNMenuApp/main.swift`
- Create: `macos/Sources/HYUVPNMenuApp/AppDelegate.swift`
- Modify: `macos/Tests/HYUVPNMenuAppTestHarness/main.swift`

**Interfaces:**
- Consumes Task 1 `MenuModel` and Task 2 policies/gate.
- Produces an icon-only `NSStatusItem`, dynamic menu actions, startup connect retries, diagnostics alert, and `applicationShouldTerminate` disconnect gate.
- Adds exact CLI modes `--register-login-item` and `--unregister-login-item`; all other arguments exit 64 before AppKit startup.

- [ ] **Step 1: Add harness source-contract tests for menu order and absence of UserNotifications**

```swift
try expect(!appSource.contains("import UserNotifications"), "expiry notifications removed")
try expect(appSource.contains("#selector(primaryConnection)"), "one primary action")
try expect(appSource.contains("applicationShouldTerminate"), "quit interception")
try expect(!appSource.contains("NSApp.terminate(nil)"), "no direct unsafe quit")
```

- [ ] **Step 2: Add a test seam for startup retry and termination results**

Drive the Task 2 policy with fake results: transient failure then success; non-transient failure; quit disconnect success; quit timeout/failure. Assert duplicate quit is ignored and failure replies `.terminateCancel`.

- [ ] **Step 3: Run the harness and confirm failure**

Run:

```bash
cd macos
swift run hyu-vpn-menu-harness
```

Expected: source-contract or coordinator tests fail against the old direct-quit app.

- [ ] **Step 4: Split app bootstrap from AppDelegate and remove notification runtime**

`main.swift` validates the two exact login-item CLI modes before creating `NSApplication`; normal no-argument execution starts the accessory app. `AppDelegate.swift` owns status watching and menu creation.

- [ ] **Step 5: Implement icon-only menu and dynamic handlers**

Set `button.title = ""`, template symbol image, tooltip/accessibility description `HYU VPN <state>`, and build only the approved menu rows. Run control work on a utility queue and marshal results to main.

- [ ] **Step 6: Implement startup connect and safe termination**

On launch, attempt `.connect`; retry once per second only while `StartupConnectPolicy` permits. Implement `applicationShouldTerminate` returning `.terminateLater`, execute `.disconnect` with a 15-second timeout, and call `NSApp.reply(toApplicationShouldTerminate:)` with success/failure. Failure displays a normalized `NSAlert` and keeps the app running.

- [ ] **Step 7: Implement sanitized Diagnostics alert**

Display only state, tunnel interface, normalized backend error, normalized last control result, and build version. Never include raw process output.

- [ ] **Step 8: Run menu harness and release compilation**

Run:

```bash
cd macos
swift run hyu-vpn-menu-harness
swift build -c release
```

Expected: menu harness passes; build has zero warnings because warnings are errors.

- [ ] **Step 9: Commit Task 3**

```bash
git add macos/Sources/HYUVPNMenuApp/main.swift macos/Sources/HYUVPNMenuApp/AppDelegate.swift macos/Tests/HYUVPNMenuAppTestHarness/main.swift
git -c user.name=shchoi00 -c user.email=shchoi00@hanyang.ac.kr commit -m "feat: make the menu app own VPN lifecycle"
```

---

### Task 4: Native credential-reset GUI and Keychain transaction

**Files:**
- Create: `macos/Sources/HYUVPNMenuApp/CredentialResetController.swift`
- Create: `macos/Sources/HYUVPNMenuApp/SystemAdapters.swift`
- Modify: `macos/Sources/HYUVPNMenuApp/AppDelegate.swift`
- Modify: `macos/Package.swift` only if explicit framework linker settings are required by the local toolchain
- Test: `macos/Tests/HYUVPNMenuAppTestHarness/main.swift`

**Interfaces:**
- Implements Task 2 `CredentialStore` with fixed services `gp-vpn-username`, `gp-vpn-password`, `gp-vpn-totp` and account `hyu-vpn` through Security.framework.
- Implements `TOTPStateResetting` for `~/Library/Application Support/hyu-openconnect/totp-counter.json` with owner/mode/symlink checks.
- Produces `CredentialResetController.present(from:completion:)`.

- [ ] **Step 1: Add source and adapter tests proving secrets never enter process-launch surfaces**

Assert credential code imports `Security`, does not reference `/usr/bin/security`, `Process`, `posix_spawn`, `argv`, or logging calls, and only accepts the fixed three `CredentialKey` cases.

- [ ] **Step 2: Add GUI-model tests for two confirmations and optional TOTP**

Use Task 2 validation tests plus a harness test that the form declares five fields and uses `NSSecureTextField` for password, confirmation, TOTP, and TOTP confirmation.

- [ ] **Step 3: Run tests and confirm failure**

Run:

```bash
cd macos
swift run hyu-vpn-menu-harness
swift build
```

Expected: missing controller/adapter source.

- [ ] **Step 4: Implement Security.framework store with rollback-safe reads/writes**

Use `SecItemCopyMatching`, `SecItemUpdate`, and `SecItemAdd` with exact service/account queries. Convert OSStatus to stable codes such as `KEYCHAIN_READ_FAILED`, `KEYCHAIN_WRITE_FAILED`, and `KEYCHAIN_ROLLBACK_FAILED`; never interpolate a secret.

- [ ] **Step 5: Implement the native five-field form**

Build an `NSGridView` accessory view. Prefill only the username. Keep password and TOTP fields blank. Loop validation without clearing valid entries, show inline/alert normalized validation copy, and never open Terminal.

- [ ] **Step 6: Implement disconnect → Keychain transaction → connect**

Suppress duplicate operations with `OperationGate`. Do validation on main, control/Keychain work off main, clear the TOTP counter only after a new seed commits, reconnect only after full success, and remain disconnected on failure.

- [ ] **Step 7: Run focused tests, harness, and secret scan**

Run:

```bash
cd macos
swift test --filter HYUVPNMenuAppTests
swift run hyu-vpn-menu-harness
cd ..
rg -n 'print\(|NSLog|os_log|/usr/bin/security|Process\(' macos/Sources/HYUVPNMenuApp
```

Expected: tests pass; scan findings are either absent or limited to non-secret bootstrap code explicitly reviewed.

- [ ] **Step 8: Commit Task 4**

```bash
git add macos/Sources/HYUVPNMenuApp/CredentialResetController.swift macos/Sources/HYUVPNMenuApp/SystemAdapters.swift macos/Sources/HYUVPNMenuApp/AppDelegate.swift macos/Package.swift macos/Tests
git -c user.name=shchoi00 -c user.email=shchoi00@hanyang.ac.kr commit -m "feat: add native VPN credential reset"
```

---

### Task 5: `SMAppService` launch-at-login and legacy LaunchAgent migration

**Files:**
- Modify: `macos/Sources/HYUVPNMenuApp/SystemAdapters.swift`
- Modify: `macos/Sources/HYUVPNMenuApp/AppDelegate.swift`
- Modify: `macos/Sources/HYUVPNMenuApp/main.swift`
- Delete: `launchd/com.hyu.vpn.menubar.plist.in`
- Modify: `installer/manifest.py:265-300`
- Modify: `installer/root-admin.sh:91-94,367-405`
- Modify: `installer/install.sh:39-55,117-134`
- Modify: `installer/uninstall.sh:23-39`
- Test: `tests/test_installer.py`
- Test: `tests/test_packaging.py`
- Test: `macos/Tests/HYUVPNMenuAppTestHarness/main.swift`

**Interfaces:**
- Implements `LoginItemControlling` through `SMAppService.mainApp`.
- Uses `UserDefaults` key `hyu.vpn.launchAtLogin.userChoice` only to distinguish first launch from an explicit off choice; `SMAppService.status` remains runtime truth.
- CLI `--unregister-login-item` allows the uninstaller to unregister before removing the bundle.

- [ ] **Step 1: Add failing Swift tests for all `SMAppService.Status` projections**

Cover enabled, not registered, requires approval, not found, register failure, unregister failure, and System Settings action. Verify the menu checkmark/title are derived from the adapter state.

- [ ] **Step 2: Add failing installer/package tests for single login owner**

```python
self.assertFalse((staged / "config/launchd/com.hyu.vpn.menubar.plist.in").exists())
self.assertNotIn("com.hyu.vpn.menubar.plist", installed_paths)
self.assertIn("--unregister-login-item", uninstall_source)
self.assertIn("SMAppService.mainApp", swift_source)
self.assertIn("write(True)", install_source)
```

Also assert the exact legacy plist is backed up, booted out, and removed during upgrade while `com.hyu.vpn.service.plist` remains installed and bootstrapped.

- [ ] **Step 3: Run focused tests and confirm failure**

Run:

```bash
python3 -m unittest tests.test_installer tests.test_packaging -v
cd macos && swift run hyu-vpn-menu-harness
```

Expected: old menu plist and false auto-reconnect assertions fail.

- [ ] **Step 4: Implement the ServiceManagement adapter and first-launch default**

Map `SMAppService.mainApp.status` into Task 2 states. Enable with `register()`, disable with `unregister()`, and call `SMAppService.openSystemSettingsLoginItems()` only for approval-required status. First launch attempts registration unless the explicit-choice preference is false.

- [ ] **Step 5: Remove the menu LaunchAgent from new payloads and migrate the exact legacy job transactionally**

Delete the template and staging requirement. In the root phase, operate only on `$HOME/Library/LaunchAgents/com.hyu.vpn.menubar.plist`: boot out the exact label, back up the file, remove it, and record rollback state. Continue rendering/chowning only `com.hyu.vpn.service.plist`.

- [ ] **Step 6: Make install default-on and open the app once**

Write `AutoReconnectPreference(...).write(True)`, bootstrap/kickstart only the service LaunchAgent, then launch `/Applications/HYU VPN.app` with fixed `/usr/bin/open -gj -a`. Require one exact menu process but do not create or bootstrap another menu LaunchAgent.

- [ ] **Step 7: Unregister before uninstall**

From the user phase, invoke the exact installed app executable with `--unregister-login-item`, tolerate only “not registered/not found”, terminate the menu process, then enter the existing sudo uninstall phase.

- [ ] **Step 8: Run installer/package and Swift tests**

Run:

```bash
python3 -m unittest tests.test_installer tests.test_packaging -v
cd macos
swift test
swift run hyu-vpn-menu-harness
```

Expected: all migration, single-owner, and login-state tests pass.

- [ ] **Step 9: Commit Task 5**

```bash
git add macos/Sources/HYUVPNMenuApp installer launchd tests/test_installer.py tests/test_packaging.py
git -c user.name=shchoi00 -c user.email=shchoi00@hanyang.ac.kr commit -m "feat: add native launch at login control"
```

---

### Task 6: Full regression, target integration, packaging, and controlled live proof

**Files:**
- Modify only files required by failures directly attributable to Tasks 1–5.
- Create release evidence under a new current-only output directory outside Git.

**Interfaces:**
- Consumes all prior tasks.
- Produces one verified current DMG and one concise current-release pointer; no old version accumulation.

- [ ] **Step 1: Run complete offline gates**

Run:

```bash
cd macos
swift test
swift run hyu-vpn-helper-test-harness
swift run hyu-vpn-menu-harness
swift build -c release
cd ..
python3 -m unittest discover -s tests -v
python3 -m compileall -q src bin tests installer scripts
zsh -n installer/install.sh installer/root-admin.sh installer/uninstall.sh 'installer/Install HYU VPN.command' 'installer/Uninstall HYU VPN.command'
sh -n scripts/preflight.sh scripts/assemble-app.sh privileged/hyu-vpnc-wrapper
bash -n tests/live_acceptance.sh tests/live_acceptance_gate.sh
plutil -lint launchd/com.hyu.vpn.service.plist.in macos/Resources/HYUVPNMenuApp/Info.plist
git diff --check
```

Expected: every command exits 0; helper/menu harnesses print explicit PASS counts.

- [ ] **Step 2: Run independent code review and security review**

Review changed code for secret lifetime, rollback correctness, termination races, `SMAppService` state handling, legacy plist allowlisting, and any path that could start two menu processes. Resolve every high/medium correctness finding before packaging.

- [ ] **Step 3: Assemble and verify the app locally without installing**

Build the app through `scripts/assemble-app.sh`, verify `LSUIElement`, `codesign --verify --deep --strict`, arm64 architecture, fixed dependencies, and the absence of the legacy menu LaunchAgent from the staged payload.

- [ ] **Step 4: Exercise `SMAppService.mainApp` on the target Mac**

With the signed app in `/Applications`, read status, register, verify `.enabled` or `.requiresApproval`, unregister, and verify `.notRegistered`. If ad-hoc signing returns invalid signature, stop release packaging and fix the signing/distribution decision rather than installing a hidden LaunchAgent fallback.

- [ ] **Step 5: Package one current DMG and independently verify it**

Run the existing package pipeline with metadata bound to current `HEAD`. Verify manifest exactness, SHA-256 sidecar, `hdiutil verify`, all Mach-O architectures/dependencies, signatures, source bundle, and that no legacy menu plist exists.

- [ ] **Step 6: Perform controlled install and live lifecycle validation**

Snapshot current DNS/default route/helper/session. Install the new DMG, verify one menu process, login-item status, auto-connect, HIP success, protected route/DNS through the tunnel, and public HTTPS. Exercise Reconnect. Exercise Disconnect and prove helper stopped, OpenConnect absent, DNS/default route restored, and app remains. Relaunch/Connect and prove automatic reconnection resumes.

- [ ] **Step 7: Perform controlled Quit proof**

While connected, choose/invoke the same Quit path. Prove the app does not exit before disconnect completes, then prove menu process absent, helper stopped, OpenConnect absent, DNS/default route restored, and public HTTPS succeeds. Relaunch the app and prove it automatically connects again.

- [ ] **Step 8: Exercise GUI credential validation without changing real secrets**

Use mismatch and blank-optional-TOTP paths only against the installed GUI to prove no Terminal opens, validation stays native, and no Keychain write occurs. Use fake-store harness evidence for successful/rollback secret transactions unless the user intentionally supplies replacement credentials.

- [ ] **Step 9: Final cleanup and release commit**

Keep only the new current DMG, checksum, source bundle, installer log, and live validation evidence. Delete superseded intermediate build directories outside Git. Commit any final source/test fixes with `shchoi00 <shchoi00@hanyang.ac.kr>` and verify `.omx/` is not staged.

---

## Plan Self-Review

- Every approved UX requirement maps to Tasks 1–5.
- Network/helper code is explicitly excluded and remains protected by the existing helper harness.
- GUI credential confirmation, optional TOTP retention, Keychain rollback, and no-terminal/no-argv constraints are testable.
- Login-at-login has one owner only and includes upgrade/uninstall paths.
- Live validation distinguishes ordinary Disconnect from controlled Quit.
- No placeholder tasks or unspecified “handle errors” steps remain.
