# Task 3 Report — AppKit control tower, startup auto-connect, diagnostics, safe quit

## Changed files

- `macos/Sources/HYUVPNMenuApp/main.swift` — split bootstrap/argv gate before `NSApplication.shared`; recognized login-item commands return explicit unavailable exit.
- `macos/Sources/HYUVPNMenuApp/AppDelegate.swift` — new AppKit owner for status item, watcher, startup connect, explicit disconnect pause/handoff, diagnostics alert, accessibility label/help, and guarded quit flow.
- `macos/Sources/HYUVPNMenuCore/ControlTowerCore.swift` — exposed read-only `OperationGate` state for UI gating.
- `macos/Sources/HYUVPNMenuCore/MenuCore.swift` — fixed control-runner/client contract: bounded stdout capture with overflow tracking, shared strict top-level JSON helpers, strict CLI JSON decoding/allowlist, malformed+overflow fallback to `CONTROL_EXIT_n`.
- `macos/Tests/HYUVPNMenuAppTests/HYUVPNMenuAppTests.swift` — added focused control-JSON normalization and overflow fallback coverage.
- `macos/Tests/HYUVPNMenuAppTestHarness/main.swift` — added Task 3 source-contract/runtime checks for bootstrap split, menu copy/order/icon contract, startup retry/pause handoff, quit interception, accessibility label/help, strict control JSON normalization, and overflow fallback.

## RED evidence

### First harness RED after Task 3 tests

Command:

```bash
cd macos && swift run hyu-vpn-menu-harness
```

Output excerpt before production changes:

```text
HARNESS FAIL: control unavailable normalized
RUN strict-status-all-states-and-corrupt
PASS strict-status-all-states-and-corrupt
RUN status-file-security
PASS status-file-security
RUN presentation-symbols-and-title-rule
PASS presentation-symbols-and-title-rule
RUN dynamic-menu-actions-and-checks
PASS dynamic-menu-actions-and-checks
RUN primary-action-disabled-transient-states
PASS primary-action-disabled-transient-states
RUN live-menu-omits-unimplemented-actions
PASS live-menu-omits-unimplemented-actions
RUN control-security-timeout-and-normalized-errors
```

This exposed the confirmed scope-expansion bug: `SystemControlProcessRunner` discarded stdout and `SecureVPNControlClient` collapsed strict JSON failures to `CONTROL_EXIT_1`, so startup retry could not distinguish `CONTROL_UNAVAILABLE` from `REPAIR_REQUIRED`.

### Additional compile RED while tightening AppDelegate

Command:

```bash
cd macos && swift test --filter HYUVPNMenuAppTests
```

Output excerpt during the first AppDelegate build:

```text
AppDelegate.swift:219:17: error: capture of 'completion' with non-Sendable type '((ControlResult) -> Void)?' in a '@Sendable' closure
```

I removed the captured callback and replaced it with enum-driven follow-up handling inside `runControl`.

## GREEN evidence

Required command set actually run after the final fixes:

```bash
cd macos && swift test --filter HYUVPNMenuAppTests
cd macos && swift run hyu-vpn-menu-harness
cd macos && swift build
cd macos && swift build -c release
cd .. && git diff --check
```

Observed outputs:

### `swift test --filter HYUVPNMenuAppTests`

```text
Building for debugging...
[4/12] Compiling HYUVPNMenuApp main.swift
[5/12] Compiling HYUVPNMenuApp AppDelegate.swift
[6/12] Emitting module HYUVPNMenuApp
[10/13] Compiling HYUVPNMenuAppTests HYUVPNMenuAppTests.swift
[11/13] Emitting module HYUVPNMenuAppTests
Build complete! (1.46s)
```

On this toolchain, the filtered Swift Testing command exited `0` and produced build-only output; it did not emit per-test case lines.

### `swift run hyu-vpn-menu-harness`

```text
RUN strict-status-all-states-and-corrupt
PASS strict-status-all-states-and-corrupt
RUN status-file-security
PASS status-file-security
RUN presentation-symbols-and-title-rule
PASS presentation-symbols-and-title-rule
RUN dynamic-menu-actions-and-checks
PASS dynamic-menu-actions-and-checks
RUN primary-action-disabled-transient-states
PASS primary-action-disabled-transient-states
RUN live-menu-omits-unimplemented-actions
PASS live-menu-omits-unimplemented-actions
RUN control-security-timeout-and-normalized-errors
PASS control-security-timeout-and-normalized-errors
RUN bootstrap-splits-appkit-and-argument-gate
PASS bootstrap-splits-appkit-and-argument-gate
RUN control-tower-menu-copy-and-icon-contract
PASS control-tower-menu-copy-and-icon-contract
RUN startup-connect-and-disconnect-pause-contract
PASS startup-connect-and-disconnect-pause-contract
RUN safe-quit-and-diagnostics-contract
PASS safe-quit-and-diagnostics-contract
...
HARNESS PASS 33 tests
```

### `swift build`

```text
Building for debugging...
Build complete! (0.07s)
```

### `swift build -c release`

```text
Building for production...
[7/11] Linking HYUVPNMenuApp
[10/11] Linking hyu-vpn-menu-harness
Build complete! (4.23s)
```

### `git diff --check`

Exited `0` with no output.

## Self-review

- The privileged/network boundary stayed intact: no helper/DNS/route/SystemConfiguration mutation code was added.
- App bootstrap now validates argv before touching `NSApplication.shared` and does not create a LaunchAgent fallback for login items.
- The status item is icon-only with explicit textual tooltip plus button accessibility label/help; state is not conveyed by icon alone.
- Startup connect uses `StartupConnectPolicy` and now receives real normalized control codes from strict CLI JSON when available.
- Explicit disconnect now pauses startup reconnect and survives an in-flight startup connect via pending handoff instead of being dropped by the gate.
- Quit uses normal AppKit termination interception, performs exactly one guarded disconnect attempt with `timeout: 15`, and never calls `NSApp.terminate(nil)`.
- Diagnostics remain allowlisted and normalized; raw stdout/stderr never reaches menu text or diagnostics.
- Control stdout overflow is now tracked so truncated valid-looking JSON cannot be decoded into a false normalized error.

## Race / normalization concerns

- `swift test --filter HYUVPNMenuAppTests` did not emit per-test runtime lines on this local Swift Testing toolchain, so the executable harness is the strongest runtime evidence captured here.
- Startup retry classification is intentionally strict: only allowlisted strict JSON failures (`BAD_REQUEST`, `INTERNAL_ERROR`, `REPAIR_REQUIRED`, `CONTROL_UNAVAILABLE`) are decoded, and overflow/malformed output falls back to `CONTROL_EXIT_n`.
- Because backend startup absence may still surface as a specific launch failure or exit code depending on the service state, startup retries are limited to `CONTROL_LAUNCH_FAILED` and `CONTROL_UNAVAILABLE`; other codes stop retrying and are recorded only as normalized results.
- The explicit-disconnect handoff closes the known startup-connect race inside one process, but full behavioral confidence for real AppKit termination paths still depends on interactive macOS integration exercise outside this harness.
