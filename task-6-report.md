# Task 6 Report: Swift direct Rust IPC control path

## Scope

Replaced the Swift menu app's legacy `hyu-vpn-control`/shell execution path with a direct Unix-domain socket client for the Rust macOS service, using schema-v1 big-endian length-prefixed JSON frames generated from Rust-owned fixtures.

## RED evidence

Observed during strict TDD before implementation:

1. Fixture generation did not exist, so Swift had no Rust-owned golden protocol inputs.
2. `swift test --package-path macos --filter RustIPCClientTests --no-parallel` failed at compile time after adding Task 6 tests because Task 6 production symbols were missing, including representative errors for:
   - `cannot find 'VPNCommand' in scope`
   - `cannot find 'VPNResponse' in scope`
   - `cannot find 'VPNServiceError' in scope`
   - `cannot find 'CredentialInput' in scope`
   - `cannot find 'RustIPCClient' in scope`
3. After initial implementation, `swift run --package-path macos hyu-vpn-menu-harness </dev/null` failed first on stale menu-copy/source-contract expectations (`menu/icon contract contains OTP:`), then on credential validation/lifecycle expectations (`TOTP_SEED_REQUIRED`, `successful completion returns value and clears fields`) until the harness was updated to the new direct-service contract.

## Implemented behavior

- Added Rust fixture generator:
  - `rust/crates/hyu-vpn-protocol/examples/generate_swift_fixtures.rs`
- Generated golden protocol JSON/frame fixtures under `tests/fixtures/protocol/` from Rust codecs only.
- Added strict Swift protocol/request-response layer:
  - `macos/Sources/HYUVPNMenuCore/RustProtocol.swift`
- Added direct Unix socket client:
  - `macos/Sources/HYUVPNMenuCore/RustIPCClient.swift`
- Security/contract details implemented:
  - big-endian `u32` frame prefix
  - exact schema version/request-id matching
  - strict top-level key validation and unknown/version rejection
  - bounded connect/write/read/total timeouts
  - bounded maximum response size
  - socket parent/file owner/mode/symlink/type validation
  - serial background queue with main-thread completions
  - no raw backend error payload leakage
  - secret-bearing request data kept out of `CustomStringConvertible`/debug strings; buffers zeroed where feasible
- Rewired production app flow to injected `VPNServiceRequesting`:
  - connect/disconnect/reconnect/status/current OTP/automatic preference
  - credential replacement as a single service transaction
  - current OTP/countdown/copy behavior preserved in the menu UI
- Removed legacy production command-runner path from the Task 6 Swift surface.

## GREEN evidence

### Fixture / static / formatting

- `cargo fmt --all -- --check` → PASS
- `cargo run -q -p hyu-vpn-protocol --example generate_swift_fixtures` → PASS
- `git diff --exit-code -- tests/fixtures/protocol` immediately after regeneration → PASS
- `cargo clippy -p hyu-vpn-protocol -p hyu-vpn-macos-service --all-targets -- -D warnings` → PASS
- `git diff --check` → PASS
- `git grep -n -E 'hyu-vpn-control|Process\(|usesShell' -- macos/Sources/HYUVPNMenuApp macos/Sources/HYUVPNMenuCore` → no matches

### Rust protocol / service tests

- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-macos-service --all-targets` → PASS
  - `hyu-vpn-protocol` tests: 9 passed
  - `hyu-vpn-macos-service` runtime tests: 26 passed

### Swift package / harnesses

- `swift test --package-path macos --filter RustIPCClientTests --no-parallel` → PASS
- `swift test --package-path macos --no-parallel` → PASS
- `swift run --package-path macos hyu-vpn-helper-test-harness </dev/null` → PASS (`HARNESS PASS 71 tests`)
- `swift run --package-path macos hyu-vpn-menu-harness </dev/null` → PASS (`HARNESS PASS 37 tests`)
- `swift run --package-path macos hyu-vpn-installer-harness </dev/null` → PASS
- `macos/Scripts/test-wrapperd-closed-stderr.sh </dev/null` → PASS

## Review fix round 1: OTP preview semantics, request IDs, EINTR/deadline, peer trust, stale refreshes

### RED evidence

1. New Rust OTP preview tests initially failed to compile because `current_otp_preview` did not exist:
   - `error[E0432]: unresolved import 'hyu_vpn_macos_service::current_otp_preview'`
2. New Swift runtime coverage initially failed to compile because the new deterministic IPC seams and refresh coordinator were absent:
   - `cannot find 'SequencedSocketMetadataProvider' in scope`
   - `cannot find 'ServiceRefreshCoordinator' in scope`
3. After adding explicit harness coverage, `swift run --package-path macos hyu-vpn-menu-harness </dev/null` failed RED on missing per-command ACK fixtures:
   - `The file “connect-ack-response-v1.frame” couldn’t be opened because there is no such file.`
4. An intermediate real-socket harness attempt exposed an unavailable-path regression before the deterministic harness was finalized:
   - `fixture ack request swift-connect-1: failure(HYUVPNMenuCore.VPNServiceError.unavailable)`

### Implemented behavior in fix round 1

- Added non-reserving OTP preview on the Rust macOS service path while keeping reservation for the connector start path.
- Added Rust tests proving:
  - repeated preview in the same counter succeeds
  - preview does not consume the counter
  - reservation anti-reuse still holds after preview
- Extended the Rust fixture generator with per-command ACK response fixtures whose request IDs match the command fixtures:
  - connect/disconnect/reconnect/automatic-on/automatic-off/replace-credentials ACK frames
- Added deterministic Swift IPC seam coverage for:
  - request-ID mismatch rejection
  - EINTR retry handling under one monotonic absolute deadline
  - peer/socket post-connect revalidation before any credential bytes are sent
- Switched the Swift IPC client from `Date`-based timeout accounting to monotonic nanosecond deadlines.
- Revalidated the socket path after connect and checked peer effective UID before writing request payload bytes.
- Added `ServiceRefreshCoordinator` and updated `AppDelegate` so:
  - launch no longer double-forces the initial refresh
  - only one refresh generation is active at a time
  - queued forced refreshes suppress stale status/OTP application
  - stale completions cannot overwrite current menu state
- Extended the explicit menu harness with deterministic Rust IPC runtime cases, repeated passive OTP polling/copy coverage, and stale-refresh sequencing coverage.

### GREEN evidence for fix round 1

#### Rust

- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → PASS
  - `hyu-vpn-core`: 21 passed
  - `hyu-vpn-daemon`: 8 passed
  - `hyu-vpn-macos-service`: 27 passed
  - `hyu-vpn-platform-macos`: 44 passed
  - `hyu-vpn-protocol`: 9 passed
- `cargo clippy --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets -- -D warnings` → PASS

#### Swift / harnesses

- `swift test --package-path macos --filter RustIPCClientTests --no-parallel` → PASS (SwiftPM emits build-only success output in this package)
- `swift test --package-path macos --no-parallel` → PASS (SwiftPM emits build-only success output in this package)
- `swift run --package-path macos hyu-vpn-helper-test-harness </dev/null` → PASS (`HARNESS PASS 71 tests`)
- `swift run --package-path macos hyu-vpn-menu-harness </dev/null` → PASS (`HARNESS PASS 40 tests`)
  - includes explicit `rust-ipc-client-runtime-fixtures-and-request-ids`
  - includes explicit `passive-otp-preview-polling-preserves-snapshot-countdown-copy`
  - includes explicit `service-refresh-coordinator-drops-stale-forced-results`
- `swift run --package-path macos hyu-vpn-installer-harness </dev/null` → PASS
- `macos/Scripts/test-wrapperd-closed-stderr.sh </dev/null` → PASS
- `git grep -n -E 'hyu-vpn-control|Process\(|usesShell' -- macos/Sources/HYUVPNMenuApp macos/Sources/HYUVPNMenuCore` → no matches
- `git diff --check` → PASS

## Changed files

- `macos/Sources/HYUVPNMenuApp/AppDelegate.swift`
- `macos/Sources/HYUVPNMenuApp/CredentialResetController.swift`
- `macos/Sources/HYUVPNMenuCore/ControlTowerCore.swift`
- `macos/Sources/HYUVPNMenuCore/MenuCore.swift`
- `macos/Sources/HYUVPNMenuCore/RustIPCClient.swift`
- `macos/Sources/HYUVPNMenuCore/RustProtocol.swift`
- `macos/Tests/HYUVPNMenuAppTestHarness/main.swift`
- `macos/Tests/HYUVPNMenuAppTests/HYUVPNMenuAppTests.swift`
- `macos/Tests/HYUVPNMenuAppTests/RustIPCClientTests.swift`
- `rust/apps/hyu-vpn-macos-service/src/lib.rs`
- `rust/apps/hyu-vpn-macos-service/tests/service_runtime.rs`
- `rust/crates/hyu-vpn-protocol/examples/generate_swift_fixtures.rs`
- `tests/fixtures/protocol/*`

## Residual risk

- `swift test` itself emits only the SwiftPM build summary in this package; detailed behavioral evidence comes from the dedicated harnesses and the Rust protocol/service suites above.
- The explicit menu harness now carries deterministic Rust IPC runtime coverage so the task no longer depends on silent Swift Testing output alone.
- No live service/helper/VPN/network/credential reads were performed; integration with a real running service still depends on the service honoring the same validated protocol/socket contracts covered here.
