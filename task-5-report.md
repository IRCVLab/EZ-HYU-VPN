# Task 5 Report: Per-user Rust macOS service

## RED
- Added `rust/apps/hyu-vpn-macos-service/tests/service_runtime.rs` before production implementation.
- Initial RED command: `cargo test -p hyu-vpn-macos-service --test service_runtime`.
- Observed expected compile failures: unresolved `AutomaticPreference`, `MacActionExecutor`, `ServiceConfig`, `ServiceError`, `bind_owner_socket`, `current_otp_reserved`, `peer_uid_authorized_for_test`, `reconcile_helper_at_startup`, `run_health_check`, `NetworkReadinessTracker`, and `run_service` because the service crate API did not exist yet.

## GREEN
- Added `hyu-vpn-macos-service` workspace crate with:
  - owner-only Unix socket binding (`0700` parent, `0600` socket) and macOS `LOCAL_PEERCRED` authorization;
  - `AutomaticPreference` atomic `0600` storage with symlink rejection;
  - `MacActionExecutor` over the approved Task 4 owned `HelperSessionRunner::start_session` API;
  - helper startup reconciliation that stops stale running helper state and surfaces repair/failure outcomes;
  - daemon framing/status handling with schema-v1 responses and status-file projection;
  - current OTP reservation through `CounterGuard` without exposing credentials/seeds in status/debug;
  - cancellable retry and owned-generation stop handling;
  - production wiring for `MacPaths`, `MacCredentialRepository`, `MacNetworkMonitor`, `MacPortalProbe`, and `InstalledHelperRunner`.
- No live sudo/helper/VPN/network mutation was performed; service tests use deterministic fakes and temporary paths only.

## Verification
- `cargo fmt --all -- --check` → PASS.
- Targeted RED: `cargo test -p hyu-vpn-macos-service --test service_runtime` → initial compile RED for missing Task 5 API.
- Targeted GREEN: `cargo test -p hyu-vpn-macos-service --test service_runtime` → PASS: 10 passed, 0 failed.
- Service all-targets: `cargo test -p hyu-vpn-macos-service --all-targets` → PASS: service runtime 10 passed plus lib/main unit targets.
- Locked regression: `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → PASS.
- Clippy: `cargo clippy -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets -- -D warnings` → PASS.
- Diff hygiene: `git diff --check` → PASS.

## Risks / Notes
- Deterministic tests do not launch the installed helper, sudo, OpenConnect, or mutate routes/DNS.
- Live helper cleanup, real VPN connectivity, Swift client integration, launchd packaging, and installer activation remain later task/live-acceptance gates.

---

## Code Review Addendum (Task 5, base 7b71311 → head 10d67475)

**Verdict:** REQUEST CHANGES

**Validation run (non-live only):**
- `cargo fmt --all -- --check` → PASS.
- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo check -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo clippy -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets -- -D warnings` → PASS.
- `git diff --check 7b71311..10d67475` → PASS.
- Requested-pattern `ast-grep` scans for `console.log`, empty `catch`, and hardcoded `apiKey` found no matches. `rust-analyzer diagnostics` is unavailable for the active toolchain (`infinite recursion detected`), so `cargo check`/Clippy were used as the type/diagnostic gate.

### Issues

[HIGH] Production shutdown can terminate without cleanly cancelling/awaiting the retained helper start session.

- File: `rust/apps/hyu-vpn-macos-service/src/main.rs:21-26`; `rust/apps/hyu-vpn-macos-service/src/lib.rs:344-393`; `rust/apps/hyu-vpn-macos-service/src/lib.rs:770-773`
- Issue: `main` only converts `tokio::signal::ctrl_c()` into graceful shutdown, but launchd/service stop normally arrives as SIGTERM; the default SIGTERM action can kill the process before `run_service` reaches `executor.stop_all()`. Even on the internal shutdown path, `MacActionExecutor` spawns helper-session tasks without retaining join handles, and `run_service` only sends cancellation then awaits the daemon runtime, not the active session task(s). This means the approved Task 4 `HelperStartSession::cancel()`/`wait()` cleanup evidence is not guaranteed to complete before the service exits.
- Risk: A launchd stop, upgrade, logout, or health-check shutdown can leave helper/OpenConnect cleanup to process teardown/drop behavior instead of the explicit helper-owned SIGTERM/status/repair/status path Task 4 established. That violates Task 5's clean-shutdown/no-leaked-tasks and retained-session lifecycle requirements.
- Fix: Handle SIGTERM/SIGHUP/termination in production `main`, route all exits through the shutdown watch, store start-session `JoinHandle`s or explicit session handles per generation, and on `run_service` shutdown send cancels then boundedly await each session's `wait()` outcome before returning. Add a non-live fake session test that blocks until `cancel` is observed and proves `run_service` does not return until the session cleanup outcome has been collected.

[HIGH] Helper `RepairRequired`/cleanup-failure outcomes are flattened into a generic connector exit, causing automatic retry instead of surfacing repair state.

- File: `rust/apps/hyu-vpn-macos-service/src/lib.rs:452-465`
- Issue: `outcome_to_exit` maps `HelperSessionOutcome::RepairRequired`, `Failed`, and `FailedWithCleanup` with `RepairRequired`/`Failed`/`CleanupFailed` cleanup into `(return_code: 2, runtime_seconds: 0)`. The shared engine treats any nonzero connector exit with automatic reconnect and available network as Backoff + `ScheduleRetry`, so the service will retry rather than publish `ErrorCode::RepairRequired`/service failure or stop the unsafe loop.
- Risk: A helper cleanup/repair-required condition can be masked as an ordinary transient connection failure. The daemon may repeatedly start new generations against a helper state that Task 4 explicitly reported as requiring repair or failed cleanup.
- Fix: Preserve the Task 4 outcome class across the service boundary. Add an engine/status path for repair-required/service-unavailable outcomes (for example `VpnState::Error` with `ErrorCode::RepairRequired`), cancel pending retry, and do not start another generation until repair/status reconciliation succeeds. Add tests for `RepairRequired`, `Failed`, and `FailedWithCleanup { cleanup: ... }` proving no retry is scheduled and the status/error mapping is visible.

[MEDIUM] macOS peer authorization is not exact UID-only because root is accepted as a peer.

- File: `rust/apps/hyu-vpn-macos-service/src/lib.rs:590-611`; test expectation at `rust/apps/hyu-vpn-macos-service/tests/service_runtime.rs:156-160`
- Issue: `peer_uid_authorized_for_test` returns true for `peer_uid == 0` even when the socket owner is a non-root user, and `authorize_stream` uses that helper for every `LOCAL_PEERCRED` result. The Task 5 brief/user review scope called for exact UID authorization on every connection.
- Risk: Root-owned unrelated processes can drive the per-user lifecycle socket despite the intended owner-only IPC contract. Root is privileged, but this still violates the exact peer-UID gate and weakens auditability of the service authority boundary.
- Fix: Require `peer_uid == owner_uid` (and reject `owner_uid == 0` for a per-user service unless explicitly supported). Update the test to assert root is rejected when the owner UID is non-root, and add an integration-style accept/reject test around the macOS `LOCAL_PEERCRED` path where feasible.

[MEDIUM] Health check only waits for the socket path to exist; it does not prove schema-v1 IPC, auth, or status handling works.

- File: `rust/apps/hyu-vpn-macos-service/src/lib.rs:780-801`; weak assertion at `rust/apps/hyu-vpn-macos-service/tests/service_runtime.rs:488-493`
- Issue: `run_health_check` reports success as soon as `socket.exists()` becomes true. It never connects to the owner socket, sends a framed schema-v1 `Status` request, verifies the response/request ID, or validates that `serve_owner_socket`/`serve_connection` is accepting authorized clients.
- Risk: Packaging/installer code can treat a stale or merely bound socket as a healthy backend even if peer authorization, framing, protocol decode, request handling, or status publication is broken.
- Fix: Replace the path-exists probe with a bounded real local IPC status request using `hyu_vpn_protocol::encode_request`/`decode_response`; require matching request ID, `Response::Status`, schema version 1, and clean shutdown afterward. Add tests that fail if the socket exists but no valid response is served.

[LOW] The credential-replacement/backoff test does not exercise backoff or verify the replacement credentials reach `start_session`.

- File: `rust/apps/hyu-vpn-macos-service/tests/service_runtime.rs:381-435`
- Issue: The test sends `Connect` without publishing network readiness, so no helper start/backoff generation is created; then it asserts only that debug-formatted helper call names do not contain `old-password`, but `FakeHelper::start_session` discards `HelperStartInput` and never records usernames/passwords. This can pass even if replacement during backoff does not cancel a retry or if a later start still uses stale credentials.
- Risk: One of Task 5's named requirements is effectively untested, making regressions in credential replacement during retry/backoff easy to miss.
- Fix: Drive the control plane into Backoff with a ready network and a failed generation, replace credentials, then assert the old retry is cancelled and the next fake `start_session` receives the new username/secret through a redacted test seam (without exposing the password in logs/debug output).

### Recommendation

REQUEST CHANGES. The Rust checks pass, and the implementation uses the approved Task 4 start-session API rather than a placeholder, but the shutdown/session lifecycle and repair-required mapping are load-bearing Task 5 blockers. Fix those before treating the service as merge-ready.

---

## Fix Round 1: Review findings resolved

### RED
- Added failing service-runtime coverage first, then ran `cargo test -p hyu-vpn-macos-service --test service_runtime`.
- Observed RED compile/test failures for missing `shutdown_sessions_for_test`, retained session counting, health-check socket validation, `ServiceConfig::for_test_with_network`, exact root peer rejection, repair outcome/status handling, and stronger credential-replacement/backoff assertions.

### Resolutions
1. **Clean shutdown/session retention**
   - Production main now routes SIGINT, SIGTERM, and SIGHUP into the shutdown watch.
   - `MacActionExecutor` retains per-generation cancel senders and join handles.
   - `run_service` drains active sessions on shutdown, sends cancel, and boundedly awaits cleanup outcomes before returning.
   - Shutdown failure/timeout returns `ServiceError::Failed`.
2. **Repair-required/error preservation**
   - Added shared `EngineEvent::ConnectorError` and `EngineAction::PublishError` support.
   - Repair-required/helper cleanup failures now publish stable `VpnState::Error` with `ErrorCode::RepairRequired` or `ServiceUnavailable` instead of ordinary retry backoff.
   - New starts are blocked behind helper status/repair/status reconciliation.
3. **Exact peer authorization**
   - Peer authorization is now exact owner UID only; root is rejected for non-root per-user sockets.
4. **Real health check**
   - Health check now performs a bounded framed schema-v1 `Status` request over the owner socket and validates matching request ID plus `Status` response.
   - Added unavailable/malformed socket tests.
5. **Credential replacement during real backoff**
   - Strengthened deterministic fake-helper test to drive a failed generation, cancel retry, start immediately after replacement, and verify the new start input uses the replacement username marker without exposing password markers.

### GREEN / Verification
- `cargo test -p hyu-vpn-macos-service --test service_runtime` → PASS: 18 passed, 0 failed.
- `cargo test -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo fmt --all -- --check` → PASS.
- `cargo clippy -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets -- -D warnings` → PASS.
- `git diff --check` → PASS.

### Remaining risk
- Still deterministic/non-live only: no sudo, installed helper, OpenConnect, route/DNS mutation, or real credential reads were performed.

---

## Code Review Addendum: Fix Round 1 Re-review (2026-08-12)

**Verdict:** REQUEST CHANGES

**Review scope:** fix package `10d6747..330a45a` / `.superpowers/sdd/2026-08-08-hyu-vpn-macos-rust-backend/review-task5-fix1.diff`, current Task 5 service code/tests, and shared `hyu-vpn-core`/`hyu-vpn-daemon` state/runtime changes.

**Validation run (non-live only):**
- `git diff --check 10d6747..330a45a` → PASS.
- `cargo fmt --all -- --check` → PASS.
- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo check -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo clippy -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets -- -D warnings` → PASS.
- Requested-pattern `ast-grep` scans for `console.log`, empty `catch`, and hardcoded `apiKey` found no matches.
- `rust-analyzer diagnostics` is unavailable for the active toolchain (`infinite recursion detected`), so `cargo check`/Clippy were used as the diagnostic gate.
- Cross-platform check note: `cargo check -p hyu-vpn-linux-service --all-targets` cannot run on this macOS host because existing Linux-only `libc::ucred`/`SO_PEERCRED`/`TcpSocket::bind_device` APIs are not available; this appears platform-target related rather than caused by the shared enum additions. The macOS-selected locked suite did compile the shared core/daemon changes.

### Prior findings status

- **Signal shutdown / retained sessions:** partially fixed. SIGINT/SIGTERM/SIGHUP are now routed into the shutdown watch, and session join handles are retained. However, completed session controls are never removed, which creates a new load-bearing shutdown bug below.
- **Cleanup outcome propagation / repair-required mapping:** mostly fixed. Helper `RepairRequired` and failed cleanup outcomes now become `ConnectorError` and publish `VpnState::Error` with `RepairRequired`/`ServiceUnavailable` instead of ordinary retry backoff.
- **Repair block before reconnect:** acceptable direction. New starts behind a repair block call helper reconciliation before launching another helper session.
- **Exact UID authorization:** fixed for the explicit policy (`owner_uid != 0 && peer_uid == owner_uid`).
- **Framed health check:** improved from path existence to framed schema-v1 `Status`, but the implementation is still not a reliable bounded service health check; see finding below.
- **Credential replacement during backoff:** improved. The new test verifies replacement username reaches the next fake start after cancel/start sequencing, and the shared daemon test already covers `ReplaceCredentials` cancelling a real engine backoff. The older weak test remains but is no longer the only coverage.

### Issues

[HIGH] Completed session controls are never removed, so ordinary failed sessions make later service shutdown fail and the map leaks one entry per attempt.

- File: `rust/apps/hyu-vpn-macos-service/src/lib.rs:409-452`, `rust/apps/hyu-vpn-macos-service/src/lib.rs:498-519`
- Issue: the session task publishes its outcome at lines 426/443 but never removes its generation from `self.sessions`; the map is only drained during `shutdown_sessions`. If a connection attempt exits normally with `Exited { status: 1 }`, that completed join handle stays in the map. Later, a completely ordinary service shutdown calls `shutdown_sessions`, awaits the already-completed join, sees the historical non-clean outcome, and returns `ServiceError::Failed` even though the failure was already reported to the engine/backoff path. Long-running retry/backoff cycles also accumulate stale `SessionControl` entries indefinitely.
- Risk: after any transient connection failure, launchd/logout/upgrade shutdown can exit the service as failed; repeated failures leak retained join outputs/cancel senders for the lifetime of the daemon. This violates the fix's retained-session/no-leaked-task goal and can turn normal retry history into a shutdown failure.
- Fix: remove each generation from the session table when the session task completes, or have a supervisor/reaper own the join handle and evict completed generations before publishing the final event. `shutdown_sessions` should only cancel/await currently active sessions; it should not reinterpret already-published historical connector failures as shutdown failures. Add a test that starts a generation returning `Exited { status: 1 }`, observes the `ConnectorExited` event, asserts `active_session_count_for_test() == 0`, then verifies `shutdown_sessions(...)` succeeds and no retry/session entries remain.

[MEDIUM] Health check is still not a bounded readiness check because it performs exactly one connect attempt and then awaits service shutdown outside the timeout.

- File: `rust/apps/hyu-vpn-macos-service/src/lib.rs:905-915`, `rust/apps/hyu-vpn-macos-service/src/lib.rs:918-963`
- Issue: `run_health_check` spawns the service and immediately calls `run_health_check_socket`; that helper performs a single `UnixStream::connect(path)`. If startup is still in `reconcile_helper_at_startup` or has not bound the socket yet, an initial `ENOENT`/connection failure returns immediately instead of retrying until the health-check deadline. Also, the timeout only wraps the one socket operation; `service.await` after sending shutdown is unbounded relative to the caller's `timeout`.
- Risk: production health checks can fail fast on a healthy-but-still-starting service, especially because real helper status/reconciliation is slower than the deterministic fake tests. Conversely, a stuck startup/shutdown path can exceed the requested health-check bound.
- Fix: make the health check a deadline-driven loop: retry connect + framed `Status` until the deadline, validate request ID/schema/status on success, then signal shutdown and boundedly await service termination within the remaining or separate documented cleanup budget. Add tests where binding is delayed but succeeds before the deadline, and where service shutdown hangs to prove the public `timeout` (or documented total bound) is enforced.

### Recommendation

REQUEST CHANGES. Fix round 1 resolves the exact UID policy and the repair-required status mapping direction, but the retained-session table now leaks completed attempts and can fail normal shutdown after an already-handled connector failure. The health check also remains unreliable under realistic startup timing. I would not approve Task 5 until these two issues are fixed and covered by deterministic tests.

---

## Fix Round 2: Session eviction and bounded health-check fixes

### RED
- Added deterministic service-runtime tests for completed-session eviction, shutdown after already-handled failure, active-session shutdown cancellation, stale completion vs newer generation ownership, delayed health-check socket readiness, and hung service shutdown during health-check cleanup.
- Initial `cargo test -p hyu-vpn-macos-service --test service_runtime` was RED with missing `force_replace_session_for_test`/session-count support and failing new behavior coverage.
- `cargo test -p hyu-vpn-macos-service --test service_runtime run_health_check_bounds_service_shutdown_hang -- --nocapture` then reproduced the health-check shutdown hang until `run_health_check` bounded service shutdown and the network-watch loop yielded between immediate fake monitor polls.

### Resolutions
1. **Completed session eviction**
   - Added per-session monotonic IDs and current-entry removal so each completion path evicts only its own generation after publishing the outcome.
   - `shutdown_sessions` now drains and awaits only currently active retained sessions; already-handled connector failures are not re-cancelled or reinterpreted as shutdown failures.
   - Stale completions cannot remove a newer retained session for the same generation.
2. **Robust health check**
   - Health check socket probing now retries bounded framed schema-v1 `Status` connect/request attempts until an absolute deadline.
   - Each attempt validates response request ID, response variant, and protocol schema version.
   - Public `run_health_check` now signals service shutdown and bounds service termination with the provided timeout, aborting and returning failure if cleanup hangs.
   - `run_network_watch` yields after immediate monitor wakeups to prevent deterministic fakes or unusually eager monitors from starving shutdown timers.

### GREEN / Verification
- `cargo test -p hyu-vpn-macos-service --test service_runtime run_health_check_bounds_service_shutdown_hang -- --nocapture` → PASS.
- `cargo test -p hyu-vpn-macos-service --test service_runtime` → PASS: 23 passed, 0 failed.
- `cargo test -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo fmt --all -- --check` → PASS.
- `cargo clippy -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets -- -D warnings` → PASS.
- `git diff --check` → PASS.

### Remaining risk
- Verification remains deterministic/non-live only as required: no sudo, installed helper, OpenConnect, route/DNS mutation, network mutation, or real credential reads were performed.

---

## Code Review Addendum: Fix Round 2 Re-review (2026-08-12)

**Verdict:** REQUEST CHANGES

**Review scope:** fix package `330a45a..97c5093` / `.superpowers/sdd/2026-08-08-hyu-vpn-macos-rust-backend/review-task5-fix2.diff`, current Task 5 service code/tests, prior Task 5 findings, and shutdown/session/health-check race behavior.

**Validation run (non-live only):**
- `git diff --check 330a45a..97c5093` → PASS.
- `cargo fmt --all -- --check` → PASS.
- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo check -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo clippy -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets -- -D warnings` → PASS.
- Requested-pattern `ast-grep` scans for `console.log`, empty `catch`, and hardcoded `apiKey` found no matches.
- `rust-analyzer diagnostics` is unavailable for the active toolchain (`infinite recursion detected`), so `cargo check`/Clippy were used as the diagnostic gate.

### Prior findings status

- **Completed session eviction/no re-await:** fixed. Completion paths now remove only the current session ID after publishing, and tests cover repeated failed attempts plus shutdown after handled failure.
- **Stale completion cannot remove newer generation:** fixed for the retained-session table via monotonic session IDs and a regression test.
- **Shutdown active-only:** fixed for completed helper sessions; `shutdown_sessions` drains only entries still retained at shutdown.
- **Health-check framed status retry:** fixed for socket readiness timing. It now retries connect/request/response until a deadline and validates request ID, status response, and schema version.
- **Health-check bounded shutdown:** bounded, but the abort path is not safe enough for a service that can own a real helper session; see HIGH finding below.
- **Earlier Task 5 findings:** exact UID-only peer authorization, repair-required/error propagation, repair reconciliation before restart, true backoff credential replacement coverage, and current OTP counter reservation remain acceptable in this round.

### Issues

[HIGH] Health-check timeout aborts `run_service` while helper cleanup may still be active, so it can abandon the explicit VPN teardown contract.

- File: `rust/apps/hyu-vpn-macos-service/src/lib.rs:990-1004`; active service wiring at `rust/apps/hyu-vpn-macos-service/src/lib.rs:964-987`
- Issue: `run_health_check` launches the full production service, including the network watcher and `MacActionExecutor`. If automatic reconnect is enabled/defaulted and the network becomes ready, the health-check service can own a real helper start session. On shutdown timeout, the new code calls `service.abort()` and returns failure. Aborting the `run_service` task while it is inside `executor.shutdown_sessions(...)` drops the service future and its retained session join handles; it does not prove that `HelperStartSession::cancel()`/`wait()` reached a `Stopped`/repair outcome before the health-check caller proceeds or exits. The new regression intentionally simulates a hung cleanup and only asserts that the public function returns an error within the bound; it does not prove the helper session is safely stopped or repaired after the abort.
- Risk: a bounded health check can leave the privileged helper/OpenConnect cleanup path running detached or abandoned, especially if the caller exits after the failed health check. This reintroduces the original load-bearing concern that VPN teardown must flow through the retained Task 4 start-session cleanup evidence rather than task abort/drop behavior.
- Fix: make the health check status-only and non-connecting, or otherwise make abort safe before returning. Preferred options: query an already-running service instead of spawning a full auto-connecting service; or construct the health-check service with automatic reconnect/network starts disabled. If a helper session can be active, do not abort `run_service` until a bounded explicit cleanup/repair/status result has been collected and reported. Add a deterministic fake-helper test proving that the timeout path cannot leave an active session after `run_health_check` returns.

[MEDIUM] Accepted IPC connection tasks are still detached and unbounded across shutdown.

- File: `rust/apps/hyu-vpn-macos-service/src/lib.rs:748-764`; shutdown path at `rust/apps/hyu-vpn-macos-service/src/lib.rs:896-987`
- Issue: `serve_owner_socket` spawns one untracked task per accepted connection and `run_service` does not retain or drain those tasks on shutdown. A same-UID client can connect and stall mid-frame, leaving `serve_connection` blocked on I/O while the service shutdown path returns after helper/runtime/network tasks only.
- Risk: this violates the Task 5 clean-shutdown/no-detached-task requirement and gives an authorized local client a simple resource-leak/slow-shutdown surface. It is less severe than helper-session cleanup because these tasks do not own VPN state, but it is still a daemon task-lifecycle gap.
- Fix: track accepted connection tasks in a `JoinSet`/task registry, add per-connection read/write deadlines or a shutdown-aware serving wrapper, and boundedly drain/abort them during service shutdown. Add a test that opens an authorized connection, sends a partial frame, triggers shutdown, and proves `run_service` still drains/terminates the connection task within the shutdown budget.

### Recommendation

REQUEST CHANGES. The session-eviction fix is good and the framed health-check retry is improved, but the health-check abort path can still bypass or abandon the retained helper cleanup contract if the health-check service owns a VPN generation. I would not approve Task 5 until abort safety is made explicit and covered.

---

## Fix Round 3: Status-only health checks and bounded IPC connection tasks

### RED
- Added `health_check_is_status_only_and_never_starts_helper`, `run_health_check_uses_delayed_existing_service_without_helper_start`, `owner_socket_shutdown_drains_stalled_partial_frame_client`, and `owner_socket_tracks_multiple_clients_and_registry_is_empty_after_shutdown` before production changes.
- Initial targeted service-runtime run failed at compile time because `serve_owner_socket_for_test` did not exist, proving the new IPC task-registry seam/behavior was absent.
- The status-only health-check test targeted the existing full-service health-check path, which could start automatic helper sessions instead of purely probing an already running service.

### Resolutions
1. **Status-only health check**
   - `run_health_check` no longer starts `run_service`, no longer wires automatic reconnect/network/helper execution, and no longer aborts a potentially active service.
   - Health checks are now pure bounded clients over the configured owner socket, using the existing framed schema-v1 `Status` request/response validation and retry deadline.
   - Deterministic tests prove automatic preference/credentials/network readiness do not produce helper starts, delayed existing service readiness succeeds, and unavailable/malformed responses remain bounded failures.
2. **Bounded IPC connection task lifecycle**
   - `serve_owner_socket` now tracks accepted connections in a `JoinSet` rather than detaching tasks.
   - Each connection is served under a total deadline and also exits on service shutdown notification.
   - On shutdown, accepting stops and all connection tasks are drained; if draining exceeds the bound, remaining connection tasks are aborted and reaped before returning.
   - Tests cover a same-UID partial-frame stalled client plus multiple ordinary status clients and assert the registry is empty after shutdown.

### GREEN / Verification
- `cargo test -p hyu-vpn-macos-service --test service_runtime health_check_is_status_only_and_never_starts_helper -- --nocapture` → PASS.
- `cargo test -p hyu-vpn-macos-service --test service_runtime owner_socket_shutdown_drains_stalled_partial_frame_client -- --nocapture` → PASS.
- `cargo test -p hyu-vpn-macos-service --test service_runtime owner_socket_tracks_multiple_clients_and_registry_is_empty_after_shutdown -- --nocapture` → PASS.
- `cargo test -p hyu-vpn-macos-service --test service_runtime run_health_check_uses_delayed_existing_service_without_helper_start -- --nocapture` → PASS.
- `cargo test -p hyu-vpn-macos-service --all-targets` → PASS: 26 passed, 0 failed.
- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo fmt --all -- --check` → PASS.
- `cargo clippy -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets -- -D warnings` → PASS.
- `git diff --check` → PASS.

### Remaining risk
- As required, this round used deterministic local fakes only: no sudo, installed helper, OpenConnect, route/DNS mutation, live network mutation, or real credential reads.

---

## Code Review Addendum: Fix Round 3 Re-review (2026-08-12)

**Verdict:** REQUEST CHANGES

**Review scope:** fix package `97c5093..eb9ac46` / `.superpowers/sdd/2026-08-08-hyu-vpn-macos-rust-backend/review-task5-fix3.diff`, current Task 5 service code/tests, prior health-check/session findings, and shared `EngineAction` impact on platform executors.

**Validation run (non-live only):**
- `git diff --check 97c5093..eb9ac46` → PASS.
- `cargo fmt --all -- --check` → PASS.
- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo check -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo clippy -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets -- -D warnings` → PASS.
- `cargo check -p hyu-vpn-windows-service --all-targets` on the macOS host → PASS for host-selected targets, but it does not compile the `#[cfg(windows)]` runtime module.
- Requested-pattern `ast-grep` scans for `console.log`, empty `catch`, and hardcoded `apiKey` found no matches.
- `rust-analyzer diagnostics` is unavailable for the active toolchain (`infinite recursion detected`), so `cargo check`/Clippy were used as the diagnostic gate.

### Prior findings status

- **Health check status-only / no helper/autoconnect/abort:** fixed. `run_health_check` now only probes the configured socket with framed schema-v1 `Status` and no longer spawns or aborts `run_service` (`rust/apps/hyu-vpn-macos-service/src/lib.rs:1053-1057`). The new tests cover unavailable/malformed sockets, delayed existing-service readiness, and no helper starts.
- **Accepted IPC task tracking/drain:** fixed for the macOS service. Accepted connections now run in a `JoinSet`, are shutdown-aware, have per-connection deadlines, and are drained/aborted within the configured timeout (`rust/apps/hyu-vpn-macos-service/src/lib.rs:834-895`). Tests cover stalled partial frames and multiple clients draining to zero.
- **Session eviction / stale completion / active-only shutdown:** remains fixed from round 2 via per-session IDs and current-entry eviction.
- **Earlier Task 5 requirements:** production main is real wiring; owner socket parent/socket permissions and exact UID peer policy are present; daemon framing/request ID/status handling is reused; start uses the retained Task 4 `HelperStartSession`; stop targets owned generation; repair-required maps to error instead of retry; retry cancellation and credential replacement coverage are present; TOTP counter reservation/current OTP checks remain covered. No new plaintext marker/log leak was found in the changed Task 5 code.

### Issues

[HIGH] Shared `EngineAction::PublishError` breaks target platform executors that still match `EngineAction` exhaustively without the new variant.

- File: `rust/apps/hyu-vpn-linux-service/src/lib.rs:337`
- File: `rust/apps/hyu-vpn-windows-service/src/runtime.rs:222`
- Issue: Task 5 added `EngineAction::PublishError` in shared core, and the macOS executor was updated to ignore it. The Linux and Windows action executors still have exhaustive `match action` arms ending at `EngineAction::PublishState(_) => {}` with no `PublishError` arm or wildcard. The macOS host cannot fully prove this through target builds: Linux checking fails earlier on Linux-only platform APIs, and the Windows runtime is behind `#[cfg(windows)]`. But the source-level Rust exhaustiveness rule is clear: when these target-specific modules are compiled on their target platforms, the match is non-exhaustive.
- Risk: the shared core/daemon change can break Linux/Windows service builds even though the macOS-selected Task 5 gates pass. This is a cross-platform regression from a shared enum extension and should not be merged as-is.
- Fix: add `EngineAction::PublishError(_) => {}` to every `ActionExecutor` match, or use a deliberate grouped arm such as `EngineAction::PublishState(_) | EngineAction::PublishError(_) => {}`. Add/adjust platform build checks or a static regression test so every executor handles all shared action variants when the core enum grows.

### Recommendation

REQUEST CHANGES. Fix round 3 resolves the two macOS service blockers from the prior review, and I found no remaining load-bearing macOS Task 5 lifecycle issue. However, the shared `EngineAction` expansion still leaves Linux/Windows executors source-incomplete for their target builds. Address that cross-platform regression before approval.

---

## Fix Round 4: Cross-platform `PublishError` executor coverage

### RED
- Added `rust/crates/hyu-vpn-core/tests/action_executor_coverage.rs` as a source-level static regression so macOS-hosted CI can still catch target-gated platform executors that omit shared `EngineAction` variants.
- Initial checked-in regression run failed before the production fix:
  - `cargo test --locked -p hyu-vpn-core --test action_executor_coverage platform_action_executors_explicitly_handle_publish_error -- --nocapture` → FAIL on `LinuxActionExecutor` missing `EngineAction::PublishError` handling.
  - Equivalent pre-fix `HEAD` blob scan reported both target omissions: `LinuxActionExecutor: missing EngineAction::PublishError handling` and `WindowsActionExecutor: missing EngineAction::PublishError handling`.

### GREEN / Resolution
- `rust/apps/hyu-vpn-linux-service/src/lib.rs` now groups `EngineAction::PublishState(_) | EngineAction::PublishError(_) => {}` in the Linux executor.
- `rust/apps/hyu-vpn-windows-service/src/runtime.rs` now groups `EngineAction::PublishState(_) | EngineAction::PublishError(_) => {}` in the Windows executor.
- Searched all `match action` sites; remaining test matches use wildcards, and all platform executor matches explicitly handle `PublishError`.

### Verification
- `cargo test --locked -p hyu-vpn-core --test action_executor_coverage platform_action_executors_explicitly_handle_publish_error -- --nocapture` → PASS.
- `cargo fmt --all -- --check` → PASS.
- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → PASS.
- `cargo clippy --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-windows-service --all-targets -- -D warnings` → PASS.
- `cargo check --locked -p hyu-vpn-windows-service --all-targets` → PASS for host-selected macOS cfg; note this still does not compile `#[cfg(windows)]` runtime code on this host.
- `cargo test --locked -p hyu-vpn-windows-service --all-targets` → PASS: 4 passed, 0 failed.
- `cargo check/test --locked -p hyu-vpn-linux-service --all-targets` on macOS host → BLOCKED by Linux-only APIs in `hyu-vpn-platform-linux` (`libc::ucred`, `SO_PEERCRED`, `TcpSocket::bind_device`) not existing for `aarch64-apple-darwin`.
- Cross-target `cargo check --target x86_64-pc-windows-msvc -p hyu-vpn-windows-service --all-targets` and `cargo check --target x86_64-unknown-linux-gnu -p hyu-vpn-linux-service --all-targets` → BLOCKED because only `aarch64-apple-darwin` is installed (`can't find crate for core`).
- Workspace-wide `cargo clippy --locked --workspace --all-targets -- -D warnings` remains BLOCKED by unrelated pre-existing `hyu-vpn-hip` dead-code warnings promoted to errors.
- `rg -n "EngineAction::PublishState\(_\) => \{\}" rust` → no matches.

### Remaining risk
- Full target-native Linux/Windows compilation was not possible on this macOS host with the installed Rust target set; the new static regression covers the target-gated executor source omission that caused this round.

---

## Code Review Addendum: Fix Round 4 Re-review (2026-08-12)

**Verdict:** APPROVE

**Review scope:** fix package `eb9ac46..6e3ef84` / `.superpowers/sdd/2026-08-08-hyu-vpn-macos-rust-backend/review-task5-fix4.diff`, current Task 5 service state, the prior `PublishError` cross-platform finding, and final deterministic Task 5 readiness.

**Validation run (non-live only):**
- `git diff --check eb9ac46..6e3ef84` → PASS.
- `cargo fmt --all -- --check` → PASS.
- `cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets` → PASS, including `hyu-vpn-macos-service` service-runtime 26/26 and `hyu-vpn-core` `action_executor_coverage` 1/1.
- `cargo clippy -p hyu-vpn-platform-macos -p hyu-vpn-macos-service --all-targets -- -D warnings` → PASS.
- `cargo test --locked -p hyu-vpn-core --test action_executor_coverage platform_action_executors_explicitly_handle_publish_error -- --nocapture` → PASS.
- `cargo check --locked -p hyu-vpn-windows-service --all-targets` → PASS for host-selected macOS cfg.
- `cargo test --locked -p hyu-vpn-windows-service --all-targets` → PASS: 4 passed, 0 failed.
- `cargo clippy --locked -p hyu-vpn-protocol -p hyu-vpn-core -p hyu-vpn-daemon -p hyu-vpn-platform-macos -p hyu-vpn-macos-service -p hyu-vpn-windows-service --all-targets -- -D warnings` → PASS.
- `cargo check --locked -p hyu-vpn-linux-service --all-targets` on this macOS host remains blocked by Linux-only platform APIs (`libc::ucred`, `SO_PEERCRED`, `TcpSocket::bind_device`) not existing for `aarch64-apple-darwin`; this is not introduced by fix round 4.
- Requested-pattern `ast-grep` scans for `console.log`, empty `catch`, and hardcoded `apiKey` found no matches in the reviewed sources.
- `rust-analyzer diagnostics` remains unavailable for the active toolchain (`infinite recursion detected`), so `cargo check`/Clippy were used as the diagnostic gate.

### Prior finding status

- **Shared `EngineAction::PublishError` platform executor regression:** fixed.
  - Linux now explicitly ignores the status-only action alongside `PublishState` at `rust/apps/hyu-vpn-linux-service/src/lib.rs:337`.
  - Windows now explicitly ignores the status-only action alongside `PublishState` at `rust/apps/hyu-vpn-windows-service/src/runtime.rs:222`.
  - Mac already had the grouped arm at `rust/apps/hyu-vpn-macos-service/src/lib.rs:694`.
- **Static regression:** acceptable for this host-limited review. `rust/crates/hyu-vpn-core/tests/action_executor_coverage.rs:3-35` enumerates the three platform executor source files and requires each named `ActionExecutor` impl to explicitly mention `EngineAction::PublishError`. This is source-level rather than a substitute for target-native Linux/Windows compilation, but it is not tied to line numbers and covers the target-gated executor source omission that macOS CI cannot compile directly. No literal/comment-only false-positive was found in the current sources.

### Final Task 5 assessment

No CRITICAL, HIGH, MEDIUM, or LOW findings remain from this re-review.

Task 5 now satisfies the deterministic non-live acceptance scope reviewed here:
- production service wiring uses `MacPaths`, `MacCredentialRepository`, `MacNetworkMonitor`, `MacPortalProbe`, and `InstalledHelperRunner` rather than placeholders;
- owner socket parent/socket permissions and exact UID peer authorization are implemented;
- daemon framing/request IDs/schema-v1 status handling are reused and health check is pure status-only;
- helper start uses the approved retained `HelperStartSession` path, with owned-generation stop, session eviction, stale-completion protection, and bounded shutdown cleanup;
- repair-required/failed cleanup outcomes publish explicit error state instead of retry storms;
- retry cancellation, credential replacement during backoff, current OTP counter reservation, automatic preference atomic storage, and bounded IPC task draining are covered by deterministic tests;
- no live sudo/helper/OpenConnect/network mutation or real credential reads were performed.

### Recommendation

APPROVE. The prior load-bearing findings have been resolved and the remaining limitations are the expected non-live/target-native verification gaps for later platform CI or live acceptance.
