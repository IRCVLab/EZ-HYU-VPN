# HYU VPN macOS Rust Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the installed macOS Python connection backend with the shared Rust engine while retaining the native Swift menu-bar frontend and Swift privileged helper.

**Architecture:** A new `hyu-vpn-platform-macos` crate adapts macOS paths, credentials, network evidence, and the existing fixed helper contract to `hyu-vpn-core`. A new per-user `hyu-vpn-macos-service` composes the shared daemon and serves schema-v1 IPC; the Swift menu becomes a thin direct Unix-socket client. The DMG installs only the Rust backend and launches it directly with launchd.

**Tech Stack:** Rust 1.85+, Tokio, Swift 6/AppKit, Unix domain sockets, launchd, existing Swift privileged helper, Python packaging tests, GitHub Actions macOS arm64.

## Global Constraints

- Run implementation, compilation, Swift integration, packaging, DMG, and live acceptance on the current Apple Silicon Mac, not the Ubuntu host.
- Keep the Swift/AppKit menu frontend and existing Swift privileged helper.
- Remove the production Python connection backend; do not implement a Python fallback.
- Preserve/import the user's existing encrypted credential files without displaying plaintext and without Keychain.
- Never put credentials, passwords, OTP seeds/codes, cookies, or portal responses in argv, environment variables, status files, logs, crash output, or installer output.
- The Rust service is the only lifecycle authority and owns at most one connection generation.
- Only the privileged helper may mutate routes or DNS, and it may restore only owned mutations.
- Do not disable Wi-Fi or mutate live routes during deterministic tests. Physical network loss is the final explicit live gate.
- Follow red-green-refactor: every production behavior begins with a failing targeted test whose failure is observed.
- No new third-party dependencies unless the standard library/current workspace dependencies cannot implement the required boundary.

---

### Task 1: Lock the greenfield product boundary with failing static gates

**Files:**
- Modify: `tests/test_packaging.py`
- Modify: `tests/test_installer.py`
- Modify: `tests/test_launchd_config.py`
- Modify: `tests/test_macos_workflow.py`

**Interfaces:**
- Consumes: approved design in `docs/superpowers/specs/2026-08-08-hyu-vpn-macos-rust-backend-design.md`.
- Produces: executable gates that require a Rust service binary and forbid production Python backend paths.

- [ ] **Step 1: Add the failing packaging tests**

  Add tests named:

  ```python
  test_macos_release_payload_contains_rust_service_and_no_python_backend
  test_macos_manifest_rejects_legacy_backend_entries
  test_macos_launchagent_execs_rust_service_directly
  test_macos_workflow_builds_and_tests_rust_backend
  ```

  The assertions require `hyu-vpn-macos-service`, forbid installed `src/hyu_vpn`, `hyu-vpn-control`, `hyu-vpn-connect`, and forbid `/usr/bin/python3` in `com.hyu.vpn.service.plist`.

- [ ] **Step 2: Run the targeted tests and observe RED**

  Run:

  ```bash
  python3 -m unittest -v \
    tests.test_packaging \
    tests.test_installer \
    tests.test_launchd_config \
    tests.test_macos_workflow
  ```

  Expected: the newly named tests fail because the package, manifest, launchd plist, and workflow still require Python.

- [ ] **Step 3: Commit only the RED contract tests**

  ```bash
  git add tests/test_packaging.py tests/test_installer.py \
    tests/test_launchd_config.py tests/test_macos_workflow.py
  git commit -m "Test macOS Rust backend product boundary"
  ```

---

### Task 2: Add secure macOS paths and credential storage

**Files:**
- Modify: `Cargo.toml`
- Create: `rust/crates/hyu-vpn-platform-macos/Cargo.toml`
- Create: `rust/crates/hyu-vpn-platform-macos/src/lib.rs`
- Create: `rust/crates/hyu-vpn-platform-macos/src/paths.rs`
- Create: `rust/crates/hyu-vpn-platform-macos/src/storage.rs`
- Create: `rust/crates/hyu-vpn-platform-macos/tests/paths.rs`
- Create: `rust/crates/hyu-vpn-platform-macos/tests/credentials.rs`

**Interfaces:**
- Consumes: `hyu_vpn_core::credentials::CredentialEnvelope`, `hyu_vpn_daemon::runtime::CredentialRepository`, `hyu_vpn_protocol::Credentials`.
- Produces:

  ```rust
  pub struct MacPaths {
      pub state_dir: PathBuf,
      pub credential_key: PathBuf,
      pub credentials: PathBuf,
      pub socket: PathBuf,
      pub status: PathBuf,
      pub automatic_reconnect: PathBuf,
      pub totp_counter: PathBuf,
      pub helper: PathBuf,
  }

  impl MacPaths {
      pub fn production(home: &Path) -> Result<Self, PlatformError>;
      pub fn under(root: &Path, uid: u32) -> Self;
  }

  pub struct MacCredentialRepository;
  impl CredentialRepository for MacCredentialRepository;
  ```

- [ ] **Step 1: Create the crate and write failing path tests**

  Tests require canonical `~/Library/Application Support/hyu-openconnect` paths, fixed `/Library/PrivilegedHelperTools/com.hyu.vpn.helper`, no relative components, and rejection of symlink/world-accessible/wrong-owner state directories.

- [ ] **Step 2: Run the path tests and observe RED**

  ```bash
  cargo test -p hyu-vpn-platform-macos --test paths
  ```

  Expected: compile failure because `MacPaths` and `PlatformError` do not exist.

- [ ] **Step 3: Implement the minimal secure path layer**

  Use `symlink_metadata`, `MetadataExt`, `PermissionsExt`, `O_NOFOLLOW`, exact owner UID, directory mode `0700`, file mode `0600`, and bounded absolute paths. Do not call shell commands.

- [ ] **Step 4: Run the path tests and observe GREEN**

  ```bash
  cargo test -p hyu-vpn-platform-macos --test paths
  ```

- [ ] **Step 5: Write failing credential import/replacement tests**

  Cover the existing raw CryptoKit combined envelope, the versioned Rust envelope, wrong key, truncation, symlinks, wrong owner/mode, oversize, atomic replacement, unique nonce, and absence of plaintext in stored bytes/debug output.

- [ ] **Step 6: Run the credential tests and observe RED**

  ```bash
  cargo test -p hyu-vpn-platform-macos --test credentials
  ```

- [ ] **Step 7: Implement `MacCredentialRepository` minimally**

  Reuse `CredentialEnvelope`; create a 32-byte key from `/dev/urandom` only when absent; use same-directory create-new `0600` temporary files, `fsync`, atomic rename, and zeroizing buffers. Existing valid key/envelope pairs load without rewriting.

- [ ] **Step 8: Run the crate and shared credential suites**

  ```bash
  cargo test -p hyu-vpn-platform-macos --all-targets
  cargo test -p hyu-vpn-core --test credentials
  ```

- [ ] **Step 9: Commit**

  ```bash
  git add Cargo.toml Cargo.lock rust/crates/hyu-vpn-platform-macos
  git commit -m "Add secure macOS Rust storage adapter"
  ```

---

### Task 3: Add macOS physical-network readiness and portal probing

**Files:**
- Create: `rust/crates/hyu-vpn-platform-macos/src/network.rs`
- Create: `rust/crates/hyu-vpn-platform-macos/tests/network.rs`

**Interfaces:**
- Consumes: `hyu_vpn_core::ports::{NetworkMonitor, PortalProbe}` and `NetworkIdentity`.
- Produces:

  ```rust
  pub struct MacNetworkMonitor;
  pub struct MacPortalProbe;
  pub fn parse_default_route(bytes: &[u8]) -> Result<Option<NetworkIdentity>, PlatformError>;
  ```

- [ ] **Step 1: Write failing route/parser/change tests**

  Fixture tests require selection of the non-tunnel default route, exclusion of `utun`, `tap`, `tun`, `ppp`, `wg`, and `vpn` prefixes, bounded interface names, stable identity changes, offline mapping, and sleep/resume wakeup behavior.

- [ ] **Step 2: Observe RED**

  ```bash
  cargo test -p hyu-vpn-platform-macos --test network
  ```

- [ ] **Step 3: Implement bounded macOS evidence collection**

  Use fixed absolute executables or direct system APIs. If invoking `/sbin/route`, accept only the fixed `-n get default` shape, bound stdout/stderr/time, parse no untrusted command fragments, and exclude tunnel routes. Portal probing binds to the observed physical interface and performs bounded DNS/TCP reachability.

- [ ] **Step 4: Observe GREEN and run shared readiness tests**

  ```bash
  cargo test -p hyu-vpn-platform-macos --test network
  cargo test -p hyu-vpn-core --test readiness
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add rust/crates/hyu-vpn-platform-macos/src/network.rs \
    rust/crates/hyu-vpn-platform-macos/tests/network.rs
  git commit -m "Add macOS Rust network readiness adapter"
  ```

---

### Task 4: Add the exact macOS privileged-helper adapter

**Files:**
- Create: `rust/crates/hyu-vpn-platform-macos/src/helper.rs`
- Create: `rust/crates/hyu-vpn-platform-macos/tests/helper.rs`

**Interfaces:**
- Produces:

  ```rust
  pub enum HelperCommand { Start, Stop, Status, Repair }
  pub enum HelperState { Stopped, Running { tunnel: Option<String> }, RepairRequired }
  pub trait HelperRunner: Send + Sync {
      async fn run(&self, command: HelperCommand) -> Result<HelperState, HelperError>;
  }
  pub struct InstalledHelperRunner;
  ```

- [ ] **Step 1: Write failing helper contract tests**

  Require exact `/usr/bin/sudo -n /Library/PrivilegedHelperTools/com.hyu.vpn.helper <command>` argv, empty sanitized environment, maximum output bytes, timeout, exact JSON keys, allowed `utun[0-9]+`, and no credentials/OTP/cookie/portal in argv or diagnostics.

- [ ] **Step 2: Observe RED**

  ```bash
  cargo test -p hyu-vpn-platform-macos --test helper
  ```

- [ ] **Step 3: Implement the minimal runner and parser**

  Execute only the fixed command enum, close stdin, capture bounded output, kill on timeout, and map invalid/partial state to stable local errors without echoing raw output.

- [ ] **Step 4: Observe GREEN and run all adapter tests**

  ```bash
  cargo test -p hyu-vpn-platform-macos --all-targets
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add rust/crates/hyu-vpn-platform-macos/src/helper.rs \
    rust/crates/hyu-vpn-platform-macos/tests/helper.rs
  git commit -m "Add macOS privileged helper Rust adapter"
  ```

---

### Task 5: Compose the per-user Rust macOS service

**Files:**
- Modify: `Cargo.toml`
- Create: `rust/apps/hyu-vpn-macos-service/Cargo.toml`
- Create: `rust/apps/hyu-vpn-macos-service/src/lib.rs`
- Create: `rust/apps/hyu-vpn-macos-service/src/main.rs`
- Create: `rust/apps/hyu-vpn-macos-service/tests/service_runtime.rs`

**Interfaces:**
- Consumes: `ControlPlane`, `DaemonRuntime`, `MacCredentialRepository`, `MacNetworkMonitor`, `MacPortalProbe`, `HelperRunner`.
- Produces:

  ```rust
  pub struct MacActionExecutor<H: HelperRunner>;
  pub struct AutomaticPreference;
  pub async fn bind_owner_socket(path: &Path, uid: u32) -> Result<UnixListener, ServiceError>;
  pub async fn run_service(config: ServiceConfig, shutdown: watch::Receiver<bool>) -> Result<(), ServiceError>;
  ```

- [ ] **Step 1: Write failing service tests**

  Cover owner-only socket creation, peer UID rejection, status response, connect readiness followed by one helper start, disconnect stop, retry cancellation, credential replacement during backoff, current OTP, service restart reconciliation, no duplicate helper start, and bounded health check.

- [ ] **Step 2: Observe RED**

  ```bash
  cargo test -p hyu-vpn-macos-service --test service_runtime
  ```

- [ ] **Step 3: Implement preference/socket/service skeleton**

  Reuse the daemon framing and status writer. Store automatic reconnect atomically at `0600`. Bind the Unix socket in a validated `0700` directory, set `0600`, and validate `LOCAL_PEERCRED` before serving a request.

- [ ] **Step 4: Implement `MacActionExecutor` against `HelperRunner`**

  `StartConnection` loads credentials and reserves the TOTP counter, then invokes the existing helper start path without placing secrets in helper argv. `StopConnection` stops only the owned generation. Startup reconciles helper status before publishing state. Retry tasks are cancellable and bounded.

- [ ] **Step 5: Observe GREEN**

  ```bash
  cargo test -p hyu-vpn-macos-service --all-targets
  ```

- [ ] **Step 6: Run shared regression gates**

  ```bash
  cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core \
    -p hyu-vpn-daemon -p hyu-vpn-platform-macos \
    -p hyu-vpn-macos-service --all-targets
  cargo clippy -p hyu-vpn-platform-macos -p hyu-vpn-macos-service \
    --all-targets -- -D warnings
  ```

- [ ] **Step 7: Commit**

  ```bash
  git add Cargo.toml Cargo.lock rust/apps/hyu-vpn-macos-service
  git commit -m "Add Rust macOS VPN service"
  ```

---

### Task 6: Replace the Swift command runner with direct Rust IPC

**Files:**
- Create: `macos/Sources/HYUVPNMenuCore/RustProtocol.swift`
- Create: `macos/Sources/HYUVPNMenuCore/RustIPCClient.swift`
- Modify: `macos/Sources/HYUVPNMenuCore/MenuCore.swift`
- Modify: `macos/Sources/HYUVPNMenuApp/AppDelegate.swift`
- Create: `macos/Tests/HYUVPNMenuAppTests/RustIPCClientTests.swift`
- Create: `tests/fixtures/protocol/status-response-v1.json`
- Create: `tests/fixtures/protocol/current-otp-response-v1.json`
- Create: `tests/fixtures/protocol/error-protocol-mismatch-v1.json`
- Create: `tests/fixtures/protocol/replace-credentials-request-v1.json`

**Interfaces:**
- Consumes: schema-v1 length-prefixed JSON from `hyu-vpn-protocol`.
- Produces:

  ```swift
  public protocol VPNServiceRequesting {
      func request(_ command: VPNCommand, completion: @escaping (Result<VPNResponse, VPNServiceError>) -> Void)
      func replaceCredentials(_ credentials: CredentialInput, completion: @escaping (Result<Void, VPNServiceError>) -> Void)
  }

  public final class RustIPCClient: VPNServiceRequesting
  ```

- [ ] **Step 1: Add golden fixtures from Rust codecs**

  Generate fixtures using a test-only Rust program or test helper calling `encode_request`/`encode_response`; do not hand-maintain divergent JSON.

- [ ] **Step 2: Write failing Swift tests**

  Cover exact connect/disconnect/reconnect/status/OTP frames, one credential transaction, request ID matching, unknown fields/version rejection, socket metadata/symlink rejection, bounded timeouts, oversized responses, daemon unavailable behavior, and a static assertion that production code does not execute `hyu-vpn-control` or a shell.

- [ ] **Step 3: Observe RED**

  ```bash
  swift test --package-path macos --filter RustIPCClientTests --no-parallel
  ```

- [ ] **Step 4: Implement the minimal direct socket client**

  Use Unix sockets directly, big-endian `u32` length prefix, exact Codable types, a serial background queue, bounded timeouts, owner/mode validation, and main-thread completion delivery. Keep secret buffers scoped to the request and never include them in `description` or errors.

- [ ] **Step 5: Replace menu dependency injection and remove command execution**

  Route menu controls, credential replacement, and OTP through `VPNServiceRequesting`. Keep status/menu presentation behavior unchanged.

- [ ] **Step 6: Observe GREEN and run all Swift harnesses**

  ```bash
  swift test --package-path macos --no-parallel
  swift run --package-path macos hyu-vpn-helper-test-harness </dev/null
  swift run --package-path macos hyu-vpn-menu-harness </dev/null
  swift run --package-path macos hyu-vpn-installer-harness </dev/null
  macos/Scripts/test-wrapperd-closed-stderr.sh
  ```

- [ ] **Step 7: Commit**

  ```bash
  git add macos/Sources macos/Tests tests/fixtures/protocol
  git commit -m "Connect macOS menu to Rust VPN service"
  ```

---

### Task 7: Switch launchd, installer, and release packaging to Rust

**Files:**
- Modify: `launchd/com.hyu.vpn.service.plist.in`
- Modify: `installer/manifest.py`
- Modify: `installer/root-admin.sh`
- Modify: `macos/Sources/HYUVPNInstallerApp/main.swift`
- Modify: `scripts/package-macos.sh`
- Modify: `scripts/package-release.py`
- Modify: `scripts/release_packaging.py`
- Modify: `.github/workflows/macos.yml`
- Modify: `tests/test_packaging.py`
- Modify: `tests/test_installer.py`
- Modify: `tests/test_launchd_config.py`
- Modify: `tests/test_macos_workflow.py`

**Interfaces:**
- Consumes: release-mode `hyu-vpn-macos-service` arm64 binary.
- Produces: installed `/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service`, direct per-user launchd entry, transactionally verified backend SHA-256, and no production Python backend.

- [ ] **Step 1: Re-run Task 1 tests and confirm they remain RED**

  ```bash
  python3 -m unittest -v tests.test_packaging tests.test_installer \
    tests.test_launchd_config tests.test_macos_workflow
  ```

- [ ] **Step 2: Build the Rust service in `package-macos.sh`**

  Use the locked workspace and `--release -p hyu-vpn-macos-service`; verify `file` reports `arm64`; stage the binary under a fixed backend path; include its SHA-256 in the immutable manifest.

- [ ] **Step 3: Render direct launchd execution**

  `ProgramArguments[0]` is `/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service`. Remove `/usr/bin/python3` and the script argument. Preserve the per-user environment and restart policy without shell evaluation.

- [ ] **Step 4: Replace installer backend staging and preference mutation**

  Stop and drain the prior service, copy/hash the Rust binary, preserve existing encrypted credentials, bootstrap launchd, perform a bounded schema-v1 status health check, and roll back the transaction snapshot on failure. Do not copy `src/hyu_vpn`, `hyu-vpn-control`, `hyu-vpn-connect`, or the Python service.

- [ ] **Step 5: Update release manifest and macOS CI**

  Add Rust fmt/test/clippy/audit gates before Swift/package gates. Inspect the mounted DMG for the Rust binary, arm64 identity, direct launchd path, forbidden production Python paths, and signatures.

- [ ] **Step 6: Observe GREEN for static/package tests**

  ```bash
  python3 -m unittest -v tests.test_packaging tests.test_installer \
    tests.test_launchd_config tests.test_macos_workflow
  ```

- [ ] **Step 7: Run the full deterministic local suite**

  ```bash
  cargo fmt --all -- --check
  cargo test --locked -p hyu-vpn-protocol -p hyu-vpn-core \
    -p hyu-vpn-daemon -p hyu-vpn-platform-macos \
    -p hyu-vpn-macos-service --all-targets
  cargo clippy -p hyu-vpn-platform-macos -p hyu-vpn-macos-service \
    --all-targets -- -D warnings
  swift test --package-path macos --no-parallel
  python3 -m unittest discover -s tests -p 'test_*.py' -v
  ```

- [ ] **Step 8: Commit**

  ```bash
  git add launchd installer macos/Sources/HYUVPNInstallerApp \
    scripts .github/workflows/macos.yml tests
  git commit -m "Package the Rust backend for macOS"
  ```

---

### Task 8: Build and inspect the DMG without installing it

**Files:**
- Create: `scripts/macos-dmg-acceptance.sh`
- Modify: `tests/test_macos_workflow.py`

**Interfaces:**
- Produces: a repeatable read-only artifact inspection that cannot mutate installed networking.

- [ ] **Step 1: Write a failing test requiring the acceptance script and checks**

  Require read-only mount, `hdiutil verify`, deep strict code signatures, arm64 checks for menu/installer/service/helper, direct launchd execution, no production Python backend paths, manifest SHA identity, and clean detach.

- [ ] **Step 2: Observe RED**

  ```bash
  python3 -m unittest -v tests.test_macos_workflow
  ```

- [ ] **Step 3: Implement the bounded acceptance script**

  Use temporary mount points, traps, exact artifact paths, bounded output, and no installer launch.

- [ ] **Step 4: Build and inspect the DMG**

  ```bash
  scripts/package-macos.sh
  scripts/macos-dmg-acceptance.sh dist/EZ-HYU-VPN-arm64.dmg
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add scripts/macos-dmg-acceptance.sh tests/test_macos_workflow.py
  git commit -m "Verify macOS Rust backend DMG"
  ```

---

### Task 9: Install and run safe live Mac acceptance

**Files:**
- Create: `scripts/live-macos-rust-acceptance.sh`
- Create: `docs/release-checklist-macos-rust.md`

**Interfaces:**
- Consumes: inspected DMG and authorized existing local encrypted credentials.
- Produces: sanitized evidence for install, Rust backend identity, real connection, owned reconnect, restoration, rollback, and uninstall.

- [ ] **Step 1: Implement read-only preflight and evidence redaction**

  The script records baseline default route, DNS service state, helper state, installed version/hash, internet probes, and credential metadata only. It refuses to print credential contents and refuses to proceed if baseline internet is already unhealthy.

- [ ] **Step 2: Install through the graphical installer**

  One user-entered macOS administrator authorization is permitted. Verify the installed service hash equals the DMG manifest, launchd executes Rust directly, one service/menu instance exists, and Python backend paths are absent.

- [ ] **Step 3: Verify real connect and secret hygiene**

  Use the existing encrypted credentials through the service. Wait boundedly for helper-verified `utun` evidence, HIP success, Rust backend version, and normal internet. Scan only sanitized logs for forbidden key names/patterns and report counts, never raw matching lines.

- [ ] **Step 4: Verify owned-process and service restart recovery**

  Terminate only the helper-recorded owned OpenConnect generation, prove a new generation connects without prompts, then restart only the Rust user service and prove helper reconciliation and one new connection. Check internet before and after every step.

- [ ] **Step 5: Verify session-expiry/backoff behavior**

  Use a test-only service injection accepted only by a debug/test build or a fake helper harness; never change the production protocol. Prove retry timing and cancellation with bounded evidence.

- [ ] **Step 6: Verify disconnect restoration**

  Explicitly disconnect, wait for helper stopped state, compare owned route/DNS restoration to baseline, and verify Google/GitHub reachability. Abort and invoke helper repair if any owned state remains.

- [ ] **Step 7: Perform the final controlled physical-network gate**

  Only after all prior gates pass and the user is present, disconnect/reconnect Wi-Fi or move to a second network, then prove the Rust service begins a new attempt within ten seconds after readiness returns. Continuously verify fallback internet and run repair if restoration fails.

- [ ] **Step 8: Verify rollback injection and uninstall**

  Exercise installer failure injection in a transaction-safe test root first, then the installed rollback path. Uninstall and verify no stale launchd entry, service process, socket, helper session, route, DNS mutation, or plaintext artifact remains.

- [ ] **Step 9: Record evidence and commit**

  ```bash
  git add scripts/live-macos-rust-acceptance.sh \
    docs/release-checklist-macos-rust.md
  git commit -m "Add macOS Rust live acceptance gate"
  ```

---

### Task 10: Final review, CI, release, and cleanup

**Files:**
- Modify: `README.md`
- Modify: `update.json`
- Modify: release workflow only if artifact names/version change.
- Delete: obsolete production Python backend files after all replacement tests pass.

**Interfaces:**
- Produces: reviewable branch, green macOS CI, verified artifact, exact documentation, and no stale product backend.

- [ ] **Step 1: Run the complete verification sequence from a clean checkout**

  Run all Rust fmt/test/clippy/audit, Swift tests/harnesses, Python static/package tests, DMG acceptance, and safe live checks. Save only non-secret summaries.

- [ ] **Step 2: Delete obsolete production backend sources and update tests**

  Remove Python service/control/connect product code only after searches and package tests prove no product consumer remains. Retain packaging scripts such as `installer/manifest.py` only where they are installer build tools rather than the runtime backend.

- [ ] **Step 3: Run secret and legacy scans**

  ```bash
  rg -n '/usr/bin/python3|hyu-vpn-control|hyu-vpn-connect|src/hyu_vpn' \
    launchd installer macos scripts tests
  git grep -n -E 'password=|totp=|credential=' -- ':!tests/fixtures/**'
  ```

  Every remaining match must be a non-production test/build-tool reference and explicitly justified.

- [ ] **Step 4: Review the complete diff and run independent verification**

  Validate architecture, security, rollback, test coverage, and artifact identity. Fix every correctness issue and rerun the smallest proving gate plus the full final sequence.

- [ ] **Step 5: Push the feature branch and require green macOS CI**

  Do not merge or publish until CI artifact inspection and the target-Mac live acceptance checklist both pass.

- [ ] **Step 6: Merge, version, publish, and independently download-verify**

  Publish the next prerelease/version, download the public DMG and checksum into a new temporary directory, verify checksum/signature/mount/runtime identity, and confirm the installed backend hash matches the public artifact before calling the migration complete.
