# HYU VPN Rust Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a portable Rust daemon core that reproduces the existing connection, OTP, credential, status, and automatic-reconnect behavior behind a strict local IPC protocol.

**Architecture:** A Cargo workspace separates pure state-machine logic from process, network, credential, and platform adapters. The daemon owns connection generations and exposes a bounded JSON protocol; platform applications remain presentation-only clients.

**Tech Stack:** Rust 2024, Tokio, Serde, AES-GCM, HMAC-SHA1, zeroize, Unix sockets/named pipes, existing Python fixtures as a migration oracle.

## Global Constraints

- Support macOS 14+, Windows 11 x64, and Ubuntu 22.04/24.04 LTS x64.
- Connect enables automatic reconnect; explicit Disconnect disables it.
- A restored or changed physical network begins a VPN attempt within ten seconds, excluding the OpenConnect handshake.
- Secrets never enter argv, environment variables, status files, crash reports, or logs.
- Keep the working Python macOS backend until Rust parity and rollback validation pass.
- Do not embed or dynamically load `libopenconnect`; supervise the packaged executable.

---

### Task 1: Cargo workspace and protocol types

**Files:**
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `rust/crates/hyu-vpn-protocol/Cargo.toml`
- Create: `rust/crates/hyu-vpn-protocol/src/lib.rs`
- Create: `rust/crates/hyu-vpn-protocol/tests/protocol.rs`

**Interfaces:**
- Produces: `RequestEnvelope`, `Request`, `ResponseEnvelope`, `Response`, `VpnStatus`, `VpnState`, `ErrorCode`, `Credentials`, and `MAX_FRAME_BYTES`.
- Produces: `decode_request(&[u8]) -> Result<RequestEnvelope, ProtocolError>` and `encode_response(&ResponseEnvelope) -> Result<Vec<u8>, ProtocolError>`.

- [ ] Write protocol tests that accept exact version-1 commands, reject unknown or oversized fields, zeroize credential values on drop, and prove status serialization contains no secret-bearing keys.
- [ ] Run `cargo test -p hyu-vpn-protocol` and confirm the crate is missing.
- [ ] Implement exact-field Serde models with `deny_unknown_fields`, a 64-KiB frame limit, bounded username/password/TOTP lengths, and stable snake-case wire values.
- [ ] Run `cargo test -p hyu-vpn-protocol` and confirm all protocol tests pass.
- [ ] Commit with `git commit -m "Add versioned Rust VPN protocol"`.

### Task 2: Pure connection state machine

**Files:**
- Create: `rust/crates/hyu-vpn-core/Cargo.toml`
- Create: `rust/crates/hyu-vpn-core/src/lib.rs`
- Create: `rust/crates/hyu-vpn-core/src/state.rs`
- Create: `rust/crates/hyu-vpn-core/tests/state_machine.rs`

**Interfaces:**
- Consumes: `hyu_vpn_protocol::{VpnState, VpnStatus, ErrorCode}`.
- Produces: `Engine`, `EngineEvent`, `EngineAction`, `NetworkIdentity`, `ConnectionGeneration`, and `ReconnectPolicy`.
- `Engine::handle(&mut self, event: EngineEvent) -> Vec<EngineAction>` is deterministic and side-effect free.

- [ ] Write table-driven tests for Connect, Disconnect, child start/exit, stale-generation output, connection timeout, session expiry, native network loss/restoration, sleep/resume, and 10/20/40/80/120-second backoff.
- [ ] Add the critical test proving `NetworkReady` with a new identity cancels a 120-second retry and immediately emits `StartConnection`.
- [ ] Run `cargo test -p hyu-vpn-core --test state_machine` and confirm failure because the types are absent.
- [ ] Implement the minimum state machine and backoff logic needed by the table.
- [ ] Run `cargo test -p hyu-vpn-core` and confirm all transitions pass.
- [ ] Commit with `git commit -m "Implement portable reconnect state machine"`.

### Task 3: TOTP and non-reuse guard

**Files:**
- Create: `rust/crates/hyu-vpn-core/src/totp.rs`
- Create: `rust/crates/hyu-vpn-core/tests/totp.rs`
- Create: `tests/fixtures/totp-vectors.json`

**Interfaces:**
- Produces: `TotpSecret::parse(&str)`, `TotpGenerator::code_at(SystemTime)`, and `CounterGuard::reserve(counter: u64)`.
- Uses RFC 6238 SHA-1, six digits, and a 30-second step.

- [ ] Export deterministic Python-generated and RFC-compatible vectors into `tests/fixtures/totp-vectors.json` without real credentials.
- [ ] Write Rust tests for Base32 normalization, malformed input, exact code vectors, countdown, concurrent counter reservation, and refusal to reuse a counter.
- [ ] Run `cargo test -p hyu-vpn-core --test totp` and confirm failure.
- [ ] Implement TOTP and an atomic locked counter file with strict ownership/permission hooks.
- [ ] Run the Rust test plus the existing Python OTP/connector tests.
- [ ] Commit with `git commit -m "Port TOTP generation and reuse protection"`.

### Task 4: Credential envelope and log redaction

**Files:**
- Create: `rust/crates/hyu-vpn-core/src/credentials.rs`
- Create: `rust/crates/hyu-vpn-core/src/redaction.rs`
- Create: `rust/crates/hyu-vpn-core/tests/credentials.rs`
- Create: `rust/crates/hyu-vpn-core/tests/redaction.rs`

**Interfaces:**
- Produces: `CredentialEnvelope::seal`, `CredentialEnvelope::open`, `CredentialStore` trait, `KeyProtector` trait, and `RedactedError`.
- The plaintext model contains only `username`, `password`, and `totp_seed`.

- [ ] Write tests for AES-256-GCM round trips, nonce uniqueness, version mismatch, truncation, authentication failure, schema rejection, zeroization, and canary exclusion from every formatted error/log line.
- [ ] Add a fixture proving the Rust reader can open the current macOS combined AES-GCM envelope.
- [ ] Run credential and redaction tests and confirm failure.
- [ ] Implement the versioned envelope, compatibility decoder, and allow-listed diagnostic formatter.
- [ ] Run `cargo test -p hyu-vpn-core` and existing `tests/test_security_privacy.py`.
- [ ] Commit with `git commit -m "Add secret-safe credential envelope"`.

### Task 5: Network readiness and process supervision ports

**Files:**
- Create: `rust/crates/hyu-vpn-core/src/ports.rs`
- Create: `rust/crates/hyu-vpn-core/src/readiness.rs`
- Create: `rust/crates/hyu-vpn-core/src/openconnect.rs`
- Create: `rust/crates/hyu-vpn-core/tests/readiness.rs`
- Create: `rust/crates/hyu-vpn-core/tests/openconnect.rs`

**Interfaces:**
- Produces async traits `NetworkMonitor`, `PortalProbe`, `ConnectorProcess`, `ConnectorFactory`, `StatusSink`, and `Clock`.
- Produces `ReadinessGate::wait_for_stable_network` and `build_openconnect_args`, with secrets supplied only through bounded stdin.

- [ ] Write fake-adapter tests for two stable samples, tunnel-route rejection, DNS/TCP portal failure, event-driven wake, polling fallback, process-group termination, connection timeout, and no secret-bearing argv/environment.
- [ ] Run targeted tests and confirm failure.
- [ ] Implement the adapter traits, readiness gate, event parser, and OpenConnect command builder.
- [ ] Run `cargo test -p hyu-vpn-core` and compare OpenConnect argv/event fixtures with Python tests.
- [ ] Commit with `git commit -m "Add portable network and connector ports"`.

### Task 6: Daemon orchestration and authenticated IPC

**Files:**
- Create: `rust/crates/hyu-vpn-daemon/Cargo.toml`
- Create: `rust/crates/hyu-vpn-daemon/src/lib.rs`
- Create: `rust/crates/hyu-vpn-daemon/src/runtime.rs`
- Create: `rust/crates/hyu-vpn-daemon/src/ipc.rs`
- Create: `rust/crates/hyu-vpn-daemon/src/status_file.rs`
- Create: `rust/crates/hyu-vpn-daemon/tests/runtime.rs`
- Create: `rust/crates/hyu-vpn-daemon/tests/ipc.rs`

**Interfaces:**
- Consumes all core ports and protocol types.
- Produces `DaemonRuntime::run`, `CommandHandler::handle`, atomic status compatibility output, and transport-neutral `serve_connection`.

- [ ] Write end-to-end fake-daemon tests for status, connect, disconnect, reconnect, credential replacement, current OTP, concurrent commands, oversized frames, peer rejection, stale processes, restart recovery, and secret-free status output.
- [ ] Run `cargo test -p hyu-vpn-daemon` and confirm failure.
- [ ] Implement the orchestration loop, exact one-request-per-connection transport, single-instance lock, and atomic status writer.
- [ ] Run daemon tests under Tokio's paused clock where retry timing is involved.
- [ ] Commit with `git commit -m "Implement Rust VPN daemon and IPC"`.

### Task 7: Cross-language compatibility fixtures

**Files:**
- Create: `tests/fixtures/rust-protocol-v1/*.json`
- Create: `tests/test_rust_compatibility.py`
- Modify: `src/hyu_vpn/status.py`
- Modify: `macos/Sources/HYUVPNMenuCore/MenuCore.swift`

**Interfaces:**
- Consumes protocol/status fixtures from Task 1 and daemon status from Task 6.
- Produces a compatibility gate that all Python, Rust, and Swift decoders must pass.

- [ ] Add valid and hostile fixtures covering every state, all optional fields, version mismatch, unknown fields, secret fields, invalid timestamps, and oversized input.
- [ ] Write Python tests and Swift harness checks that consume the same fixtures.
- [ ] Run Python and Swift tests and confirm the new fixtures initially expose missing Rust-v1 compatibility.
- [ ] Add only the compatibility parsing required; do not switch the production macOS control path yet.
- [ ] Run `cargo test --workspace`, `python3 -m unittest discover -s tests`, and `swift test --package-path macos`.
- [ ] Commit with `git commit -m "Lock cross-language VPN protocol compatibility"`.

