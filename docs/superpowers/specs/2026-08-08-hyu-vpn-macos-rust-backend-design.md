# HYU VPN macOS Rust Backend Design

## Decision

HYU VPN for macOS will use a native Swift/AppKit frontend and a new Rust
connection backend. The existing Python connection backend is not migrated or
retained as a product dependency; the macOS backend is implemented as a new
platform composition over the already implemented shared Rust crates.

The long-term boundary is:

```text
HYU VPN.app (Swift/AppKit presentation)
        |
        | schema-v1 bounded JSON over an owner-only Unix socket
        v
hyu-vpn-macos-service (Rust lifecycle authority)
        |
        +-- hyu-vpn-core
        +-- hyu-vpn-daemon
        +-- hyu-vpn-protocol
        +-- hyu-vpn-platform-macos
        |
        | fixed, secret-free privileged command contract
        v
com.hyu.vpn.helper (small Swift root boundary)
        |
        v
packaged OpenConnect and owned route/DNS transaction ledger
```

## Why the frontend remains Swift

The menu-bar application is an operating-system integration surface, not the
portable VPN engine. Swift/AppKit provides the most direct and stable access to
macOS status items, menus, text-field focus and paste behavior, clipboard,
accessibility, login items, update dialogs, administrator authorization UI,
application lifecycle, signing, notarization, and future Apple platform changes.

A Rust frontend could reduce the number of implementation languages and share
some view-model code with Windows or Ubuntu. Those benefits do not outweigh the
costs here:

- a cross-platform GUI or WebView adds runtime and packaging surface;
- macOS tray, accessibility, login, and authorization behavior still requires
  macOS-specific bridges;
- native keyboard, focus, paste, and menu behavior becomes harder to guarantee;
- signing, notarization, crash diagnosis, and new macOS API adoption become more
  indirect;
- the three operating systems intentionally have OS-specific presentation.

The Swift frontend therefore remains a thin, replaceable protocol client. It
does not calculate TOTP, choose retries, launch OpenConnect, own routes, persist
credentials, or infer connection state. This boundary keeps native UX without
creating a second connection implementation.

## Existing Rust foundation

The following crates are already portable and are reused unchanged where their
contracts satisfy macOS requirements:

- `hyu-vpn-protocol`: exact versioned IPC requests, responses, status documents,
  stable error codes, and bounded secret-bearing credential replacement;
- `hyu-vpn-core`: state machine, readiness policy, network-change behavior,
  retry/backoff, session expiry, TOTP, encrypted credential envelope, and
  diagnostic redaction;
- `hyu-vpn-daemon`: event orchestration, connection-generation ownership,
  request handling, and atomic secret-free status projection.

These crates build and their 37 current integration tests pass on Apple Silicon
macOS. That proves the portable contracts compile and behave on macOS, but it
does not prove an installed Mac application until the macOS adapter, service,
Swift integration, packaging, and live acceptance below also pass.

## New Rust components

### `hyu-vpn-platform-macos`

This crate implements macOS ports for the shared engine:

- canonical per-user paths and secure filesystem validation;
- compatibility import of the user's existing AES-256-GCM credential files,
  followed by the same versioned Rust envelope implementation;
- physical network identity and readiness using bounded macOS evidence while
  excluding `utun*` interfaces;
- sleep/wake and network-change wakeups;
- exact invocation and parsing of the installed privileged helper;
- reconciliation of helper state after service restart;
- GlobalProtect conflict detection that blocks rather than mutates foreign VPN
  state;
- truthful HIP evidence through a fixed packaged interface;
- strict process ownership and bounded child cleanup.

The adapter never modifies routes or DNS itself. All privileged network changes
remain inside the existing audited helper and transaction ledger.

### `hyu-vpn-macos-service`

This native arm64 binary composes the shared daemon and macOS adapter. It is the
only connection lifecycle authority. It owns:

- one connection generation at a time;
- automatic reconnect preference;
- portal readiness and network-change evaluation;
- TOTP generation and counter non-reuse;
- helper start/stop/status/repair orchestration;
- bounded Unix-socket IPC;
- atomic status publication;
- credential replacement and zeroization;
- recovery after sleep, process exit, session expiry, and service restart.

The service retains the current private application-support directory only as a
stable user-data location. It does not import Python modules, execute Python
scripts, or share authority with the old service.

## Swift frontend integration

The Swift menu app connects directly to the Rust Unix socket. It no longer
executes `hyu-vpn-control` or reads Python-specific behavior.

The Swift client has:

- exact request/response types matching protocol schema version 1;
- strict byte and field limits;
- bounded connect/read/write timeouts;
- peer-owned socket path validation;
- stable mapping from non-secret error codes to menu presentation;
- one credential form that sends HYU ID, password, and TOTP setup secret as one
  authenticated local transaction;
- current OTP display/countdown and click-to-copy through the Rust service;
- no fallback backend and no silent protocol downgrade.

The existing status file remains a read-only compatibility projection for UI
startup and diagnostics during one release. It is never network authority.

## Privileged helper boundary

The Swift helper remains because it is a small macOS-specific security boundary
with existing route/DNS ownership and repair logic. Keeping it does not retain
the legacy backend: it is an OS adapter below the Rust lifecycle authority.

Only four fixed commands are permitted: `start`, `stop`, `status`, and `repair`.
The sudoers entry remains exact. Credentials, passwords, OTP seeds/codes,
cookies, portal responses, and untrusted strings never enter helper argv,
environment variables, status output, or logs.

Moving this helper to Rust is explicitly deferred unless a future audit finds a
correctness or maintainability reason. Rewriting a working privileged boundary
solely for language uniformity would add risk without improving product behavior.

## Product cleanup

The production macOS payload removes:

- `hyu-vpn-service` Python entry point;
- `hyu-vpn-control` Python entry point;
- `hyu-vpn-connect` Python entry point;
- installed `src/hyu_vpn` Python package;
- `/usr/bin/python3` from the service launchd plist;
- Python-based automatic-reconnect preference mutations in the installer.

Python tests may temporarily remain in the repository only for unrelated
packaging or historical regression coverage while equivalent Rust/Swift tests
are introduced. Release artifacts must contain no production Python backend.
After parity is proven, obsolete backend sources and tests are deleted rather
than maintained indefinitely.

Existing encrypted user credentials are data, not backend code. The installer
preserves or imports them without displaying plaintext and without Keychain.

## Installation and rollback

The DMG stages and verifies the Rust service before administrator authorization.
The root transaction:

1. stops the old user service and safely drains any helper-owned session;
2. snapshots the existing installation for transactional rollback only;
3. preserves the user's encrypted credential files;
4. installs and hashes the Rust service and direct launchd plist;
5. starts the Rust service and performs a bounded protocol health check;
6. activates the Swift menu app only after service readiness;
7. restores the pre-install snapshot if any mutation or health check fails.

The new package does not ship the old Python backend as a fallback. Rollback uses
the machine's pre-install snapshot during the installer transaction; successful
installation leaves one Rust service and one Swift menu process.

## Verification strategy

Verification proves the portable Rust engine and installed macOS product
separately. Ubuntu internal-network connectivity is not accepted as evidence.

### 1. Portable Rust engine

Deterministic tests with fake ports and a virtual clock cover:

- connect, disconnect, reconnect, and automatic reconnect preference;
- two-sample readiness, offline waiting, network identity change, and recovery;
- OpenConnect exit, session expiry, and retry delays of
  `10, 20, 40, 80, 120` seconds;
- retry reset after a usable network returns;
- stale generation suppression and exactly one active generation;
- authentication failure without aggressive retry;
- credential replacement during connect and backoff;
- RFC 6238 vectors, counter non-reuse, encrypted-envelope corruption, and
  zeroization boundaries;
- exact IPC/status schemas, size limits, authorization, and redaction;
- generated event-sequence invariant tests.

These run on macOS, Windows, and Ubuntu CI but do not depend on a real VPN.

### 2. macOS platform adapter

Tests use fixtures, temporary directories, fake helper binaries, and bounded
system evidence without touching live routes:

- physical route/interface discovery with `utun*` exclusion;
- sleep/wake and network-change mapping;
- credential import and adversarial file owner/mode/symlink cases;
- exact helper argv, response parsing, timeout, ownership, and repair behavior;
- HIP fixture parity and GlobalProtect conflict handling;
- no secret in argv, environment, status, diagnostics, crash output, or logs.

### 3. Swift/Rust protocol integration

Golden protocol fixtures execute against both Rust and Swift. Tests cover every
menu state and control, daemon unavailable/incompatible behavior, credential
replacement, OTP countdown/copy, launch-at-login, quit, tab order, paste, and
bounded error presentation.

### 4. Package and lifecycle

From a clean checkout, CI and local Mac verification cover:

- Rust formatting, all-target tests, Clippy with warnings denied, and audit;
- Swift tests and helper/menu/installer harnesses;
- arm64 identity, deep code signatures, DMG mount/verify, and runtime closure;
- direct launchd execution of the Rust service;
- absence of the production Python backend;
- upgrade from v0.1.1 with credentials preserved;
- injected installer failure and exact rollback at every mutation boundary;
- single service/menu instance, launch-at-login, quit/relaunch, and uninstall;
- public artifact checksum and installed-binary hash identity.

### 5. Real Mac acceptance

Only after all deterministic gates pass:

- install through the graphical installer with one administrator authorization;
- import authorized local encrypted credentials without displaying plaintext;
- connect until the helper verifies a live `utun` interface;
- verify HIP success and secret-free connected status;
- terminate only the owned OpenConnect generation and prove automatic reconnect
  without credential prompts;
- restart only the Rust service and prove safe reconciliation/reconnect;
- simulate session expiry and verify the documented retry;
- disconnect and prove owned DNS/routes restore while normal internet works;
- perform one controlled physical network loss/change and prove a new attempt
  starts within ten seconds after readiness returns;
- upgrade, rollback injection, and uninstall without leaving stale services,
  routes, DNS, or credentials in logs.

The physical network-loss test is intentionally the final disruptive gate. No
ordinary build or test command disables Wi-Fi or changes live routes.

## Ubuntu incident separation

The Ubuntu host is not used to prove the shared engine or macOS product. Its SSH
outage is a separate safety defect. Static evidence shows that the installed
Linux `hyu-vpnc-script` preserves established SSH reply routes only for port 22,
while the host is managed on port 2200. This is a credible cause of the lockout
when OpenConnect changes routes, but live route evidence is still required once
access returns.

No further network mutation is made on that host while it is unreachable. When
access returns, the VPN service is stopped first, route and service evidence is
captured, and SSH recovery is verified. The Linux fix is test-first and must
discover or explicitly configure the real SSH listener rather than hard-code a
port.

## Completion criteria

The macOS Rust backend is complete only when:

- the installed launchd service is the Rust binary;
- the Swift app controls the real Rust service through authenticated IPC;
- the production payload and launchd path contain no Python backend;
- all portable Rust, macOS adapter, Swift integration, security, installer,
  package, and public-artifact gates pass from a clean checkout;
- real connect, owned-process reconnect, service restart, session expiry,
  physical network recovery, disconnect restoration, upgrade, rollback, and
  uninstall pass on the target Mac;
- no credential, password, OTP seed/code, cookie, or session material appears in
  argv, environment, status, logs, installer output, or release artifacts;
- every failed or interrupted test leaves the non-VPN network usable;
- release documentation distinguishes deterministic proof from live platform
  evidence and does not substitute Ubuntu internal connectivity for VPN proof.
