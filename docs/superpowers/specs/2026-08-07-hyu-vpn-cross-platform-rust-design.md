# HYU VPN Cross-Platform Rust Design

## Goal

Ship one HYU VPN product for macOS 14+, Windows 11 x64, and Ubuntu 22.04/24.04 LTS x64. Each platform keeps a native menu-bar or system-tray experience while sharing one Rust connection engine. A user installs through a graphical installer, enters the HYU ID, password, and TOTP setup secret once, and can leave the app running so Wi-Fi changes, VPN process exits, and session expiry recover automatically.

## User-visible contract

- macOS keeps the existing Swift menu-bar application.
- Windows uses a native system-tray application and Windows-style credential dialogs.
- Ubuntu uses a GTK/AppIndicator tray application and GNOME-style dialogs.
- Every platform exposes the same operations: Connect, Disconnect, Reconnect, Launch at Login, credential replacement, current OTP with remaining time and click-to-copy, and Quit.
- Installation requests administrator authorization once. Normal launches, reconnects, OTP display, and credential updates do not repeatedly request an administrator password.
- Connect enables automatic reconnect. An explicit Disconnect disables it until the next Connect.
- No terminal window is part of installation or normal use.

## Architecture

The repository becomes a Rust workspace while the existing Python implementation remains as a temporary, testable compatibility oracle during migration.

### Shared Rust crates

- `hyu-vpn-protocol`: versioned, bounded IPC requests, responses, status documents, and stable error codes. Secret-bearing requests are accepted only on authenticated local IPC and never serialized to status or logs.
- `hyu-vpn-core`: the platform-independent state machine, reconnect policy, OpenConnect lifecycle, status projection, TOTP generation, session-expiry handling, log redaction, and interfaces for network, credential, posture, process, clock, and privilege adapters.
- `hyu-vpn-daemon`: service orchestration, single-instance enforcement, IPC server, state persistence, and adapter composition.
- `hyu-vpn-platform-macos`, `hyu-vpn-platform-windows`, and `hyu-vpn-platform-linux`: platform paths, connectivity monitoring, process control, privilege integration, conflict detection, secure file handling, and HIP posture collection.
- `hyu-vpn-cli`: a closed administrative/test client supporting only the fixed control operations. It never accepts credentials as command-line arguments.

The daemon launches the packaged OpenConnect executable rather than embedding or dynamically loading `libopenconnect`. This preserves a narrow process boundary, makes license materials and binary closure explicit, and lets the same state machine supervise platform-specific OpenConnect packages.

### Native applications

- macOS: the existing Swift app moves from Python control/status files to the versioned Unix-socket protocol after parity tests pass.
- Windows: a self-contained .NET 8 WinForms tray executable uses `NotifyIcon`, Windows dialogs, and an ACL-restricted named pipe client.
- Ubuntu: a Rust GTK4 application uses Ayatana AppIndicator/StatusNotifier integration and the daemon Unix socket.

The native apps contain presentation and input validation only. They do not manage routes, spawn OpenConnect, calculate retry policy, or persist plaintext credentials.

## Connection state machine

The canonical states are `disabled`, `waiting_for_network`, `connecting`, `connected`, `disconnecting`, `backoff`, and `error`. The state machine maintains one active connection generation so stale OpenConnect output cannot mutate a newer session.

1. Connect persists automatic reconnect as enabled and starts network readiness evaluation.
2. Readiness requires a non-tunnel default route, DNS resolution for the HYU portal, and bounded TCP reachability to the portal on port 443.
3. Two stable samples prevent connection attempts during an interface transition. Native network-change events wake the sampler immediately; polling is only a fallback.
4. Once ready, the daemon reads credentials, generates a non-reused TOTP code, starts OpenConnect, and waits for verified tunnel evidence.
5. A successful tunnel moves to `connected`; expiry metadata and HIP success are projected into secret-free status.
6. A process exit or session expiry schedules reconnect. Failures back off at 10, 20, 40, 80, and 120 seconds.
7. A transition from unavailable to usable network, or a change in network identity, resets the backoff and starts a connection attempt within ten seconds, excluding the OpenConnect handshake itself.
8. Captive-portal or unreachable-portal conditions remain in `waiting_for_network` instead of consuming the failure backoff.
9. Explicit Disconnect terminates the owned generation, restores only owned network changes, and disables automatic reconnect.

Sleep and resume are treated as a network identity transition. Service restart restores the automatic-reconnect preference but never assumes an old tunnel still exists without fresh platform evidence.

## IPC and status

- The wire format is length-bounded JSON with `schema_version: 1` and exact-field validation.
- Commands are `status`, `connect`, `disconnect`, `reconnect`, `automatic_on`, `automatic_off`, `credentials_present`, `replace_credentials`, and `current_otp`.
- Unix sockets use an owner-only directory and peer-credential verification. Windows uses a named pipe restricted to the interactive user and the service identity.
- `replace_credentials` is the only secret-bearing message. The UI sends it directly over authenticated IPC; secrets never enter argv, environment variables, status files, crash reports, or logs.
- Status is available through IPC and an atomic, secret-free compatibility file during the macOS migration.

## Credential and TOTP storage

- Credentials are stored as a versioned AES-256-GCM document with strict size and schema limits.
- macOS initially reads the existing `credentials.key` and `credentials.enc` format so upgrades require no re-entry.
- Windows wraps the data-encryption key with DPAPI and applies an explicit user/service ACL.
- Ubuntu stores the data-encryption key in a root-owned mode-0600 service directory; only the root daemon decrypts credentials. The user submits replacements over the peer-authenticated Unix socket.
- TOTP uses RFC 6238 SHA-1, a 30-second step, six digits, Base32 validation, and a persisted counter guard that prevents reuse across rapid reconnects.
- Clipboard copies contain only the current OTP and are not logged. Clearing the clipboard automatically is not guaranteed because clipboard ownership differs by desktop environment.

## Privileged boundaries and network restoration

- macOS retains its existing privileged helper and transaction ledger during the backend migration.
- Windows runs the Rust daemon as a Windows Service with the minimum service permissions needed by the packaged OpenConnect/TUN driver. The tray application remains unprivileged.
- Ubuntu runs the Rust daemon as a hardened systemd service. The tray application remains unprivileged.
- Every route, DNS, and interface change is recorded before mutation and restored only when current state still matches the owned mutation. Foreign VPN state is never removed speculatively.
- GlobalProtect conflict detection is platform-specific and blocks rather than mutates a foreign active tunnel.

## HIP posture

The existing HIP XML schema and cookie identity rules remain shared. Each platform supplies truthful posture values through a narrow adapter:

- macOS reuses the existing posture behavior until the Rust collector reaches fixture parity.
- Windows collects OS/build, host identity, interfaces, update information, firewall, antivirus, and disk-encryption state from documented Windows APIs or bounded system commands.
- Ubuntu collects distribution/kernel, host identity, interfaces, package updates, firewall, endpoint-protection availability, and disk-encryption state from bounded, allow-listed sources.

Missing posture evidence is reported as `unknown`, never fabricated. HIP output is fixture-tested and contains no credential, OTP seed, cookie, or unbounded command output.

## Installation and launch-at-login

### macOS

The existing DMG and graphical installer remain supported. A later package revision swaps the installed service binary only after Swift/Rust protocol parity passes.

### Windows

A signed-capable x64 installer installs the self-contained tray app, Rust service, OpenConnect runtime, required TUN driver, notices, and uninstall support. UAC appears once during install. The service starts automatically; Launch at Login controls the per-user tray startup entry.

### Ubuntu

An amd64 DEB installs the GTK tray app, Rust daemon, OpenConnect runtime dependency declaration, systemd unit, desktop entry, AppIndicator dependency, notices, and purge-safe configuration ownership. `pkexec` or the package manager supplies the single installation authorization. Launch at Login controls the user autostart desktop entry, not the root service.

## Migration and rollout

1. Freeze the Python behavior with shared scenario fixtures and golden status/IPC examples.
2. Implement and test the Rust protocol, state machine, TOTP, redaction, credential envelope, and fake platform adapters.
3. Add Linux adapters and DEB packaging, then validate on Ubuntu 22.04 and 24.04 CI runners/containers where host networking permits.
4. Add Windows adapters, native tray client, and installer, then validate on Windows CI.
5. Run macOS Python/Rust parity tests. Switch the existing Swift UI to Rust only after install, connect, reconnect, sleep/wake, credential replacement, and uninstall scenarios pass.
6. Keep a one-release rollback path to the Python macOS backend. Remove the Python runtime only after the Rust backend has shipped and passed live acceptance.

## Failure handling

- Invalid credentials, unavailable portal, helper failure, tunnel timeout, unsafe state drift, and incompatible protocol versions map to stable non-secret error codes.
- Authentication failures stop aggressive retrying and surface a credential-update action.
- Network unavailability remains recoverable without user action.
- Unsafe or partially owned network state fails closed and requires repair rather than deleting unknown routes or DNS settings.
- Installer failures roll back newly installed files, service registration, autostart entries, and newly created credentials while preserving pre-existing valid installations.

## Verification

- Rust unit and property tests cover state transitions, retry timing, network-change wakeups, stale-generation suppression, TOTP counter behavior, exact IPC schemas, log redaction, credential corruption, and transactional restoration.
- Contract fixtures run against both Python and Rust during migration.
- Native UI tests verify menu enablement, tab order, paste behavior, credential transaction ordering, OTP countdown/copy, Launch at Login, and quit behavior.
- Packaging tests inspect file ownership, permissions/ACLs, manifests, third-party notices, uninstall behavior, and absence of plaintext secrets.
- CI builds and tests macOS arm64, Windows x64, and Ubuntu amd64 artifacts. Platform-specific live acceptance remains required before calling a release production-ready.
- The critical reconnect scenario disconnects the physical network, restores a different network, and proves a new VPN attempt begins within ten seconds without user interaction or credential prompts.

## Non-goals

- Supporting Windows 10, non-GNOME Linux desktops, ARM Windows, ARM Linux, mobile platforms, or browser-only operation in the first cross-platform release.
- Reimplementing the OpenConnect protocol.
- Making the three native UIs pixel-identical.
- Removing the working macOS Python backend before Rust parity and rollback validation.

## Completion criteria

The work is complete when all three supported platforms have native tray/menu applications, graphical installation, one-time credential collection, OTP display/copy, launch-at-login control, secret-safe local storage, automatic reconnect after expiry and network movement, tested uninstall/rollback behavior, and installable artifacts produced by CI. A platform is not advertised as production-ready until its live reconnect and network-restoration acceptance matrix passes on that operating system.
