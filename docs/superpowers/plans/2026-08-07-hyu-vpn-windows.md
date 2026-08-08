# HYU VPN Windows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a Windows 11 x64 installer containing a Rust Windows Service and a native .NET tray application with automatic reconnect, OTP, credentials, and launch-at-login controls.

**Architecture:** The Rust service owns OpenConnect, network state, credentials, and reconnect policy. A self-contained WinForms tray app communicates through an ACL-restricted named pipe and performs no privileged networking.

**Tech Stack:** Rust, Tokio, Windows APIs, .NET 8 WinForms, Windows Service Control Manager, named pipes, DPAPI, and WiX Toolset 5.

## Global Constraints

- Support Windows 11 x64.
- UAC appears only during installation, upgrade, repair, and uninstall.
- A changed or restored network resets retry backoff and starts an attempt within ten seconds.
- No console window appears during installation or normal use.
- Secrets never enter process arguments, environment variables, logs, status, or crash output.

---

### Task 1: Windows service adapters

**Files:**
- Create: `rust/crates/hyu-vpn-platform-windows/Cargo.toml`
- Create: `rust/crates/hyu-vpn-platform-windows/src/lib.rs`
- Create: `rust/crates/hyu-vpn-platform-windows/src/network.rs`
- Create: `rust/crates/hyu-vpn-platform-windows/src/process.rs`
- Create: `rust/crates/hyu-vpn-platform-windows/src/storage.rs`
- Create: `rust/crates/hyu-vpn-platform-windows/src/peer.rs`
- Create: `rust/crates/hyu-vpn-platform-windows/tests/windows_adapters.rs`

**Interfaces:**
- Implements core network/process/storage ports and named-pipe peer authorization.
- Produces `WindowsPlatform::production()` and `WindowsPaths`.

- [ ] Write Windows tests for adapter identity changes, interface notifications, DPAPI round trips, ACL rejection, named-pipe identity checks, Job Object cleanup, and hidden OpenConnect process startup.
- [ ] Run tests on Windows CI and confirm failure.
- [ ] Implement the adapters with documented Windows APIs and bounded conversions.
- [ ] Run Windows and shared workspace tests.
- [ ] Commit with `git commit -m "Add Windows VPN service adapters"`.

### Task 2: Windows Service host and HIP posture

**Files:**
- Create: `rust/apps/hyu-vpn-windows-service/Cargo.toml`
- Create: `rust/apps/hyu-vpn-windows-service/src/main.rs`
- Create: `rust/crates/hyu-vpn-platform-windows/src/posture.rs`
- Create: `rust/crates/hyu-vpn-platform-windows/tests/posture.rs`
- Create: `tests/fixtures/windows-posture/*.json`

**Interfaces:**
- Hosts `DaemonRuntime` under Service Control Manager and maps stop/shutdown/session-change controls.
- Produces truthful Windows posture for shared HIP XML generation.

- [ ] Write service lifecycle tests and fixtures for Windows build, device identity, adapters, update state, Defender/antivirus, firewall, and BitLocker.
- [ ] Write hostile/missing-evidence tests that emit `unknown` without leaking command or API output.
- [ ] Implement the service entry point and posture adapter.
- [ ] Run service/posture tests on Windows CI.
- [ ] Commit with `git commit -m "Host HYU VPN as a Windows service"`.

### Task 3: Native Windows tray application

**Files:**
- Create: `windows/HYUVPN.sln`
- Create: `windows/HYUVPN.Tray/HYUVPN.Tray.csproj`
- Create: `windows/HYUVPN.Tray/Program.cs`
- Create: `windows/HYUVPN.Tray/TrayApplicationContext.cs`
- Create: `windows/HYUVPN.Tray/CredentialDialog.cs`
- Create: `windows/HYUVPN.Tray/ProtocolClient.cs`
- Create: `windows/HYUVPN.Tray/AutostartManager.cs`
- Create: `windows/HYUVPN.Tray.Tests/HYUVPN.Tray.Tests.csproj`

**Interfaces:**
- Consumes protocol version 1 through `ProtocolClient`.
- Produces a `NotifyIcon` menu with status, OTP/countdown/copy, connection actions, Launch at Login, Change Credentials, and Quit.

- [ ] Write .NET tests for exact protocol JSON, menu-state projection, credential validation, tab order, OTP countdown/copy, reconnect transaction ordering, autostart enable/disable, cancellation, and quit.
- [ ] Implement the pure view model and named-pipe client first.
- [ ] Implement native dialogs and `NotifyIcon` wiring with background async calls marshalled to the UI synchronization context.
- [ ] Publish a self-contained `win-x64` GUI executable and prove it has Windows subsystem metadata rather than a console subsystem.
- [ ] Commit with `git commit -m "Add native Windows tray application"`.

### Task 4: Windows installer and lifecycle

**Files:**
- Create: `packaging/windows/Product.wxs`
- Create: `packaging/windows/Files.wxs`
- Create: `scripts/package-windows.ps1`
- Create: `tests/windows/Installer.Tests.ps1`
- Create: `packaging/windows/LICENSES/README.md`

**Interfaces:**
- Installs the service, tray app, OpenConnect runtime, TUN driver dependency, icons, notices, Start Menu entry, and uninstall metadata.

- [ ] Write PowerShell assertions for per-machine paths, service account/start mode, named-pipe ACL setup, one elevation boundary, no console custom action, upgrade codes, rollback, uninstall, and third-party notices.
- [ ] Implement deterministic x64 packaging and code-signing hooks that work unsigned in CI and signed when secrets are present.
- [ ] Exercise silent install, upgrade, repair, and uninstall in a Windows CI VM.
- [ ] Verify no plaintext credential material exists in MSI tables, install logs, registry, or process command lines.
- [ ] Commit with `git commit -m "Package HYU VPN for Windows"`.

### Task 5: Windows acceptance workflow

**Files:**
- Create: `.github/workflows/windows.yml`
- Create: `tests/windows/Acceptance.Tests.ps1`
- Modify: `README.md`

**Interfaces:**
- Produces checksummed Windows x64 installer artifacts.

- [ ] Add CI for Rust format/Clippy/tests, .NET tests, self-contained publish, installer build, clean install/upgrade/uninstall, and secret scans.
- [ ] Add an opt-in live acceptance test proving new-network recovery begins within ten seconds without UAC or credential prompts.
- [ ] Document graphical installation and tray use in the end-user README.
- [ ] Run the workflow and retain installer checksum evidence.
- [ ] Commit with `git commit -m "Verify Windows VPN distribution"`.
