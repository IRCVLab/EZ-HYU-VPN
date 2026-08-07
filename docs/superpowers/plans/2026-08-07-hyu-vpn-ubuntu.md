# HYU VPN Ubuntu Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an installable Ubuntu 22.04/24.04 amd64 DEB with a hardened Rust daemon, native GTK/AppIndicator tray UI, one-time graphical credential collection, and automatic reconnect.

**Architecture:** A root systemd service composes Linux adapters around the shared Rust daemon. An unprivileged GTK4 tray client communicates through an owner-authenticated Unix socket and manages only presentation, credentials, and user autostart.

**Tech Stack:** Rust, Tokio, rtnetlink/netlink notifications, GTK4, Ayatana AppIndicator, systemd, Debian packaging, OpenConnect.

## Global Constraints

- Support Ubuntu 22.04 and 24.04 LTS GNOME on amd64.
- Network restoration resets retry backoff and starts an attempt within ten seconds.
- Installation may use one package-manager/pkexec authorization; normal use must not prompt for sudo.
- Secrets cross only the authenticated Unix socket and remain absent from logs, argv, and environment.

---

### Task 1: Linux service adapters

**Files:**
- Create: `rust/crates/hyu-vpn-platform-linux/Cargo.toml`
- Create: `rust/crates/hyu-vpn-platform-linux/src/lib.rs`
- Create: `rust/crates/hyu-vpn-platform-linux/src/network.rs`
- Create: `rust/crates/hyu-vpn-platform-linux/src/process.rs`
- Create: `rust/crates/hyu-vpn-platform-linux/src/storage.rs`
- Create: `rust/crates/hyu-vpn-platform-linux/src/peer.rs`
- Create: `rust/crates/hyu-vpn-platform-linux/tests/linux_adapters.rs`

**Interfaces:**
- Implements the core `NetworkMonitor`, `ConnectorFactory`, `CredentialStore`, and IPC peer-authorizer ports.
- Produces `LinuxPlatform::production()` and `LinuxPaths`.

- [ ] Write namespace-safe tests for route identity, network-change notification, UID peer checks, mode-0600 storage, symlink rejection, process-group cleanup, and OpenConnect stdin handling.
- [ ] Run the tests on Ubuntu CI and confirm failure.
- [ ] Implement bounded Linux adapters using netlink events plus a one-second polling fallback.
- [ ] Run Linux adapter and shared workspace tests.
- [ ] Commit with `git commit -m "Add hardened Linux VPN adapters"`.

### Task 2: Linux HIP posture

**Files:**
- Create: `rust/crates/hyu-vpn-platform-linux/src/posture.rs`
- Create: `rust/crates/hyu-vpn-platform-linux/tests/posture.rs`
- Create: `tests/fixtures/linux-posture/*.txt`
- Create: `tests/fixtures/linux-posture/expected-hip.xml`

**Interfaces:**
- Produces `LinuxPostureCollector::collect() -> Posture` using fixed absolute command paths and bounded output.

- [ ] Add Ubuntu 22.04/24.04 fixtures for os-release, kernel, interfaces, package updates, firewall, endpoint status, and encrypted storage.
- [ ] Write exact XML and hostile-output tests; unknown evidence must remain `unknown`.
- [ ] Implement allow-listed collectors and shared HIP mapping.
- [ ] Run posture tests and secret-canary scans.
- [ ] Commit with `git commit -m "Add truthful Ubuntu HIP posture"`.

### Task 3: GTK/AppIndicator tray application

**Files:**
- Create: `rust/apps/hyu-vpn-gtk/Cargo.toml`
- Create: `rust/apps/hyu-vpn-gtk/src/main.rs`
- Create: `rust/apps/hyu-vpn-gtk/src/menu.rs`
- Create: `rust/apps/hyu-vpn-gtk/src/credentials.rs`
- Create: `rust/apps/hyu-vpn-gtk/src/autostart.rs`
- Create: `rust/apps/hyu-vpn-gtk/tests/model.rs`
- Create: `assets/icons/hyu-vpn.svg`

**Interfaces:**
- Consumes the protocol client and renders status without direct service mutation.
- Produces a native indicator menu with status, OTP/countdown/copy, Connect/Disconnect/Reconnect, Launch at Login, Change Credentials, and Quit.

- [ ] Write UI-model tests for every daemon state, button enablement, OTP countdown, clipboard action, tab order, credential confirmation, reconnect transaction ordering, autostart state, and quit.
- [ ] Implement the pure model before GTK widgets and verify it headlessly.
- [ ] Implement GTK dialogs and AppIndicator wiring with all daemon calls off the UI thread.
- [ ] Run tests under `xvfb-run` and perform a package smoke launch.
- [ ] Commit with `git commit -m "Add native Ubuntu tray application"`.

### Task 4: systemd unit and DEB packaging

**Files:**
- Create: `packaging/linux/hyu-vpn.service`
- Create: `packaging/linux/hyu-vpn.desktop`
- Create: `packaging/linux/com.hyu.vpn.policy`
- Create: `packaging/linux/debian/control`
- Create: `packaging/linux/debian/postinst`
- Create: `packaging/linux/debian/prerm`
- Create: `packaging/linux/debian/postrm`
- Create: `scripts/package-linux.sh`
- Create: `tests/test_linux_packaging.py`

**Interfaces:**
- Installs `/usr/lib/hyu-vpn`, `/usr/bin/hyu-vpn`, `/etc/hyu-vpn`, the systemd unit, PolicyKit metadata, desktop entry, icons, licenses, and uninstall scripts.

- [ ] Write static tests for systemd hardening, package dependencies, root ownership, socket directory lifecycle, idempotent upgrades, purge behavior, autostart ownership, notices, and absence of secrets.
- [ ] Implement the unit and maintainer scripts with no interactive shell flow.
- [ ] Build the amd64 DEB and inspect it with `dpkg-deb --info` and `dpkg-deb --contents`.
- [ ] Install/upgrade/remove it in Ubuntu containers, then run service and UI smoke tests where systemd is available.
- [ ] Commit with `git commit -m "Package HYU VPN for Ubuntu"`.

### Task 5: Ubuntu acceptance workflow

**Files:**
- Create: `.github/workflows/ubuntu.yml`
- Create: `tests/linux_acceptance.sh`
- Modify: `README.md`

**Interfaces:**
- Produces checksummed Ubuntu 22.04/24.04 amd64 DEBs as CI artifacts.

- [ ] Add CI jobs for formatting, Clippy, unit tests, GTK headless tests, DEB build, package inspection, and clean install/upgrade/uninstall.
- [ ] Add an opt-in live test that proves network loss/new-network recovery begins within ten seconds without credential prompts.
- [ ] Document GUI installation and tray usage only; do not expose internal service commands in the end-user README.
- [ ] Run the workflow and retain artifact checksums in the build summary.
- [ ] Commit with `git commit -m "Verify Ubuntu VPN distribution"`.

