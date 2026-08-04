# HYU OpenConnect HIP Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify a native-GlobalProtect-independent OpenConnect service that performs dual-TOTP authentication, submits a truthful macOS HIP report, reconnects safely, and leaves no stale routes or DNS state.

**Architecture:** A Python-standard-library HIP wrapper converts OpenConnect's csd-wrapper arguments and live macOS posture into deterministic HIP v4 XML. A pty-based connector handles the two OTP challenges and owns the OpenConnect process group; a small supervisor provides bounded reconnect backoff. All live network testing is gated behind an offline suite and a reversible state snapshot.

**Tech Stack:** Python 3 standard library, `unittest`, `/opt/homebrew/bin/openconnect` 9.21, `/opt/homebrew/bin/oathtool`, macOS Keychain, launchd, vpnc-script.

## Global Constraints

- The completed runtime must not execute or depend on GlobalProtect, PanGPS, PanGPA, PanGpHip, PanGpHipMp, or native cached HIP report files.
- Report actual posture; never convert probe failures into fabricated compliant values.
- Do not add runtime dependencies.
- Do not persist or log passwords, TOTP seeds, OTP values, authentication cookies, host identifiers, MAC addresses, or raw HIP XML.
- Do not disturb the current native VPN session until all offline verification passes.
- Do not enable automatic launch until one controlled foreground connect/use/disconnect cycle passes.
- Do not uninstall GlobalProtect without a separate explicit request.

---

### Task 1: Lock the OpenConnect HIP contract and native schema

**Files:**
- Create: `src/hyu_vpn/__init__.py`
- Create: `src/hyu_vpn/hip_contract.py`
- Create: `tests/fixtures/native_hip_sanitized.xml`
- Create: `tests/test_hip_contract.py`

**Interfaces:**
- Produces: `HipInvocation.from_argv(argv: Sequence[str], environ: Mapping[str, str]) -> HipInvocation`
- Produces: immutable `HipInvocation(cookie, client_ip, client_ipv6, md5, client_os, app_version)`
- Produces: `CookieIdentity.from_encoded(value: str) -> CookieIdentity`

- [ ] **Step 1: Add a failing test for required OpenConnect arguments**

Assert that cookie, md5, and at least one client address are required, while IPv4-only and IPv6-only invocations are valid.

- [ ] **Step 2: Run the focused test and confirm the expected missing-symbol failure**

Run: `python3 -m unittest -v tests.test_hip_contract`

- [ ] **Step 3: Implement the immutable invocation parser without logging argv**

Use `argparse.ArgumentParser(add_help=False)` and a custom exception whose message names only missing option names.

- [ ] **Step 4: Add a failing URL-encoded cookie parsing test**

Cover percent-encoded user, empty domain, plus-encoded computer name, reordered fields, and absent optional values.

- [ ] **Step 5: Implement `CookieIdentity` with `urllib.parse.parse_qs(..., keep_blank_values=True)`**

- [ ] **Step 6: Add the fully synthetic native HIP fixture**

The fixture must preserve element/category structure but use `TEST-USER`, `TEST-HOST`, `00:00:00:00:00:00`, and documentation IP ranges only.

- [ ] **Step 7: Run the focused suite and commit**

Run: `python3 -m unittest -v tests.test_hip_contract`

Commit: `test: lock HIP invocation contract`

### Task 2: Generate deterministic HIP v4 XML

**Files:**
- Create: `src/hyu_vpn/hip_xml.py`
- Create: `tests/test_hip_xml.py`

**Interfaces:**
- Consumes: `HipInvocation`, `CookieIdentity`
- Produces: posture dataclasses `HostInfo`, `Product`, `Drive`, `Patch`, `MacPosture`
- Produces: `build_hip_xml(invocation: HipInvocation, identity: CookieIdentity, posture: MacPosture, generated_at: datetime) -> bytes`

- [ ] **Step 1: Add a failing minimal-report test**

Assert the root header contains the passed md5, user/domain/computer identity, client addresses, timestamp, report version 4, and categories in native order.

- [ ] **Step 2: Run the focused test and observe failure because the builder is absent**

Run: `python3 -m unittest -v tests.test_hip_xml.HipXmlTests.test_builds_required_header_and_category_order`

- [ ] **Step 3: Implement immutable posture dataclasses and the minimal ElementTree builder**

- [ ] **Step 4: Add failing golden normalized-schema and XML-escaping tests**

Normalize timestamp, md5, addresses, and identifiers before comparing against the synthetic native fixture. Include `&`, `<`, `>`, quotes, non-ASCII text, and malicious shell-looking strings.

- [ ] **Step 5: Implement all seven categories and deterministic ordering**

- [ ] **Step 6: Add a failing test proving unknown posture is not emitted as `yes` or `encrypted`**

- [ ] **Step 7: Implement explicit unknown/empty representations and re-run the complete XML suite**

Run: `python3 -m unittest -v tests.test_hip_xml`

- [ ] **Step 8: Commit**

Commit: `feat: generate deterministic HIP v4 XML`

### Task 3: Collect truthful macOS posture

**Files:**
- Create: `src/hyu_vpn/macos_posture.py`
- Create: `tests/fixtures/commands/*.txt`
- Create: `tests/test_macos_posture.py`

**Interfaces:**
- Produces: `CommandResult(argv, returncode, stdout, stderr)`
- Produces: `CommandRunner.run(argv: Sequence[str], timeout: float) -> CommandResult`
- Produces: `MacPostureCollector.collect() -> MacPosture`

- [ ] **Step 1: Add failing OS and XProtect collector tests with fixture outputs/plists**

- [ ] **Step 2: Confirm RED**

Run: `python3 -m unittest -v tests.test_macos_posture.MacPostureCollectorTests.test_collects_os_and_xprotect`

- [ ] **Step 3: Implement `CommandRunner`, plist reads, and OS/XProtect collection**

- [ ] **Step 4: Add failing Gatekeeper, FileVault, application firewall, and PF tests**

Each feature requires enabled, disabled, command-missing, permission-denied, malformed-output, and timeout cases.

- [ ] **Step 5: Implement the four collectors with `yes`/`no`/`unknown` results**

- [ ] **Step 6: Add failing physical-interface and host-ID tests**

Exclude loopback and tunnel interfaces, ignore invalid MACs, prefer the stable primary hardware MAC, and make missing identity explicit.

- [ ] **Step 7: Implement interface parsing without shell commands**

- [ ] **Step 8: Add failing software-update parsing and timeout tests**

Cover no updates, multiple updates, restart-required text, localized/malformed output, timeout, and cache corruption.

- [ ] **Step 9: Implement bounded update discovery and an atomic mode-0600 six-hour cache**

- [ ] **Step 10: Run all posture tests and commit**

Run: `python3 -m unittest -v tests.test_macos_posture`

Commit: `feat: collect truthful macOS HIP posture`

### Task 4: Expose a safe csd-wrapper CLI

**Files:**
- Create: `src/hyu_vpn/hip_cli.py`
- Create: `bin/gp-hip-report`
- Create: `tests/test_hip_cli.py`
- Create: `tests/test_security_privacy.py`

**Interfaces:**
- Consumes: `HipInvocation`, `CookieIdentity`, `MacPostureCollector`, `build_hip_xml`
- Produces: `main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int`

- [ ] **Step 1: Add a failing subprocess test requiring XML-only stdout**

Use synthetic arguments and an injected fixture posture. Assert stderr contains no cookie or identifiers.

- [ ] **Step 2: Confirm RED**

Run: `python3 -m unittest -v tests.test_hip_cli`

- [ ] **Step 3: Implement the CLI and executable entry point**

Write exactly one XML document to `sys.stdout.buffer`; send only redacted error classes to stderr.

- [ ] **Step 4: Add canary-based privacy tests**

Inject distinct password, seed, OTP, cookie, user, host-ID, and MAC canaries. Capture stdout/stderr and diagnostic logger output. Assert secrets appear only where the HIP protocol strictly requires them in stdout, never in stderr or log files.

- [ ] **Step 5: Add missing-argument, collector-failure, broken-pipe, and non-UTF-8 environment tests**

- [ ] **Step 6: Run security and CLI tests and commit**

Run: `python3 -m unittest -v tests.test_hip_cli tests.test_security_privacy`

Commit: `feat: add secure OpenConnect HIP wrapper`

### Task 5: Harden dual-TOTP authentication and process ownership

**Files:**
- Create: `src/hyu_vpn/otp.py`
- Create: `src/hyu_vpn/connector.py`
- Create: `bin/hyu-vpn-connect`
- Create: `tests/helpers/fake_openconnect.py`
- Create: `tests/helpers/fake_oathtool.py`
- Create: `tests/test_connector.py`

**Interfaces:**
- Produces: `TotpProvider.current() -> str`
- Produces: `PromptSession.run() -> int`
- Consumes: HIP wrapper path and existing Keychain service names

- [ ] **Step 1: Add a failing test for password plus two distinct challenge responses**

The fake child splits prompt text across pty reads. The second challenge occurs in the same clock window and must receive a different OTP only after the bounded wait.

- [ ] **Step 2: Confirm RED**

Run: `python3 -m unittest -v tests.test_connector.ConnectorTests.test_uses_distinct_totp_for_portal_and_gateway`

- [ ] **Step 3: Implement keychain and oathtool boundaries plus the prompt state machine**

- [ ] **Step 4: Add failing tests for TOTP failure, duplicate prompts, EOF, child error, and partial prompt chunks**

- [ ] **Step 5: Implement the minimum error paths without logging secret material**

- [ ] **Step 6: Add failing real-subprocess SIGINT/SIGTERM forwarding tests**

The fake child records its received signal in a temporary marker and exits normally. Assert no child remains.

- [ ] **Step 7: Implement dedicated process-group ownership and bounded graceful shutdown**

- [ ] **Step 8: Run connector and privacy tests and commit**

Run: `python3 -m unittest -v tests.test_connector tests.test_security_privacy`

Commit: `feat: harden dual OTP OpenConnect connector`

### Task 6: Add reconnect supervision and launchd configuration

**Files:**
- Create: `src/hyu_vpn/supervisor.py`
- Create: `bin/hyu-vpn-service`
- Create: `launchd/local.hyu-openconnect.plist`
- Create: `tests/test_supervisor.py`
- Create: `tests/test_launchd_config.py`

**Interfaces:**
- Produces: `ReconnectPolicy.next_delay(consecutive_failures: int) -> int`
- Produces: `Supervisor.run() -> int`

- [ ] **Step 1: Add failing backoff and reset tests**

Expected sequence is 10, 20, 40, 80, then 120 seconds for subsequent failures; a session that remains established for at least five minutes resets the counter.

- [ ] **Step 2: Implement the reconnect policy**

- [ ] **Step 3: Add failing tests that suppress startup while native GlobalProtect owns the HYU routes**

- [ ] **Step 4: Implement conflict detection using process and route probes without invoking native binaries**

- [ ] **Step 5: Add failing SIGTERM and no-spin tests for the supervisor**

- [ ] **Step 6: Implement graceful child stop and single-instance locking**

- [ ] **Step 7: Add failing plist tests**

Assert absolute paths, `RunAtLoad`, `KeepAlive`, `ThrottleInterval`, safe log paths, and absence of embedded secrets.

- [ ] **Step 8: Add the plist and run tests**

Run: `python3 -m unittest -v tests.test_supervisor tests.test_launchd_config`

- [ ] **Step 9: Commit**

Commit: `feat: supervise and launch HYU OpenConnect`

### Task 7: Offline integration and adversarial verification

**Files:**
- Create: `tests/test_offline_integration.py`
- Create: `README.md`
- Create: `docs/reverse-engineering.md`

**Interfaces:**
- Consumes all runtime entry points
- Produces documented install, rollback, diagnostic, and privacy procedures

- [ ] **Step 1: Add a failing end-to-end fake OpenConnect test**

Drive password, portal OTP, gateway OTP, HIP wrapper invocation, simulated session establishment, SIGTERM, and teardown through real subprocesses without network access.

- [ ] **Step 2: Implement only the integration glue required for the test**

- [ ] **Step 3: Add adversarial cases**

Cover malformed cookie, hostile XML characters, command timeouts, missing binaries, rapid child crashes, concurrent service start, broken cache, and signal during an OTP wait.

- [ ] **Step 4: Run the entire offline suite**

Run: `python3 -m unittest discover -s tests -v`

- [ ] **Step 5: Run static and syntax checks**

Run: `python3 -m compileall -q src bin tests`

Run: `python3 -m unittest discover -s tests -v`

Run: `plutil -lint launchd/local.hyu-openconnect.plist`

Run: `git diff --check`

- [ ] **Step 6: Inspect generated live posture XML offline**

Use synthetic cookie, MD5, and documentation client IP. Parse the result and compare its normalized schema with the synthetic native fixture. Do not save or print raw identifiers.

- [ ] **Step 7: Write the reverse-engineering evidence and operational README**

- [ ] **Step 8: Commit**

Commit: `test: verify offline HIP automation`

### Task 8: Controlled live cutover and rollback proof

**Files:**
- Create: `tests/live_acceptance.sh`
- Create: `docs/live-test-report.md`

**Interfaces:**
- Produces: an opt-in, state-snapshotting acceptance runner

- [ ] **Step 1: Add a dry-run test for the acceptance script**

Assert that the default mode only reports preconditions and never changes VPN state.

- [ ] **Step 2: Implement state snapshot and cleanup traps**

Capture relevant processes, routes, resolvers, loaded launch agents, and native connection state. Never capture credentials or cookies.

- [ ] **Step 3: Re-run the full offline suite and review the cleanup path**

Run: `python3 -m unittest discover -s tests -v && tests/live_acceptance.sh --dry-run`

- [ ] **Step 4: Perform one foreground live attempt**

Only after offline success: stop the native connection gracefully, run the new connector in the foreground, and require `HIP report submitted successfully` plus a working protected endpoint.

- [ ] **Step 5: Prove graceful teardown**

Stop the connector, verify no OpenConnect PID remains, verify pushed routes are gone, and verify DNS matches the snapshot.

- [ ] **Step 6: Record evidence and either enable or roll back**

On success, record sanitized evidence and leave the new LaunchAgent disabled pending explicit operational cutover. On failure, record the discriminating failure, restore native connectivity, and return to root-cause analysis without stacking speculative fixes.

- [ ] **Step 7: Commit the sanitized test report**

Commit: `docs: record controlled HIP cutover result`
