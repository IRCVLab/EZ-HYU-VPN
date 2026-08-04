# HYU OpenConnect HIP Automation Design

## Objective

Replace the Palo Alto GlobalProtect native client with a low-resource OpenConnect service that:

- authenticates to `secure.hanyang.ac.kr` with password plus two distinct TOTP challenges;
- generates and submits a truthful macOS HIP report;
- restores actual access to the pushed university routes, not merely tunnel establishment;
- reconnects after interruption or the approximately four-hour authentication expiry;
- shuts down without leaving stale routes or DNS state; and
- never writes passwords, TOTP seeds, OTP values, authentication cookies, host identifiers, or raw HIP XML to logs.

The native GlobalProtect installation may remain available only as a temporary migration oracle and rollback path. The completed runtime must not execute or depend on GlobalProtect, PanGPS, PanGPA, PanGpHip, PanGpHipMp, or their cached report files.

## Evidence and protocol findings

### Authentication

The preserved OpenConnect log proves the portal and gateway each request a separate `Challenge:` after password authentication. Reusing a TOTP from the same 30-second window produces HTTP 512; waiting for the next window allows authentication to proceed. Portal authentication cookies returned by this deployment are empty, so the gateway authentication phase cannot be skipped by replaying a portal cookie.

### HIP flow

The native logs show the following sequence:

1. The portal advertises a 3600-second HIP interval.
2. The native client generates a version-4 HIP report.
3. It computes an MD5 identifier and calls `/ssl-vpn/hipreportcheck.esp` with the identifier and gateway-assigned address.
4. The gateway responds with `hip-report-needed=yes` when it needs the full report.
5. The client submits the XML to `/ssl-vpn/hipreport.esp`.
6. The gateway returns success and the `HIP-Profile` notification value `allow`.

OpenConnect 9.21 implements the same check/submit sequence. Its `--csd-wrapper` executable receives `--cookie`, `--client-ip`, optional `--client-ipv6`, `--md5`, and `--client-os`, plus `APP_VERSION` in the environment. The executable must write XML only to standard output and exit zero. Diagnostics belong on standard error and must be redacted.

OpenConnect honors the portal interval but schedules its recheck 60 seconds early; the observed 3600-second portal setting therefore becomes a 3540-second recheck. Its one-hour default is used only when neither the portal nor `--force-trojan` supplies an interval.

### Native report shape

The accepted native report contains these categories, in order:

1. `host-info`
2. `anti-malware`
3. `disk-backup`
4. `disk-encryption`
5. `firewall`
6. `patch-management`
7. `data-loss-prevention`

Reverse engineering parsed 38 native reports and found the same category order in every one. The accepted macOS category schema is not a simplified `<category><product>` tree: categories are `<categories><entry name="...">`, products are represented as `<list><entry><ProductInfo><Prod .../>`, FileVault state is under `drives/entry/enc-state`, firewall state is under `is-enabled`, and missing patches are sibling `missing-patches/entry` records. A path-signature comparison proved that the first simplified prototype omitted 63 native paths and added 45 non-native paths despite its tests passing; the sanitized fixture must therefore preserve the real tag/attribute shape without alias normalization.

The native HIP generator log contains `generate-time` plus the category subtree, while PanGPS logs the check header containing `md5-sum`, `user-name`, `domain`, `host-name`, `host-id`, `ip-address`, and `ipv6-address`. OpenConnect submits wrapper stdout verbatim and its official wrapper includes those header fields plus `generate-time` and `hip-report-version`. The replacement wrapper therefore combines the OpenConnect/PanGPS header contract with the native macOS category structure.

Observed truthful values include the current macOS release, XProtect version and definition date, Gatekeeper state, FileVault state, application firewall state, Packet Filter state, physical network interfaces, stable host identifier, and available Apple software updates. The server accepted a report even though the application firewall and Packet Filter were disabled and recommended updates were available. The implementation must report those states truthfully rather than fabricating a compliant posture.

## Architecture

### Project layout

```text
src/hyu_vpn/
  hip_contract.py      OpenConnect arguments, cookie parsing, data models
  hip_xml.py           deterministic, escaped HIP v4 XML generation
  macos_posture.py     injectable macOS posture collectors
  hip_cli.py           stdout-only csd-wrapper command
  otp.py               Keychain reads and TOTP generation boundary
  connector.py         pty prompt state machine and signal forwarding
  supervisor.py        reconnect loop, backoff, and graceful stop policy
bin/
  gp-hip-report        executable csd-wrapper entry point
  hyu-vpn-connect      foreground connector entry point
  hyu-vpn-service      launchd supervisor entry point
launchd/
  local.hyu-openconnect.plist
tests/
  fixtures/            synthetic, sanitized protocol and command fixtures
  test_*.py            stdlib unittest suite
```

Python's standard library is sufficient. No new runtime dependency is permitted. Existing `/opt/homebrew/bin/openconnect` and `/opt/homebrew/bin/oathtool` remain external executables.

### HIP contract boundary

`hip_cli.py` accepts the exact OpenConnect wrapper arguments. It parses the URL-encoded cookie with `urllib.parse.parse_qs`, validates the required dynamic values, collects posture, and writes one well-formed UTF-8 XML document to stdout. It must not echo arguments or the report to stderr.

The passed `--md5` value is copied unchanged into `<md5-sum>` so the check and submission identifiers match. The allocated client address is copied unchanged into the report header. XML generation uses `xml.etree.ElementTree`, never shell interpolation.

### macOS posture collection

All command execution goes through an injectable `CommandRunner` with explicit argv arrays, fixed timeouts, captured output, and no shell. Collectors return a three-way state where appropriate: `yes`, `no`, or `unknown`. A command failure must never become a fabricated `yes`.

Sources:

- OS: `/System/Library/CoreServices/SystemVersion.plist` (or `/usr/bin/sw_vers` as a bounded fallback)
- hardware interfaces: `/usr/sbin/networksetup` plus `/sbin/ifconfig`
- XProtect: Apple XProtect bundle Info.plist and metadata modification time
- Gatekeeper: `/usr/sbin/spctl --status`
- FileVault: `/usr/bin/fdesetup status`
- application firewall: `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`
- Packet Filter: `/sbin/pfctl -s info`
- software updates: `/usr/sbin/softwareupdate --list`, with a bounded timeout

The HIP wrapper runs during connection and every server-requested recheck. Software update discovery can take tens of seconds, so its parsed result is cached for at most six hours in a mode-0600 JSON file. Cache corruption or expiry causes a fresh bounded probe; probe failure produces an explicitly unknown/empty result and a redacted stderr warning.

### Authentication and process supervision

The existing pty technique is retained because pipe-buffered OpenConnect output previously deadlocked prompt handling. The connector:

- sends the password once for `--passwd-on-stdin`;
- responds to portal and gateway `Challenge:` prompts;
- prevents reuse of the same TOTP value by waiting for the next 30-second window;
- launches OpenConnect with `--protocol=gp`, the existing gateway group, `--csd-wrapper`, and the existing vpnc-script;
- starts the child in a dedicated process group;
- forwards SIGINT and SIGTERM to that group;
- waits for normal vpnc-script teardown before escalating; and
- never uses SIGKILL until a bounded graceful-stop interval has expired and cleanup diagnostics have been captured.

The supervisor restarts failed sessions with capped backoff. It will not retry while a native GlobalProtect tunnel is detected, preventing conflicting routes during migration.

The retry sequence is exponential and capped: 10, 20, 40, 80, then 120 seconds for subsequent failures. A session that remains established for at least five minutes resets the failure counter.

## Security and privacy

- Credentials remain in macOS Keychain under the existing services.
- Passwords, TOTP seeds, generated OTPs, cookies, host IDs, MAC addresses, and complete HIP XML are forbidden from logs and exception messages.
- The OpenConnect API necessarily passes the encoded authentication cookie to the HIP wrapper as an argv value. The wrapper must consume it immediately, never copy it to another process, and never persist it.
- Any cache file is non-secret update metadata only and must be created with mode 0600 using atomic replacement.
- Synthetic identifiers are used in all test fixtures. Native logs are never copied into the repository.
- The generator reports actual posture. It does not claim enabled encryption, firewall, anti-malware, or patch state when probes fail.

## Failure handling

| Failure | Required behavior |
|---|---|
| Missing wrapper argument | Exit nonzero; safe stderr message naming only the missing field |
| Posture command absent or malformed | Emit an unknown/empty truthful field where schema permits; do not fabricate success |
| HIP XML generation failure | Exit nonzero before OpenConnect submits a partial document |
| TOTP generation failure | Stop the authentication attempt without logging the seed or OTP |
| Repeated challenge in one window | Wait until the next TOTP window, then answer once |
| OpenConnect child termination | Drain output, wait for teardown, then back off |
| SIGTERM/SIGINT | Forward to process group and wait for route/DNS teardown |
| Stale routes or DNS after test | Stop automatic retries and restore the pre-test snapshot before rollback |
| Gateway accepts XML but traffic remains blocked | Treat as HIP policy failure; compare only sanitized field structure against the accepted native report |

## Test strategy

Development follows red-green-refactor using `unittest` only.

Offline coverage includes:

- OpenConnect argument and cookie parsing;
- required-field validation;
- XML well-formedness, escaping, deterministic category order, and golden normalized schema;
- each posture collector for enabled, disabled, unavailable, malformed, and timeout cases;
- proof that unknown states never become fabricated compliant states;
- a native path-signature regression proving that simplified `category/product` aliases cannot pass;
- stdout containing XML only;
- logs containing none of the credential, cookie, OTP, host-ID, or MAC canaries;
- TOTP non-reuse across split pty prompt chunks;
- real subprocess signal propagation using harmless fake children;
- exponential backoff and retry suppression while native GlobalProtect is active.

Live validation is explicitly gated and runs only after all offline tests pass.

## Controlled rollout

1. Build and test the HIP generator offline while the current native tunnel remains untouched.
2. Generate a live local HIP report with synthetic wrapper arguments and compare only its normalized structure to the accepted native schema.
3. Snapshot active VPN processes, routes, DNS configuration, and the native connection state.
4. Stop the native tunnel gracefully for one foreground OpenConnect attempt.
5. Require all of the following before calling the attempt successful:
   - OpenConnect logs `HIP report submitted successfully`;
   - the expected tunnel address and routes are installed;
   - a protected university endpoint is reachable through the tunnel;
   - DNS remains usable; and
   - no forbidden secret appears in logs.
6. Stop OpenConnect gracefully and verify routes and DNS return to the snapshot state.
7. If any check fails, disable the OpenConnect job, clean up, and restore the native connection.
8. Enable the new LaunchAgent only after a complete connect/use/disconnect cycle succeeds.
9. Removing the native application is a separate destructive action and is outside this implementation until explicitly requested.

## Non-goals

- Bypassing or disabling the university's HIP policy
- Reporting fabricated compliant posture
- Reimplementing the GlobalProtect tunnel protocol instead of using OpenConnect
- Depending on cached files or executables from the native GlobalProtect installation at runtime
- Automatically uninstalling GlobalProtect
