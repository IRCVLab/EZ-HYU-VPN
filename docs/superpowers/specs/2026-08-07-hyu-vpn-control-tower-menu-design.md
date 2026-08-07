# HYU VPN Control-Tower Menu Design

## Status

- Approved in conversation: 2026-08-07
- Target: internal-lab macOS menu-bar application
- Minimum platform: macOS 14
- Distribution: ad-hoc signed internal DMG

This document supersedes the menu presentation, expiry-notification, auto-connect default, credential-management, login-item, and quit-behavior sections of `2026-08-04-hyu-vpn-menubar-design.md`. The earlier privileged-helper and network-safety design remains authoritative.

## Goal

Make the HYU VPN menu-bar app the single control tower for the VPN. While the app is running, it owns the user's intent to keep the VPN connected. The interface communicates connection state and recovery actions without exposing session-expiry mechanics.

## Product model

- Launching HYU VPN enables automatic reconnect and requests a connection.
- Normal session expiration, transient network loss, and clean OpenConnect exit are recovered automatically by the existing supervisor.
- `Disconnect` safely tears down the tunnel, restores owned network state, and disables automatic reconnect while leaving the menu app open.
- `Connect` after an explicit disconnect enables automatic reconnect again.
- `Reconnect` performs the existing verified disconnect-then-connect sequence.
- `Quit HYU VPN` is a controlled shutdown: it disables automatic reconnect, safely disconnects, and terminates the menu app only after the control command succeeds.
- If controlled shutdown fails, the app remains open and presents a normalized error instead of silently leaving a tunnel or damaged network state behind.
- Safety-critical `repair-required` or network-script failures remain fail-closed. “Always connected” never permits an unsafe reconnect loop.

## Menu structure

The menu contains only these rows:

1. Disabled status row: `HYU VPN: <state>`
2. Dynamic primary action: `Connect` when not connected, `Reconnect` when connected
3. `Disconnect`
4. Separator
5. `Reset Login Information…`
6. Checked `Launch at Login` option
7. `Diagnostics…`
8. Separator
9. `Quit HYU VPN`

The following legacy UI is removed:

- remaining-time text in the menu bar;
- absolute expiration and countdown rows;
- connected-duration row;
- expiry notifications and their preference;
- user-facing automatic-reconnect toggle; and
- separate simultaneous `Connect` and `Reconnect` rows.

Automatic reconnect remains an internal status field and backend safety control. It is implicit while the app is active except after the user explicitly chooses `Disconnect`.

## State presentation

The menu-bar item is icon-only and uses static template SF Symbols so it follows light/dark appearance and reduced-motion expectations.

| Backend state | Symbol | Status copy | Primary action |
| --- | --- | --- | --- |
| `connected` | `checkmark.shield.fill` | `HYU VPN: Connected` | `Reconnect` |
| `connecting` | `arrow.triangle.2.circlepath` | `HYU VPN: Connecting…` | disabled `Connect` |
| `disconnecting` | `shield.slash` | `HYU VPN: Disconnecting…` | disabled `Connect` |
| `disabled` | `shield.slash` | `HYU VPN: Disconnected` | `Connect` |
| `waiting-for-network` | `wifi.exclamationmark` | `HYU VPN: Waiting for Network` | disabled `Connect` |
| `backoff` | `clock.arrow.circlepath` | `HYU VPN: Reconnecting…` | `Reconnect Now` |
| `error` | `exclamationmark.shield.fill` | `HYU VPN: Needs Attention` | `Reconnect` |
| unavailable | `exclamationmark.shield.fill` | `HYU VPN: Status Unavailable` | disabled `Connect` |

The status-item accessibility description is the complete state phrase, for example `HYU VPN connected`. State is never communicated by icon alone because the first menu row repeats it in text.

## Launch behavior and automatic reconnect

On app launch, a startup coordinator invokes the existing fixed `hyu-vpn-control connect` command. It tolerates the service LaunchAgent starting slightly later by retrying only normalized control-unavailable failures once per second for at most 30 seconds. It stops after the first success or any non-transient failure. It never invokes a shell, sudo, or arbitrary executable.

The installer changes the initial auto-reconnect preference from false to true before starting the service and app. This makes a fresh installation conform to the same model without depending on LaunchAgent ordering.

An explicit `Disconnect` persists auto-reconnect false until `Connect`, `Reconnect`, or a later app launch. The app does not continuously override an explicit disconnect during the same process lifetime.

## Controlled quit

All normal app termination paths use the same termination coordinator rather than calling `NSApp.terminate` directly:

1. mark the UI as quitting and prevent duplicate termination requests;
2. invoke the fixed `disconnect` control command;
3. wait up to 15 seconds for its result;
4. on success, reply to AppKit that termination may continue;
5. on failure, cancel termination, restore the menu, and show only a normalized failure message.

Logout or system shutdown remains covered by the backend's existing signal teardown, but interactive `Quit HYU VPN` must use the verified control path.

## Native credential reset

`Reset Login Information…` opens an AppKit window or sheet. It never opens Terminal and never runs the installer.

Fields:

- HYU ID: one ordinary text field, prefilled from the current Keychain username when available;
- password: secure field;
- password confirmation: secure field;
- TOTP setup secret: secure field;
- TOTP setup secret confirmation: secure field.

Validation:

- ID is required, bounded to 128 characters, and rejects control characters.
- Password is required, limited to 1–1024 UTF-8 bytes, rejects NUL/newline, and must exactly match its confirmation.
- Both TOTP fields may be blank to retain the existing seed.
- If either TOTP field is nonempty, both are required. Each value is normalized by removing ASCII spaces, tabs, CR/LF, and hyphens, then uppercasing it. The normalized values must match, contain 16–256 characters from `A-Z`, `2-7`, with optional trailing `=`, and must not be a six-digit OTP code.
- Validation errors stay inside the native window and never include the submitted secret.

Update sequence:

1. validate all fields before changing state;
2. run the verified `disconnect` command;
3. update `gp-vpn-username`, `gp-vpn-password`, and optionally `gp-vpn-totp` through Security.framework;
4. keep old Keychain values in memory only long enough to roll back earlier updates if a later update fails;
5. clear the user-owned TOTP counter guard only after a new seed is committed;
6. zero or release transient secret buffers as soon as practical;
7. invoke `connect` after the complete credential transaction succeeds;
8. on failure, remain disconnected and show a normalized native error.

No credential value is passed through argv, environment variables, logs, status JSON, diagnostics, notifications, or persistent temporary files.

## Launch at Login

The menu exposes a checked `Launch at Login` row backed by `SMAppService.mainApp`, available on the supported macOS 14 floor.

- `.enabled`: checked.
- `.notRegistered`: unchecked.
- `.requiresApproval`: unchecked with `Approval Required` copy; selecting it opens System Settings Login Items.
- `.notFound` or registration error: unchecked and accompanied by a normalized diagnostic.
- Enabling calls `register()`; disabling calls `unregister()` and does not terminate the currently running app.

The first launch registers the app by default unless the user previously made an explicit choice to disable it. That choice is recorded as a non-secret app preference.

The installer migrates away from the existing `com.hyu.vpn.menubar` user LaunchAgent so the app is never owned by two login mechanisms. The service LaunchAgent remains separate because it owns the backend control socket and safe tunnel lifecycle. Upgrade code boots out and removes only the exact legacy menu label/plist and preserves transactional rollback evidence.

Because the internal package is ad-hoc signed, package validation must explicitly exercise `SMAppService.mainApp` on the target Mac. Invalid-signature or approval-required results are surfaced; the app must not silently create a second LaunchAgent fallback.

## Diagnostics

`Diagnostics…` opens a small native read-only panel containing only the existing sanitized fields:

- connection state;
- tunnel interface when present;
- normalized backend error code;
- normalized last control result; and
- backend build version when present.

It never displays raw OpenConnect output, credentials, OTP material, cookies, HIP XML, host identifiers, MAC addresses, gateway addresses, or raw network configuration.

## Architecture boundaries

- `HYUVPNMenuCore` owns pure presentation models, state/action enablement, credential validation, login-item presentation, and coordinators expressed through injectable protocols.
- `HYUVPNMenuApp` owns AppKit objects, Security.framework Keychain access, ServiceManagement integration, alerts/sheets, and application termination replies.
- The Python supervisor remains the source of truth for safe VPN lifecycle and automatic reconnect.
- The privileged helper and network wrapper are unchanged by this UX feature.

## Error handling

- Every external operation is bounded and asynchronous from the main thread.
- Duplicate Connect, Reconnect, Disconnect, credential-save, and Quit actions are suppressed while an operation is in flight.
- Control, Keychain, and login-item failures are converted to stable non-secret codes before entering menu state or diagnostics.
- A credential update never reconnects after a partial or failed Keychain transaction.
- Quit never reports success until the backend confirms the disconnect command.
- No UI failure permits direct route, DNS, process, or SystemConfiguration mutation.

## Verification

### Unit and harness coverage

- icon and copy matrix for every backend state;
- icon-only menu-bar presentation with no remaining-time fields;
- one dynamic Connect/Reconnect row and correct enablement;
- explicit Disconnect persistence semantics;
- bounded startup auto-connect retry and no retry after explicit disconnect in the same run;
- controlled Quit success, failure, duplicate request, and timeout paths;
- credential confirmation mismatch, optional TOTP retention, Base32 validation, successful transaction, rollback, and secret-redaction cases;
- launch-at-login enabled, disabled, approval-required, not-found, registration failure, and unregister failure states;
- migration removes only the exact legacy menu LaunchAgent and never touches the backend service LaunchAgent;
- installer writes initial auto-reconnect true;
- no expiry notification scheduling or legacy countdown menu rows remain.

### Release verification

- Swift package tests and visible menu harness;
- Python installer/supervisor/packaging tests;
- release build with warnings as errors;
- app deep signature and DMG manifest validation;
- target-Mac `SMAppService.mainApp` enable/disable/approval behavior;
- controlled app launch → connect → reconnect → disconnect cycle;
- controlled app launch → connect → Quit cycle proving helper stopped, OpenConnect absent, DNS/route restoration, and app termination;
- relaunch proving automatic connection resumes;
- public internet and protected Hanyang traffic checks before, during, and after the live cycle.

## Acceptance criteria

- The menu bar shows no time or duration text.
- The connected icon is `checkmark.shield.fill` and every state has explicit menu text.
- Starting the app requests and maintains a VPN connection by default.
- Session expiration is recovered without a user-facing expiry workflow.
- Disconnect pauses the VPN until Connect, Reconnect, or app relaunch.
- Quit safely disconnects before the app exits and refuses to exit on a teardown failure.
- Login information is reset entirely through native GUI with password and TOTP confirmation.
- Launch at Login is controllable from the menu and uses one login-item mechanism only.
- No secret enters argv, environment variables, logs, status, diagnostics, or persistent temporary files.
- Network safety invariants and the existing privileged boundary remain unchanged.
