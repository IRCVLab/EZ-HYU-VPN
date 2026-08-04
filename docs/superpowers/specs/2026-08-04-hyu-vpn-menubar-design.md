# HYU VPN Menu Bar App and Safe Privileged Lifecycle Design

## Goal

Ship an internal-lab macOS DMG that provides a native menu bar controller for the already-validated Hanyang OpenConnect/HIP implementation while eliminating recurring route, DNS, and orphaned-root-process failures.

Success requires more than establishing a tunnel. The shipped system must connect, expose the session expiry, disconnect cleanly, restore routes and DNS, survive network changes, and reconnect without allowing native GlobalProtect and OpenConnect to compete.

## Scope and distribution

- Internal lab distribution outside the Mac App Store.
- Ad-hoc signed application and DMG; no Apple notarization in the first release.
- Users accept the one-time Gatekeeper **Open** action.
- Apple silicon and Intel Homebrew prefixes are detected during installation.
- The first release may require Homebrew plus `openconnect` and `oath-toolkit`; it does not bundle or reimplement OpenConnect.
- Removing GlobalProtect is outside scope. The installer disables only conflicting automatic operation and preserves the native client as a manual recovery option.

## Validated foundation

The existing backend has passed a real Hanyang connection with:

- portal password and first OTP;
- gateway password and a distinct second OTP;
- successful truthful HIP submission;
- ESP tunnel establishment;
- protected route and endpoint access;
- session-expiry output from OpenConnect; and
- LaunchAgent-driven reconnection.

The live cycle also reproduced the remaining root defect: the user-owned connector can exit while a root-owned OpenConnect process remains attached to the tunnel. A direct privileged SIGTERM removes it cleanly, after which the LaunchAgent reconnects successfully. The menu app release must replace the current unrestricted sudo/OpenConnect boundary before it is considered safe.

## Architecture

### 1. HYU VPN menu bar application

A small AppKit application owns only presentation and user intent. It never reads passwords, OTP seeds, cookies, raw HIP XML, or raw OpenConnect logs.

It reads a mode-`0600` status document and invokes fixed control entry points:

- enable automatic connection;
- connect now;
- disconnect and remain disabled;
- reconnect;
- open sanitized diagnostics; and
- quit the menu UI without disconnecting the service.

The app uses template SF Symbols so the menu bar follows macOS light/dark appearance:

| State | Symbol | Menu-bar text |
| --- | --- | --- |
| Connected | `shield.lefthalf.filled` | remaining duration, for example `2h 14m` |
| Connecting | `arrow.triangle.2.circlepath` | `Connecting` |
| Backoff | `clock.arrow.circlepath` | retry countdown |
| Disconnected/disabled | `shield.slash` | no duration |
| Error | `exclamationmark.shield` | `Error` |

No colored emoji or permanently animated icon is used. Animation, if any, is limited to a low-frequency symbol transition while connecting.

### 2. User session service

The existing supervisor remains a per-user LaunchAgent but gains an explicit state machine:

`disabled -> waiting-for-network -> connecting -> connected -> disconnecting -> backoff/error`

It must:

- wait for a usable default route and DNS before authentication;
- suppress OpenConnect while the native UI reports a real connected/connecting state;
- avoid treating an OpenConnect-owned `utun` as a native conflict;
- use a cross-process OTP reuse guard so a restarted connector cannot reuse a server-rejected current-window OTP;
- serialize all connect/disconnect/reconnect transitions;
- write sanitized state atomically; and
- call the privileged helper for both start and stop.

The control channel is a foreground pipe contract, not a daemonized or detached process:

1. the user supervisor opens a PTY for progress output and a private stdin pipe;
2. it starts `sudo -n <helper> start <validated-username>`;
3. the root helper remains the parent/monitor of one OpenConnect child and inherits those file descriptors;
4. the supervisor writes only password and OTP responses to the private stdin pipe;
5. OpenConnect prompt/progress output returns through the PTY;
6. the supervisor consumes that stream, updates sanitized status events, and never copies raw output to persistent logs; and
7. disconnect invokes a separate `sudo -n <helper> stop` command and waits for both the root monitor and OpenConnect child to exit.

The username is non-secret but is strictly validated before the helper places it in the fixed OpenConnect argv. Passwords and OTPs never appear in argv, environment variables, helper state, or files. If the user-side pipe/event consumer disappears, the helper initiates a verified SIGTERM teardown rather than leaving a detached tunnel.

### 3. Root-owned lifecycle helper

A root-owned helper is installed under `/Library/PrivilegedHelperTools`. It is the only passwordless sudo command granted to the user.

The helper exposes a fixed, validated command surface:

- `start`: run OpenConnect with the fixed Hanyang portal, GP protocol, auth group, root-owned vpnc script, and root-owned HIP wrapper path;
- `stop`: read the root-owned PID record, verify the process executable and fixed server identity, send SIGTERM, wait for teardown, and remove stale state only after the process exits;
- `status`: return a small non-secret lifecycle state; and
- `repair`: remove only known HYU routes after proving the owned process is gone and a recorded teardown failed.

The helper rejects arbitrary executable paths, scripts, portals, shell fragments, environment overrides, and unvalidated identifiers. It uses absolute command paths and a root-owned configuration generated by the installer.

OpenConnect invokes the HIP collector using `--csd-user` so posture collection runs as the logged-in user rather than root. Runtime Python and wrapper files are copied to a root-owned read-only application-support directory.

The helper is a compiled command-line program rather than a user-editable shell script. `start` creates one random session nonce and a root-owned session record under `/var/run/hyu-vpn/`. The record contains only:

- PID and process-group ID;
- kernel process start/birth time;
- helper session nonce;
- invoking console UID;
- fixed portal identifier;
- launch timestamp;
- resolved OpenConnect executable identity; and
- per-session network ledger path.

`stop` and `repair` reject stale or reused PIDs unless PID, process group, birth time, executable path, portal identity, UID, and nonce all match the live helper-owned session. A root-owned non-blocking lock permits only one session per console UID. The helper never signals a process based solely on a PID file.

### 4. Root-owned network wrapper and change ledger

The fixed vpnc entry point wraps the Homebrew vpnc script and creates a root-owned, per-session change ledger. Before applying network configuration it records a fingerprint of:

- active network service and default-route interface;
- resolver/search-domain state;
- the exact known HYU routes and their prior values; and
- the new tunnel interface identity.

After the vpnc script succeeds, it records only the deltas actually installed for that session: exact destination, gateway, interface, resolver/search-domain values, and service identifier. Teardown calls the upstream script first and then verifies the ledger.

`repair` may remove a route only when its current destination, gateway, interface, and session nonce-derived ledger all match the session-installed value. It may restore resolver state only when the current resolver still matches the value applied by that same session. If the default network, service identifier, or resolver changed independently during the VPN session, the helper refuses to overwrite it, records `repair-required`, and waits for the new network to stabilize. It never restores a pre-reboot snapshot and never edits raw SystemConfiguration preference files.

### 5. Status protocol

The supervisor writes `~/Library/Application Support/HYU VPN/status.json` atomically with mode `0600`.

Fields are bounded and non-secret:

- schema version;
- state;
- automatic reconnect enabled;
- connected timestamp;
- session expiry timestamp;
- last successful HIP timestamp;
- tunnel interface name;
- next retry timestamp;
- normalized error code;
- last state transition timestamp; and
- backend build version.

The file never contains username, password, OTP, TOTP seed, cookie, host ID, MAC address, tunnel address, gateway address, or raw command output.

## Menu behavior

The menu displays:

1. current state;
2. session expiry and live remaining-duration countdown;
3. connected duration;
4. Connect;
5. Disconnect;
6. Reconnect;
7. Automatic Reconnect toggle;
8. optional **Notify 10 minutes before expiry** toggle, off by default;
9. sanitized diagnostics; and
10. Quit Menu App.

Session expiry is parsed from the OpenConnect event stream and stored as an absolute timestamp. If no expiry is available, the app shows `Unknown` rather than inventing a duration.

`Quit Menu App` never changes VPN state. `Disconnect` stops the root process, proves routes and DNS were restored, and leaves automatic reconnection disabled. `Reconnect` performs the same verified stop before starting a fresh OTP window.

## Installer and DMG

The DMG contains:

- `HYU VPN.app`;
- `Install HYU VPN.command`;
- `Uninstall HYU VPN.command`; and
- a short internal-lab README.

Installation is transactional:

1. verify supported macOS and CPU architecture;
2. locate Homebrew and verify/install user-space dependencies;
3. collect username, password, and TOTP seed without echo and store them in the user Keychain;
4. request administrator authentication once;
5. install the immutable privileged helper, backend, configuration, and constrained sudoers rule;
6. validate sudoers with `visudo -c` before activation;
7. install and bootstrap the LaunchAgent;
8. copy the menu app to `/Applications`; and
9. perform a dry-run status check without disconnecting an existing working tunnel.

Resolved dependency paths, CPU architecture, file identities, and versions are written into a root-owned configuration during installation. Apple silicon `/opt/homebrew` and Intel `/usr/local` are supported; the helper validates the recorded executable path, owner, mode, and file identity on every start and refuses moved/replaced dependencies until the installer repairs the configuration.

Privileged files and directories have an explicit trust boundary:

| Path | Owner/mode |
| --- | --- |
| `/Library/PrivilegedHelperTools/com.hyu.vpn.helper` | `root:wheel`, `0755` |
| `/Library/Application Support/HYU VPN/` | `root:wheel`, `0755` |
| executables below the application-support directory | `root:wheel`, `0755` |
| configuration/manifests below it | `root:wheel`, `0644` |
| `/var/run/hyu-vpn/` session state | `root:wheel`, `0700` |
| user application-support directory | console user, `0700` |
| `status.json` and sanitized logs | console user, `0600` |

The installer rejects symlinks or user-writable parent directories for privileged paths and verifies every payload against an embedded SHA-256 manifest before installing it.

If installation fails, rollback runs in reverse phase order: stop and unload the newly bootstrapped LaunchAgent, restore or remove the app copy, restore the prior LaunchAgent and backend, validate and restore the prior sudoers fragment, restore the prior helper/config atomically, and remove only Keychain items created during this failed transaction. A root-owned transaction marker makes rollback idempotent after interruption or reboot. A live helper upgrade first drains the existing session through the old verified stop path; it never replaces an executing helper in place.

The uninstaller first performs a verified disconnect, then unloads the LaunchAgent and removes only files installed by this package. Keychain credential removal is an explicit user choice.

The first internal release remains ad-hoc signed because the lab has no Developer ID certificate. This is an explicit distribution constraint, not equivalent to Apple trust. To reduce tampering risk, releases include a separately published SHA-256 DMG checksum, an embedded payload manifest verified before sudo, ad-hoc signature verification, and a lab-only installation guide. Developer ID signing and notarization become mandatory before distribution expands beyond the named internal lab group.

## Network-change and failure handling

- Sleep, wake, Wi-Fi changes, missing default routes, and DNS unavailability move the service to `waiting-for-network` without rapid retries.
- Route and DNS snapshots are scoped to a single transition and are never reused after reboot or network preference regeneration.
- The service requires stability across repeated probes before connecting.
- A disconnect is successful only when the owned OpenConnect process is gone, known pushed routes are absent, and resolver state is restored.
- A failed teardown blocks a conflicting reconnect and surfaces `repair-required` in the menu.
- Native GlobalProtect and OpenConnect are never deliberately active at the same time.
- Raw network configuration files under `/Library/Preferences/SystemConfiguration` are never deleted or rewritten.

## Security and privacy

- Credentials remain in the login Keychain.
- No secrets are passed on argv or written to logs/status files.
- The menu app does not run as root.
- Passwordless sudo is limited to the installed root-owned helper.
- The helper cannot execute user-selected programs or scripts.
- HIP posture remains truthful; unavailable state is reported as unknown/not-available rather than compliant.
- Diagnostic export is sanitized and opt-in.

## Verification

### Offline

- unit tests for every state transition and expiry parser;
- hostile/malformed status JSON tests;
- cross-process OTP reuse tests;
- root-helper argument rejection and PID identity tests;
- helper pipe/event-channel loss during authentication and connected states;
- stale PID, forced PID reuse, birth-time mismatch, and nonce mismatch tests;
- session-ledger route/DNS ownership and unrelated-network-change refusal tests;
- installer rollback and sudoers validation tests;
- interrupted rollback after LaunchAgent bootstrap;
- Apple silicon and Intel dependency path tests, including moved/replaced binaries;
- app menu-state snapshot tests;
- secret-canary scans of all logs and artifacts;
- universal DMG structure and ad-hoc signature verification; and
- existing HIP schema, collector, connector, supervisor, and privacy suites.

### Controlled live cycle

1. snapshot the post-reboot network baseline;
2. prove current protected traffic;
3. stop through the new privileged helper;
4. prove the root process, pushed routes, and VPN resolver are gone;
5. reconnect through the LaunchAgent;
6. require HIP success, ESP establishment, protected traffic, and general internet/DNS access;
7. verify the menu shows the same expiry as the backend state;
8. exercise reconnect once; and
9. leave one stable service-owned session active.

The live matrix also covers sleep/wake while connected, sleep/wake during teardown, Wi-Fi service changes during a session, and a resolver change from an unrelated network event. These cases must either restore only the owned deltas or stop with `repair-required`; they must never overwrite the newer network configuration.

### Acceptance criteria

- No root OpenConnect process remains after Disconnect.
- General internet and DNS work before, during, and after a controlled VPN cycle.
- Protected traffic works while connected.
- The menu expiry matches the server-provided expiry within one second.
- Automatic reconnect resumes after a simulated network interruption without a spin loop or OTP reuse.
- Native and OpenConnect tunnels never overlap.
- No credential, OTP, cookie, host identifier, MAC address, or raw HIP XML appears in persistent files.
- The DMG installs and uninstalls on a clean lab Mac using one documented administrator-authentication step.

## Rollout

1. Build and validate on the current Mac without changing the active tunnel.
2. Install the helper and migrate the current service during one controlled maintenance window.
3. Complete the live acceptance cycle on the current Mac.
4. Test the DMG on one secondary lab Mac.
5. Publish the internal DMG with checksum and versioned release notes.
