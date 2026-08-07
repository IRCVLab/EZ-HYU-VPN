# HYU OpenConnect HIP Automation

This repository contains a Python-standard-library OpenConnect setup for the HYU GlobalProtect gateway. It handles password plus two TOTP challenges, generates a truthful macOS HIP v4 report, and supervises reconnects without invoking native GlobalProtect components.

## Install after merge

Install after merge, not from a partially reviewed worktree. Keep the native GlobalProtect app available as a rollback oracle until one controlled foreground OpenConnect connect/use/disconnect cycle has passed. GlobalProtect is not uninstalled by this project.

## Prerequisites

- macOS with Python 3 and the checked-out repository.
- OpenConnect 9.21 or compatible at `/opt/homebrew/bin/openconnect`.
- `oathtool` at `/opt/homebrew/bin/oathtool`.
- vpnc-script at `/opt/homebrew/etc/vpnc/vpnc-script`.
- Fixed credential service names stored only inside the local AES-GCM encrypted credential document:
  - `gp-vpn-username`
  - `gp-vpn-password`
  - `gp-vpn-totp`

Do not place credential values in shell history, launchd plists, logs, or files in this repository.

## Foreground use

Run foreground mode first:

```sh
./bin/hyu-vpn-connect
```

Expected offline-safe behavior before live use:

```sh
python3 -m unittest tests.test_launchd_config tests.test_supervisor tests.test_offline_safety_static tests.test_live_acceptance_gate -v
python3 -m compileall -q src bin tests
plutil -lint launchd/local.hyu-openconnect.plist
git diff --check
```

During a real foreground attempt, confirm OpenConnect reports successful HIP submission, protected routes work, DNS remains usable, and disconnect restores routes/DNS to the pre-test state.

## Service disabled by default

Keep the service disabled by default; install or enable it only after live acceptance and offline checks have passed.

The tracked legacy plist at `launchd/local.hyu-openconnect.plist` is a quarantine-only inert template: it is disabled, does not run the VPN service, and must not be copied into `~/Library/LaunchAgents` as an install target. A reviewed release/install path must generate or install an explicit service plist only after offline checks and live acceptance have passed.

Live acceptance is mutation-gated. Dry-run/read-only checks remain the default; a real mutation run requires all of these in the same invocation before any live reads or mutations happen:

```sh
nonce="hyu-live-mutation-$(date +%s)"
HYU_VPN_ALLOW_LIVE_MUTATION="$nonce" tests/live_acceptance.sh --execute --acknowledge-live-mutation "$nonce"
```

Use the installed service label's documented bootout command from the reviewed installer/release artifact to stop the service. Do not bootstrap `launchd/local.hyu-openconnect.plist`.

## Stop and rollback

Stop and rollback procedure:

1. Stop foreground OpenConnect with `Ctrl-C`, or unload the LaunchAgent with `launchctl bootout`.
2. Confirm no `openconnect` child remains.
3. Confirm pushed routes and DNS have returned to the pre-test snapshot.
4. If access is not restored, keep the service unloaded and reconnect with the native GlobalProtect client.
5. Do not uninstall GlobalProtect unless a separate destructive action is explicitly approved.

## Recovery

If startup fails, check that the installed native credential reader and the bundled OpenConnect, oathtool, and vpnc-script runtime files exist and are executable. Re-run the offline suite before another live attempt. The supervisor lock lives under `~/Library/Application Support/hyu-openconnect/` and prevents concurrent service instances.

## Logs and privacy

Logs and privacy rules are strict: no passwords, no TOTP seeds, no OTP values, no authentication cookies, no raw HIP XML, no host identifiers, and no MAC addresses in diagnostics. HIP user, host, host-id, and MAC values may appear only inside the HIP XML sent to OpenConnect where the protocol requires them. Wrapper stderr is redacted by error class.
