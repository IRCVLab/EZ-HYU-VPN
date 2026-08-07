# HYU VPN Native GUI Installer Design

## Goal

Distribute the internal-lab HYU VPN release as a DMG that never opens Terminal. A user launches `Install HYU VPN.app`, completes native credential fields when needed, accepts one standard macOS administrator authorization dialog, and then uses the menu-bar control tower without further administrator-password prompts.

## User Experience

1. The DMG presents `Install HYU VPN.app` as the only installation entry point.
2. Existing HYU Keychain credentials are retained. Missing credentials are collected in AppKit:
   - HYU ID once.
   - HYU password twice.
   - TOTP setup secret twice.
3. The installer validates the two secret confirmations before any privileged mutation.
4. macOS displays one graphical administrator authorization prompt.
5. The installer shows deterministic progress and either a success screen or a sanitized failure with a diagnostics location.
6. On success, the installed menu-bar app starts and automatic VPN connection is enabled by default.
7. No `.command` launcher, Terminal window, raw shell output, password, TOTP secret, or current OTP appears in the release UX or logs.

## Architecture

### Native installer app

Add a dedicated AppKit executable and bundle, separate from `HYU VPN.app`. It owns presentation, validation, Keychain existence checks, credential confirmation, manifest verification, staging, progress, and sanitized result mapping.

### Privileged boundary

Keep `installer/root-admin.sh` as the single transactional mutation owner. The GUI invokes it once through macOS graphical administrator authorization (`do shell script ... with administrator privileges`). The privileged command contains only validated paths, manifest digests, a fresh mutation nonce, and the validated console identity. Credentials never cross this boundary or appear in argv/environment.

All dynamically inserted shell arguments use a single POSIX-quoting implementation. The root phase continues to revalidate the package/stage manifest and rolls back on failure.

### Credential transaction

The GUI writes only validated credentials through Security.framework. Existing complete credentials are not overwritten during upgrade. Credentials created for a failed installation are removed; pre-existing entries are never removed. Password and TOTP fields are held only in memory until validation and are cleared when the flow completes or is cancelled.

### Release layout

The DMG's visible installation surface contains the native installer app, not `Install HYU VPN.command` or `Uninstall HYU VPN.command`. Installer resources contain or locate the immutable verified payload needed by the root phase. Release auditing rejects visible or packaged Terminal launchers and verifies the native installer signature, architecture, manifest binding, and absence of Homebrew load paths.

## Legacy Migration

An upgrade may encounter an old `repair-required` session after the physical network has already returned to a clean state. The helper may retire that ledger without route/DNS mutation only when all of the following are proved:

- No recorded process remains live.
- No recorded protected route or tunnel interface remains.
- The recorded service and physical interface still match.
- The recorded tunnel DNS surface is absent.
- The persistent Setup DNS surface matches the recorded baseline.

Default-route equality alone must not block this deletion-only retirement. Any owned artifact, route collision, mixed DNS state, service/interface drift, or stable boot-identity mismatch remains fail-closed.

## Error Handling

- User cancellation makes no privileged mutation.
- Authentication cancellation returns to the installer UI without opening Terminal.
- Root failure preserves the existing installed version and retained repair evidence.
- Logs contain operation codes and bounded sanitized stderr only.
- No recovery path edits or deletes raw SystemConfiguration preference files.

## Verification

- Red/green tests for artifact-free retained-state retirement with the default route equal to the recorded route, plus existing adversarial drift cases.
- Native installer model/harness tests for confirmation, existing credentials, cancellation, argument quoting, one authorization call, rollback, and redaction.
- Packaging tests proving no `.command` installer and correct native app/payload binding.
- Full Swift, Python, syntax, plist, codesign, architecture, manifest, DMG checksum, and package-audit gates.
- Live external-network validation: upgrade, connect, HIP success, reconnect, disconnect, quit cleanup, relaunch auto-connect, public Internet preservation, and bounded backoff behavior.

## Acceptance Criteria

The work is complete only after the new DMG installs through GUI with one administrator authorization, no Terminal appears, the menu-bar app owns the full VPN lifecycle, and the live external-network matrix passes without leaving route or DNS residue.
