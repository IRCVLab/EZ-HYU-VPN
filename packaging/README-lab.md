# HYU VPN internal lab installer

For named internal lab users only. The DMG is a native GUI distribution; normal users do not run Terminal commands.

## Install from the DMG

1. Open the DMG.
2. Double-click **Install HYU VPN.app**.
3. Keep the installer progress window open while it verifies the package and prepares the payload.
4. If credentials are missing, enter them in the GUI:
   - HYU ID once.
   - HYU VPN password twice.
   - TOTP authenticator setup secret twice; do not enter the current 6-digit OTP code.
5. Approve the single macOS administrator authorization dialog.

Existing HYU VPN Keychain credentials are retained. Missing credentials are collected in memory before elevation and written after the root install succeeds using the Security.framework Keychain path with ACL entries for the installer, `/usr/bin/security`, and the installed menu executable.

## What the installer does

The native app uses the fixed system Python prerequisite `/usr/bin/python3` to verify `manifest.json`, stages the immutable payload, and then runs the existing transactional `installer/root-admin.sh` root phase once through the macOS administrator authorization UI. The shell scripts under `installer/` are implementation details for the app and are not user-facing launchers.

After the root transaction succeeds, the user phase writes auto-reconnect enabled, bootstraps/kickstarts the per-user service, stops any older menu process with bounded TERM/KILL fallback, opens `/Applications/HYU VPN.app`, and waits for exactly one menu process. Normal connect, reconnect, and disconnect operations use the installed helper/sudoers setup and should not request the Mac administrator password.

## Release evidence

Each release includes:

- `manifest.json` for deterministic payload verification.
- `release-metadata.json` with `installer_ux=native-gui-no-terminal` and `administrator_authorization=macos-ui-once`.
- `FINAL-RUNTIME-BINDING.json` when the source compliance bundle is present; it binds canonical pre-rewrite/pre-sign runtime artifacts to the final ad-hoc-signed payload.
- `THIRD_PARTY_NOTICES.txt` and `SOURCE-OFFER.txt` for bundled runtime components.

## Internal implementation notes

`installer/install.sh`, `installer/uninstall.sh`, and `installer/root-admin.sh` remain packaged for manifest verification, root transaction reuse, recovery, and internal diagnostics. They are not the DMG entry point for lab users.
