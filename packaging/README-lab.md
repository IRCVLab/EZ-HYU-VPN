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

Missing credentials are collected in memory before elevation and written after the root install succeeds. They are stored as an AES-GCM encrypted document with a random 256-bit local key; the containing directory is mode `0700` and the key, ciphertext, and lock files are mode `0600`. Keychain and its authorization prompts are not used.

## What the installer does

The native app uses the fixed system Python prerequisite `/usr/bin/python3` to verify `manifest.json`, stages the immutable payload, and then runs the transactional `installer/root-admin.sh` root phase once through the macOS administrator authorization UI. No Terminal installer or uninstaller is packaged.

After the root transaction succeeds, the user phase writes auto-reconnect enabled, bootstraps/kickstarts the per-user service, stops any older menu process with bounded TERM/KILL fallback, opens `/Applications/HYU VPN.app`, and waits for exactly one menu process. Normal connect, reconnect, and disconnect operations use the installed helper/sudoers setup and should not request the Mac administrator password.

The menu shows the current six-digit OTP with its remaining lifetime. Selecting that row copies only the six-digit OTP to the clipboard. Launch at Login can be toggled from the same menu; the Diagnostics row is intentionally omitted.

## Release evidence

Each release includes:

- `manifest.json` for deterministic payload verification.
- `release-metadata.json` with `installer_ux=native-gui-no-terminal` and `administrator_authorization=macos-ui-once`.
- `FINAL-RUNTIME-BINDING.json` when the source compliance bundle is present; it binds canonical pre-rewrite/pre-sign runtime artifacts to the final ad-hoc-signed payload.
- `THIRD_PARTY_NOTICES.txt` and `SOURCE-OFFER.txt` for bundled runtime components.

## Internal implementation notes

Only `installer/root-admin.sh` and `installer/manifest.py` remain as private implementation resources for the native installer.
