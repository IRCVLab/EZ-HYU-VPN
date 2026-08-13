# macOS Rust Release Checklist

Use `scripts/live-macos-rust-acceptance.sh` to collect sanitized evidence for the verified macOS Rust DMG. In live mode the script reruns scripts/macos-dmg-acceptance.sh itself; a `--dmg-acceptance-log` is optional output evidence only and is bound to the exact canonical DMG path plus digest, never sufficient alone.

## Invocation contract

1. Read-only baseline with DMG:
   `scripts/live-macos-rust-acceptance.sh --mode preflight --dmg dist/macos/EZ-HYU-VPN-arm64.dmg`
2. Test-root rollback proof bound to that DMG:
   `scripts/live-macos-rust-acceptance.sh --mode test-root --dmg dist/macos/EZ-HYU-VPN-arm64.dmg --test-root /private/tmp/hyu-test-root --rollback-injection health --evidence-out /private/tmp/task9-test-root-evidence.json`
3. Authorized live run with JSON test-root evidence and a fresh one-use live nonce:
   `HYU_LIVE_MACOS_RUST_NONCE=hyu-live-macos-rust-$(date +%s) HYU_LIVE_MACOS_RUST_TEST_ROOT_EVIDENCE=/private/tmp/task9-test-root-evidence.json scripts/live-macos-rust-acceptance.sh --mode live --test-root /private/tmp/hyu-test-root --nonce "$HYU_LIVE_MACOS_RUST_NONCE" --user-present I-am-present-for-live-macOS-Rust-acceptance --dmg dist/macos/EZ-HYU-VPN-arm64.dmg`
4. Optional uninstall/reinstall exercise:
   add `--exercise-uninstall-reinstall`; without it, live acceptance reports uninstall not exercised and cannot claim full Task 9 completion. Root-admin live uninstall/install uses fresh `hyu-install-mutation-EPOCH` nonces separate from the live acceptance nonce.
5. Run the physical Wi-Fi gate last only after every prior phase passes; add `--physical-wifi-gate` with the same live safeguards.

## Evidence boundaries

- Never record plaintext credentials, OTP seeds, cookies, private keys, or raw log matching lines.
- Use Unix-socket framed IPC for status/connect/disconnect/reconnect with schema v1 request and `result` variant response validation from `hyu-vpn-protocol`; no secrets are sent.
- Production socket default is `$HOME/Library/Application Support/hyu-openconnect/daemon.sock`.
- Record only hashes, state codes, instance counts, helper-owned PIDs/nonces, and pass/fail phase summaries.
- Baseline Google, GitHub, and DNS health must be good before any mutation phase.
- The DMG must have a regular checksum file and the live script must rerun read-only/nobrowse DMG acceptance before mounting and launching `Install HYU VPN.app`.
- Terminate only helper-recorded owned OpenConnect sessions via exact helper `stop`; do not use broad process killers.
- The physical Wi-Fi gate last is the only disruptive network-change check and must observe unhealthy, then healthy, then a connected attempt within 10 seconds.
- test-root evidence is a 0600 JSON file bound to the exact test root, DMG digest, mounted manifest digest, injection, timestamp, command contract, and result; live mode rejects stale or mismatched evidence.

## Task 9 round-3 acceptance hardening notes

The live gate now treats Task 9 completion as evidence-bound, not log-bound:

- Install identity must compare installed service, helper, and menu executable SHA-256 values, modes, and owners to the mounted verified manifest, then validate the user launchd plist points directly to `/Library/Application Support/HYU VPN/bin/hyu-vpn-macos-service` and that IPC reports backend `0.2.0`.
- No-Python/legacy residue checks report only categories and counts for exact forbidden app-support paths, Python launchd references, and Python product processes.
- Owned OpenConnect recovery requires helper `stop`, stopped proof, IPC reconnect, new helper PID/nonce, and valid `utun`.
- Rust service restart must use exact `launchctl kickstart -k gui/$UID/com.hyu.vpn.service` and preserve the same owned helper PID/nonce while keeping exactly one service/menu process.
- Full uninstall evidence requires `--exercise-uninstall-reinstall`; it uses the mounted verified root-admin payload/manifest and a fresh `hyu-install-mutation-*` nonce, then reinstalls via the verified GUI installer before rerunning installed identity/no-Python/disconnected checks.
- The physical Wi-Fi gate remains final and must observe internet drop, recovery, and backend/helper transition/readiness; it must not be used as an earlier mutation phase.

## Task 9 round-4 live gate notes

- Generate test-root evidence with unprivileged `root-admin.sh --dry-run-root` against a staged native payload from the mounted verified DMG and a dry-root-confined allowlisted tools root; do not use live sudo for this mode. The root-admin log must contain `injected failure after health`, must not contain sudo authentication failure text, and rollback state must be complete before evidence is written. Live validation recomputes both the mounted package manifest digest and the retained staged manifest digest from the exact test root before accepting the 0600 evidence file.
- Run the physical Wi-Fi gate while the VPN is connected and automatic reconnect is enabled, immediately after Rust service restart reconciliation and before explicit disconnect/restoration.
- Launch the GUI installer through the bounded `open -W` wrapper; timeout handling may terminate only that owned `open` process, then the script must fail closed before identity claims.
