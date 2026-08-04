# HYU VPN internal lab install notes

This ad-hoc-signed build is only for the named internal lab. It is not notarized and is not ready for public distribution.

## Current safety contract

- This package uses the fixed system interpreter `/usr/bin/python3` for Python backend/native/HIP entrypoints. The installer must fail before sudo if `/usr/bin/python3` is absent or not executable; it must not fall back to PATH or Homebrew Python.

- `Install HYU VPN.command` defaults to package audit only. Audit verifies the embedded manifest and exits without sudo, LaunchAgent bootstrap, Keychain writes, route/DNS changes, or VPN connection attempts.
- A real install requires the explicit `--live-install` option. The user phase generates a fresh one-shot nonce internally, verifies the payload, stages runtime artifacts in a temporary directory, and collects credentials before sudo; nonce values are not accepted from the environment or files.
- Credentials are written to the exact connector Keychain services: `gp-vpn-username`, `gp-vpn-password`, and `gp-vpn-totp`. Password/TOTP prompts use `/usr/bin/security ... -w`; secrets are not placed in argv, env, logs, or installer files.
- The root phase accepts only fixed options. It rejects duplicate options and live use of dry-run/test controls.
- The known unsafe legacy LaunchAgent label `local.hyu-openconnect` is quarantined by exact-label bootout/disable and is never re-enabled by rollback or uninstall.
- LaunchAgents use `RunAtLoad=true` and `KeepAlive=false`. After the root transaction succeeds, the user activation phase first writes `auto-reconnect=false`, then bootstraps and kickstarts the service/menu. The service therefore starts idle and cannot launch OpenConnect until the user explicitly chooses Connect or later enables automatic reconnect.
- Root helper config uses the exact eight-key Swift contract, with `vpncScript` pointing to the HYU ledger wrapper and wrapperd integrity stored separately in `runtime/vpnc/hyu-vpnc-wrapperd.sha256`.
- Connector config is installed as root-owned mode-0644 `connector-config.json` and points to fixed `/Library/Application Support/HYU VPN/runtime/current/bin/oathtool` with a lowercase SHA-256 hash; installed connector execution must not fall back to Homebrew.
- The staged runtime includes the Python backend source tree, backend entrypoints, HIP wrapper, fixed native-client CLI, oathtool, OpenConnect closure, ledger wrapper/wrapperd, and upstream `vpnc-script`.
- The installer and uninstaller never delete or rewrite macOS SystemConfiguration network preference files.

## Installed launch entries

- Service LaunchAgent executes `/Library/Application Support/HYU VPN/bin/hyu-vpn-service`; it loads at login without KeepAlive and starts idle while `auto-reconnect=false`.
- Menu LaunchAgent executes `/Applications/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp`; it loads at login without KeepAlive.

## Remaining live gate

Offline packaging review, Swift helper/menu harnesses, and read-only DMG validation are complete. Before wider lab use, perform one explicit sudo/live migration run on this Mac with the old `local.hyu-openconnect` job already disabled, then repeat the acceptance run on a clean secondary lab Mac.

## Task8 packaging contract

- The DMG root is verified by one canonical `manifest.json` with `{schema:1, files:{rel:{sha256,mode,size}}}`. `config/final-runtime-manifest.json` is intentionally not emitted by Task8; Task7 must rely on the canonical package/stage manifest instead.
- Runtime payload paths are `runtime/openconnect/bin/openconnect`, `runtime/openconnect/lib/*.dylib`, `runtime/oathtool`, `runtime/gp-hip-report`, and `runtime/vpnc/*`. During Task7 staging, OpenConnect and oathtool must live next to `runtime/lib` as `runtime/bin/*` so `@loader_path/../lib` remains valid.
- Real non-fake release builds require `SOURCE-COMPLIANCE-BUNDLE.tar.gz` in the package root and listed in `manifest.json`. When using `scripts/package-release.py --assemble-from-repo`, provide it with `--source-compliance-bundle`; direct `--source-payload` mode must already contain the same regular non-symlink bundle. Fake tests do not require this artifact.
- The source bundle describes canonical pre-rewrite/pre-sign runtime provenance. After install-name rewriting and ad-hoc signing, the packager writes manifested `FINAL-RUNTIME-BINDING.json`, which binds the source-bundle hash and every canonical runtime path/hash/size to the corresponding final shipped path/hash/size. Read-only mounted validation recomputes and verifies this binding.
- DMG bit-for-bit reproducibility is not claimed or supported; the manifest and payload validation are deterministic.
- Live install still requires explicit `--live-install`; package audit mode performs no sudo, route/DNS, VPN, Keychain, or launchctl mutation.
