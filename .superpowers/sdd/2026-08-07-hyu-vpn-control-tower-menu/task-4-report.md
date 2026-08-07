# Task 4 Report — Native login reset GUI and Keychain transaction

## Scope / files changed

- Created `macos/Sources/HYUVPNMenuApp/CredentialResetController.swift` for the native AppKit reset window.
- Created `macos/Sources/HYUVPNMenuApp/SystemAdapters.swift` for Security.framework Keychain access and secure TOTP counter reset.
- Modified `macos/Sources/HYUVPNMenuApp/AppDelegate.swift` to add `Reset Login Information…`, retain/dismiss the native controller, run the reset transaction off-main, and clear submitted payloads on transaction, cancellation, termination, and error paths.
- Modified `macos/Sources/HYUVPNMenuCore/ControlTowerCore.swift` to integrate credential reset into the deterministic lifecycle coordinator without nesting `OperationGate` operations.
- Modified Swift tests/harness only for Task 4 coverage.
- Did not modify Python, installer, helper, supervisor, DNS, route, SystemConfiguration, or `Package.swift`.

## RED evidence

Added tests/harness before production implementation, then ran:

```text
cd macos && swift test --filter HYUVPNMenuAppTests
```

Expected RED observed in `/tmp/task4-red-swift-test.log`:

```text
error: type 'AppLifecycleEvent' has no member 'credentialResetRequested'
error: type 'Array<AppLifecycleEffect>.ArrayLiteralElement' (aka 'AppLifecycleEffect') has no member 'runCredentialTransaction'
error: type 'AppLifecycleEvent' has no member 'credentialTransactionCompleted'
error: type 'Array<AppLifecycleEffect>.ArrayLiteralElement' (aka 'AppLifecycleEffect') has no member 'showCredentialResetError'
error: type 'Array<AppLifecycleEffect>.ArrayLiteralElement' (aka 'AppLifecycleEffect') has no member 'dismissCredentialReset'
```

This was a genuine feature-missing failure before adding production lifecycle/UI/adapter code.

## GREEN evidence

Fresh required verification was captured in `/tmp/task4-green-all.log`.

```text
cd macos && swift test --filter HYUVPNMenuAppTests
→ exit 0, Build complete
```

```text
cd macos && swift run hyu-vpn-menu-harness
→ exit 0, HARNESS PASS 36 tests
```

```text
cd macos && swift build
→ exit 0, Build complete
```

```text
cd macos && swift build -c release
→ exit 0, Build complete
```

```text
cd .. && rg -n 'print\(|NSLog|os_log|/usr/bin/security|Process\(|posix_spawn' macos/Sources/HYUVPNMenuApp
→ no matches (rg exit 1 when run standalone with no matches)
```

```text
git diff --check
→ exit 0, no whitespace errors
```

## Coverage disposition

Covered by Swift unit tests and/or executable harness:

- Native menu row source contract: exact `Reset Login Information…`, placed after Disconnect and before Diagnostics.
- Native reset UI source contract: five exact labels, four `NSSecureTextField` references, existing `CredentialValidator`, native validation message, username prefill seam, no Terminal/installer path.
- Keychain adapter source contract: `import Security`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemAdd`, `SecItemDelete`, fixed `hyu-vpn` account, fixed service map for only `CredentialKey.allCases`, no `/usr/bin/security`, `Process`, shell spawn, logging, or OSStatus string interpolation API.
- TOTP reset source contract: `mkdir` then `open(... O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`, UID/type/mode verification, `openat` lock with `O_NOFOLLOW|O_CLOEXEC`, `flock(LOCK_EX)`, `fstatat(... AT_SYMLINK_NOFOLLOW)`, `unlinkat`, fixed `totp-counter.json(.lock)`, no chmod/create through unverified existing path.
- Lifecycle order: reset starts verified disconnect; disconnect success triggers transaction; transaction success triggers exactly one connect; final connect completion clears gate.
- Failure behavior: disconnect failure performs no transaction/no connect; transaction failure/rollback performs no connect; connect failure after committed transaction reports stable control code without rollback.
- Duplicate suppression: Reset/Connect/Disconnect requests are absorbed while credential reset is active.
- Cancel/termination behavior: cancel performs no lifecycle event or mutation; quit while form is open dismisses the standalone native window and proceeds through normal safe disconnect; quit during reset disconnect cancels before writes; if that disconnect fails/times out it returns `reply(false)` plus normalized alert; quit during transaction lets the transaction finish/rollback, skips reconnect, and replies safely.
- Secret handling: tests never instantiate `KeychainCredentialStore` against real Keychain; canary tests cover stable validation/transaction descriptions; app source scan has no process/logging/CLI surfaces; submitted payload is cleared on transaction start/result and on skip/error/termination paths.

## Self-review

- The reset transaction uses `CredentialTransaction` with default no-op reconnect callback; AppDelegate owns the later connect through the lifecycle effect.
- No new dependencies were added; `Package.swift` was unchanged because the local toolchain built Security.framework usage without explicit linker changes.
- TOTP reset fails closed for unsafe metadata and does not delete the lock file.
- The UI uses a standalone AppKit window with `NSApp.activate(...)` instead of attaching a sheet to the status bar window.
- `.omx/` remains untracked and was not staged.

## Residual risks

- AppKit UI behavior is source/harness verified in this headless workflow rather than interactively screenshot-tested.
- Security.framework operations are not executed in tests to preserve the real Keychain stop condition; coverage is via adapter source contract and successful compile/link.

## Fix round 1 — behavioral platform coverage and Keychain ACL compatibility

### Review finding addressed

The review found that the TOTP resetter and native AppKit reset UI were primarily covered by source-token checks. I added package-internal runtime coverage that links the existing production AppKit/Security sources into `hyu-vpn-menu-harness` without duplicating production logic.

### Architecture changes

- Added internal SwiftPM target `HYUVPNMenuAppSupport` over the existing required production files:
  - `macos/Sources/HYUVPNMenuApp/CredentialResetController.swift`
  - `macos/Sources/HYUVPNMenuApp/SystemAdapters.swift`
- `HYUVPNMenuApp` and `HYUVPNMenuAppTestHarness` depend on that target directly; no externally exported support library product was added.
- Added isolated C target `HYUVPNKeychainAccessShim` for deprecated macOS file-keychain ACL APIs, built with `-Wall -Wextra -Werror`; only `-Wdeprecated-declarations` is locally suppressed in the shim source.
- Production support types and harness seams use Swift `package` access rather than public API.
- Runtime test logic lives in the executable harness; production exposes only package-access controller field/action seams and a package-access Keychain access factory used by production.

### Keychain ACL compatibility fix

Official Apple docs reviewed for `SecAccessCreate` and `kSecAttrAccess`:

- https://developer.apple.com/documentation/security/secaccesscreate(_:_:)
- https://developer.apple.com/documentation/security/ksecattraccess

Probe evidence provided in the controller turn showed default `SecItemAdd` ACLs can block the unchanged Python backend's `/usr/bin/security find-generic-password` reader, while an explicit ACL trusting the current app plus `/usr/bin/security` succeeds. The add-on-missing path now attaches `kSecAttrAccess` only to `SecItemAdd`, using a trusted-application ACL for:

- current application (`SecTrustedApplicationCreateFromPath(NULL, ...)`)
- fixed Apple tool path `/usr/bin/security`

`SecItemUpdate` remains unchanged and never replaces ACLs. The old literal-path scan exception is deliberate and scoped to the C shim; the required production scan over `macos/Sources/HYUVPNMenuApp` still has no `/usr/bin/security` matches.

### New runtime coverage

Executable harness now visibly runs these behavior checks (`HARNESS PASS 41 tests`):

- `totp-resetter-runtime-secure-delete-and-missing-state`
  - secure temp parent + lock + state deletes only `totp-counter.json`
  - preserves `totp-counter.json.lock`
  - missing state succeeds and preserves lock
- `totp-resetter-runtime-unsafe-metadata-fails-closed`
  - parent symlink and wrong mode fail closed
  - lock symlink, wrong mode, wrong type fail closed
  - state symlink, wrong mode, wrong type fail closed
  - protected state/lock paths are not unintentionally unlinked
  - wrong-owner policy is covered through the package-internal pure metadata policy seam (no sudo required)
- `totp-resetter-runtime-flock-coordination`
  - actual `flock(LOCK_EX)` coordination blocks while a sibling lock is held, then deletes state only after release
- `keychain-add-access-runtime-and-source-contract`
  - creates the production SecAccess ACL object without writing a Keychain item or executing `/usr/bin/security`
  - verifies ACL source trusts current app plus `/usr/bin/security`
  - verifies `kSecAttrAccess` is add-only and not on update
- `credential-reset-controller-runtime-behavior`
  - actual AppKit controller constructs exactly five editable fields and four secure fields
  - password mismatch keeps the window open, completes zero times, and shows stable non-secret copy
  - Cancel returns nil and clears fields
  - window Close returns nil exactly once and clears fields
  - successful submit returns validated value and clears fields
- `control-tower-transaction-policy-gate`
  - explicit visible harness assertion that blank-TOTP `CredentialTransaction` succeeds without invoking the resetter

All runtime filesystem tests use temporary homes under `NSTemporaryDirectory()` and never touch live TOTP state. Keychain ACL coverage creates only a `SecAccess` object and never adds/updates/reads/removes a real Keychain item.

### Mutation sensitivity proof

Temporary mutations were introduced and restored before GREEN:

1. **TOTP unlink mutation**
   - Mutation: changed the production `unlinkat` target from `totp-counter.json` to `totp-counter.json.mutant`.
   - Command: `cd macos && swift run hyu-vpn-menu-harness`
   - Evidence: `/tmp/task4-mutation-skip-unlink.log`
   - Result: harness exited non-zero with `HARNESS FAIL: unsafePath` during `totp-resetter-runtime-secure-delete-and-missing-state`.

2. **AppKit field-clearing mutation**
   - Mutation: skipped clearing the first secure text field in `CredentialResetController.finish`.
   - Command: `cd macos && swift run hyu-vpn-menu-harness`
   - Evidence: `/tmp/task4-mutation-skip-field-clearing.log`
   - Result: harness exited non-zero with `HARNESS FAIL: cancel returns nil and clears fields` during `credential-reset-controller-runtime-behavior`.

No mutation remains in the worktree (`rg 'MUTATION|mutant|totp-counter\.json\.mutant' macos/Sources/HYUVPNMenuApp` returned no matches before GREEN).

### Fix round GREEN evidence

Fresh required verification captured in `/tmp/task4-fix-green-all.log`:

```text
cd macos && swift test --filter HYUVPNMenuAppTests
→ exit 0, Build complete
```

```text
cd macos && swift run hyu-vpn-menu-harness
→ exit 0, HARNESS PASS 41 tests
```

```text
cd macos && swift build
→ exit 0, Build complete
```

```text
cd macos && swift build -c release
→ exit 0, Build complete
```

```text
cd .. && rg -n 'print\(|NSLog|os_log|/usr/bin/security|Process\(|posix_spawn' macos/Sources/HYUVPNMenuApp
→ no matches (the intentional `/usr/bin/security` trusted-application path is isolated in `macos/Sources/HYUVPNKeychainAccessShim/HYUVPNKeychainAccessShim.c`, not in `HYUVPNMenuApp` Swift sources and not executed)
```

```text
git diff --check
→ exit 0, no whitespace errors
```

### Residual risk update

- AppKit behavior is now exercised at runtime in the harness, but still not screenshot/pixel verified.
- Keychain item write/read behavior against a real keychain remains intentionally unexecuted to satisfy the no-real-Keychain-mutation stop condition; ACL object creation and add-path source placement are covered.
