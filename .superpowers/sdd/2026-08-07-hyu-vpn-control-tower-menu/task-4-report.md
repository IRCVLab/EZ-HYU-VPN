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
