# HYU VPN Native GUI Installer Implementation Plan

1. Lock the retained-ledger migration failure with Swift unit and helper-harness tests, then implement deletion-only retirement without widening network mutation authority.
2. Add tested installer-domain models for credential requirements, confirmation validation, progress, cancellation, sanitized errors, and exact privileged invocation construction.
3. Build `Install HYU VPN.app` with AppKit, Security.framework Keychain access, manifest/staging orchestration, and one graphical administrator authorization call.
4. Update release packaging so the DMG exposes the native installer, removes `.command` entry points, binds its immutable payload to the release manifest, and audits architecture/signatures/load paths.
5. Run targeted tests, full offline gates, independent code/security review, and rebuild a new versioned internal DMG.
6. Install the new DMG on the target Mac and run the full external-network lifecycle matrix.
7. After live success, atomically update the latest pointer and remove obsolete release artifacts while retaining the current DMG, checksum, source-compliance bundle, and sanitized validation evidence.
