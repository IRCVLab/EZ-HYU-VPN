# HYU VPN update notifications

## Goal

Starting with v0.1.1, tell users when a newer HYU VPN release exists without coupling update checks to VPN connection or reconnect behavior. v0.1.0 users receive one manual Slack announcement because that version has no updater.

## Design

- The menu app reads its installed semantic version from `CFBundleShortVersionString`.
- On launch, and no more than once every six hours, an isolated update checker fetches a small HTTPS JSON feed with a short timeout and an ephemeral URL session.
- The feed is strict schema v1 JSON containing only `version` and `release_url`; malformed, oversized, downgraded, or non-HTTPS data is rejected.
- Release links are restricted to an explicit HTTPS host and repository path configured in the app bundle. No credentials or GitHub token are shipped.
- When the feed version is newer, the menu adds `Update Available: vX.Y.Z…`. Selecting it opens the approved release page in the default browser.
- The app displays one AppKit alert per offered version with `Download` and `Later`; the last announced version is stored in user defaults so it does not nag repeatedly.
- Network, parsing, and launch failures are silent and never alter VPN state, automatic reconnect, or menu controls.
- Downloading and installing remain manual for this release. Automatic installation, background replacement, Sparkle, and privileged updater code are out of scope.

## Distribution boundary

The source repository is private, so an unauthenticated client cannot use its GitHub release API. A functional feed and downloadable DMG therefore require an explicitly approved public distribution endpoint. The recommended deployment is a separate public release/feed repository containing only the update JSON, checksums, and release assets; no source, credentials, or runtime state is published by the updater.

## Verification

- Unit tests cover semantic version ordering, strict feed validation, size limits, URL allowlisting, downgrade/equal-version suppression, and newer-version offers.
- Menu harness tests verify the update row and source-level lifecycle wiring.
- Existing Python, Swift, installer, helper, and packaging tests remain green.
- Release verification checks that both app bundles contain v0.1.1 metadata and that a failed update fetch cannot affect the installed VPN status.
