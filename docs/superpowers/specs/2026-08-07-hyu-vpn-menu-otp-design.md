# HYU VPN Menu OTP and Control Recovery Design

## Goal

Keep the menu controls usable, make Launch at Login register correctly on the shipped ad-hoc app, remove the Diagnostics entry, and add a live TOTP item that copies the current six-digit code.

## Root causes

- The Diagnostics action used a modal `NSAlert` that could remain hidden behind another application. AppKit disabled the rest of the menu while that modal session remained open.
- On a fresh installation, `SMAppService.mainApp.status` returned `.notFound`, which the app projected to an unavailable menu item. A direct `register()` call on that same installed app succeeded, so the UI prevented a valid recovery action.

## Design

- Remove Diagnostics from the menu and delete its modal alert path.
- Project the pre-registration `.notFound` login-item status as disabled/registerable. Registration errors remain fail-closed and are normalized by the existing adapter.
- Add a pure native TOTP generator to `HYUVPNMenuCore`. It decodes the validated RFC 4648 Base32 seed and calculates RFC 6238 SHA-1, six-digit, 30-second TOTP values with CryptoKit.
- Add an app-support provider that reads only the encrypted TOTP seed and returns a display snapshot. It does not mutate `totp-counter.json` and therefore cannot consume a VPN authentication counter.
- Add one menu item formatted as `OTP: 123456 · 18s — Copy`. A common-run-loop one-second timer updates the title while the menu is open. Clicking writes only the six ASCII digits to the general pasteboard.
- If the seed cannot be read or decoded, show a disabled `OTP unavailable` item and expose no secret-bearing error text.

## Tests

- RFC 4226/6238 known vector, countdown boundary, invalid Base32, and six-digit formatting tests.
- Login-item projection test proving `.notFound` remains registerable.
- App harness checks that Diagnostics is absent, the OTP action is present, and the provider reads the encrypted seed without modifying the counter state.
- Existing Swift, Python, packaging, signing, and DMG verification remain required.

## Security and privacy

- No Keychain or Security.framework access.
- No TOTP seed is shown, logged, placed in process arguments, or copied.
- Only the short-lived six-digit OTP is displayed and copied on an explicit click.
- The OTP display path never writes the connector's anti-reuse state.
