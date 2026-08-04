# HYU HIP Reverse Engineering Summary

This document summarizes sanitized evidence only. It does not contain real credentials, authentication cookies, OTP values, host identifiers, MAC addresses, private IP assignments, native raw XML, or native log excerpts.

## Evidence set

- 38 native reports were parsed from the local GlobalProtect diagnostic history during design.
- All quoted structures here are sanitized evidence using placeholders and documentation IP ranges such as `192.0.2.0/24` and `2001:db8::/32`.
- The native application remains a temporary migration oracle only; the runtime in this repository has no native runtime dependency on PanGPS, PanGPA, PanGpHip, PanGpHipMp, or GlobalProtect binaries or cached report files.

## False-positive schema correction

The first simplified HIP prototype passed tests while using a false-positive schema: simplified `category/product` paths. Path-signature comparison against native data showed missing native paths and added non-native paths. The corrected schema uses:

- `categories/entry` nodes in this exact category order: `host-info`, `anti-malware`, `disk-backup`, `disk-encryption`, `firewall`, `patch-management`, and `data-loss-prevention`.
- Product records as `list/entry/ProductInfo/Prod` with native-style status children.
- FileVault state under `drives/entry/enc-state`.
- Firewall state under `is-enabled`.
- Missing updates under sibling `missing-patches/entry` records.

## Dual OTP authentication

This is the documented dual OTP flow.

The observed authentication flow is password, portal Challenge, gateway Password, then gateway Challenge. The two `Challenge:` prompts are both bare prompt labels, so the connector cannot suppress a later identical label as a duplicate. Reusing the same TOTP window can fail, so the OTP provider waits for the next bounded window when it sees the same generated value twice.

## HIP flow

The HIP flow follows the OpenConnect GlobalProtect sequence:

1. Gateway/portal provides HIP interval metadata.
2. The client checks `/ssl-vpn/hipreportcheck.esp` with the MD5 identifier and assigned client address.
3. If needed, the wrapper emits one XML report on stdout.
4. OpenConnect posts that XML to `/ssl-vpn/hipreport.esp`.
5. A successful response carries the expected allow profile notification.

The wrapper preserves authoritative OpenConnect fields such as cookie identity, MD5, and client IP without replacement mutation. Diagnostics are redacted.

## Known limitation

known PF n/a limitation: Packet Filter state can be `n/a` when `/sbin/pfctl -s info` is unavailable, denied, timed out, or malformed. That is intentional truthful reporting; the implementation must not fabricate an enabled firewall or encrypted disk state when probes fail.
