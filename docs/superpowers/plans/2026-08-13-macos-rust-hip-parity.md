# macOS Rust HIP parity implementation plan

**Goal:** Replace the incomplete macOS Rust HIP report with a faithful native port of the previously validated Python posture and HIP v4 XML logic, then prove it against deterministic fixtures and a live HYU VPN connection.

## Acceptance criteria

- Rust emits the complete HIP v4 root fields and all seven categories in the established order.
- macOS posture includes OS, physical interface/MAC host identity, XProtect, Gatekeeper, FileVault, application firewall, PF, and Software Update state.
- Cookie contents never appear in diagnostics or generated XML except parsed identity fields.
- Unit/integration tests cover deterministic XML shape, escaping, collection parsers, and degraded command behavior.
- `cargo fmt`, targeted tests, Clippy, live HYU DNS/public Internet checks, reconnect, and fresh DMG installation all pass.
- No GitHub release is published until every local and live gate passes.

## Steps

1. Add a deterministic failing Rust regression test for the complete HIP contract.
2. Introduce macOS posture value types and a production collector using fixed-argument system commands and bounded output.
3. Port the deterministic HIP v4 XML renderer and timestamp conversion.
4. Strengthen service HIP-success accounting so status does not claim success without OpenConnect confirmation.
5. Run static and automated validation.
6. Atomically install the Rust HIP binary, verify a live connection and reconnect, and rollback to the working official hook on failure.
7. Build and install the DMG, repeat live acceptance, then decide whether it is releasable.
