# Task 5 RED/GREEN Report: dual-TOTP connector and process ownership

## Scope

Owned files only:
- `src/hyu_vpn/otp.py`
- `src/hyu_vpn/connector.py`
- `bin/hyu-vpn-connect`
- `tests/helpers/fake_openconnect.py`
- `tests/helpers/fake_oathtool.py`
- `tests/test_connector.py`
- `task-5-report.md`

Other agents' Task 2 files were not modified or staged.

## RED evidence

1. Initial focused RED:
   - Command: `python3 -m unittest -v tests.test_connector.ConnectorTests.test_uses_distinct_totp_for_portal_and_gateway`
   - Result: failed with `ModuleNotFoundError: No module named 'hyu_vpn.connector'`.
   - Meaning: connector implementation was absent before production code was added.

2. Prompt-state regression RED during broader run:
   - Command: `python3 -m unittest -v tests.test_connector tests.test_security_privacy`
   - Result: `test_duplicate_prompt_tail_gets_single_response` failed because `provider.current()` was called twice for a duplicate bare `Challenge:` prompt.
   - Fix: classify prompt keys narrowly (`password`, `challenge`, `gateway challenge`) instead of using a greedy tail label.

## GREEN evidence

- Focused first GREEN:
  - Command: `python3 -m unittest -v tests.test_connector.ConnectorTests.test_uses_distinct_totp_for_portal_and_gateway`
  - Result: 1 test passed.

- Full connector GREEN after cleanup:
  - Command: `python3 -m unittest -v tests.test_connector`
  - Result: 11 tests passed.

- Repository test suite:
  - Command: `python3 -m unittest discover -s tests -v`
  - Result: 36 tests passed.

- Static syntax check:
  - Command: `python3 -m compileall -q src tests bin`
  - Result: exit 0.

## Implemented behavior checklist

- Reads existing macOS Keychain services `gp-vpn-username`, `gp-vpn-password`, and `gp-vpn-totp` through argv-array `/usr/bin/security find-generic-password -s <service> -w`.
- Generates TOTP through argv-array `/opt/homebrew/bin/oathtool --totp -b <seed>` by default.
- Redacts secret material from raised/printed errors; no password, seed, OTP, cookie, host ID, or raw HIP XML logging was added.
- Uses PTY output handling for split prompts.
- Sends the stdin password once for `--passwd-on-stdin` and ignores duplicate password prompt echoes.
- Handles portal and gateway challenge prompts as distinct prompt keys.
- Forces distinct TOTP values by waiting until the next bounded 30-second window when oathtool initially returns the previous OTP.
- Avoids duplicate responses to an unchanged bare prompt tail.
- Starts OpenConnect in a dedicated session/process group via `start_new_session=True`.
- Handles SIGINT/SIGTERM by forwarding the signal to the child process group, waiting boundedly, then escalating to SIGKILL only on timeout.
- Tests use fake real subprocess children that record received signals and confirm no child process remains.
- Builds an OpenConnect command including `--protocol=gp`, `secure.hanyang.ac.kr`, `/opt/homebrew/bin/openconnect`, `/opt/homebrew/etc/vpnc/vpnc-script`, and planned repo `bin/gp-hip-report` as `--csd-wrapper`; no native GlobalProtect/PanGP execution path is used.
- `bin/hyu-vpn-connect` resolves the repository `src` path relative to the entrypoint before importing.

## Verification gap

- Requested command `python3 -m unittest -v tests.test_connector tests.test_security_privacy` cannot fully pass in this worktree because `tests/test_security_privacy.py` is not present yet and is outside Task 5 ownership. The connector portion of that command passes; the absent privacy module is expected to be provided by Task 4 and was not created or modified here per instruction.
