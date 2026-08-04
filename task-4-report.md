# Task 4 Report: Safe OpenConnect HIP Wrapper CLI

## RED
- Added `tests/test_hip_cli.py` covering XML-only stdout, repo-local executable import resolution, missing args, collector failure, broken pipe, and non-UTF-8/surrogate-safe handling.
- Added `tests/test_security_privacy.py` covering HIP CLI and connector privacy canaries across stdout, stderr, diagnostic logs, and OpenConnect argv construction.
- Confirmed RED with `python3 -m unittest -v tests.test_hip_cli tests.test_security_privacy`: failed because `hyu_vpn.hip_cli` and `bin/gp-hip-report` were absent.

## GREEN
- Implemented `src/hyu_vpn/hip_cli.py` as a stdlib-only csd-wrapper CLI that:
  - parses OpenConnect wrapper arguments without logging argv;
  - uses `CookieIdentity`, `MacPostureCollector`, and `build_hip_xml`;
  - builds the full XML in memory before writing;
  - writes exactly one XML document to `stdout.buffer` and nothing else on success;
  - exits zero only after successful write/flush;
  - returns nonzero with redacted stderr classes for invocation, cookie, collection, XML, and output errors;
  - handles broken pipe without traceback; and
  - replaces invalid UTF-8 surrogate text before XML encoding.
- Added `bin/gp-hip-report`, executable, resolving repository `src/` before invoking `hyu_vpn.hip_cli.main()`.
- Tests inject collectors/writers through private keyword-only seams; there is no runtime spoof environment toggle or native GlobalProtect dependency.

## Verification
- Focused CLI/privacy: `python3 -m unittest -v tests.test_hip_cli tests.test_security_privacy` → 8 tests OK.
- Full suite: `python3 -m unittest discover -s tests -p 'test*.py' -v` → 47 tests OK.
- Compile/static: `python3 -m compileall -q src tests bin` → OK.

## Privacy Notes
- Password, TOTP seed, OTP, full cookie, and `authcookie` canaries are absent from stdout, stderr, and logs.
- User, host-name, host-id, and MAC appear only in HIP XML stdout where protocol fields require them, never in stderr or diagnostic logs.
- No raw XML logging is performed.
