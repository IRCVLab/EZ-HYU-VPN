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

---

## Review Fix Round: authoritative text and complete output writes

### Findings addressed

1. XML output now loops until every byte is written. A zero, `None`, invalid, or over-reported write is a redacted output failure and returns nonzero; flush occurs only after complete output.
2. Cookie, MD5, client addresses, client OS, and parsed user/domain/computer are strict authoritative fields. Surrogates and replacement characters are rejected with redacted nonzero output instead of being silently changed. Replacement cleaning remains limited to non-authoritative posture text and optional APP_VERSION environment text.

### RED evidence

- Short writer returning 7 bytes produced truncated XML while `main()` returned zero.
- A partial write followed by zero progress returned zero.
- Surrogates in cookie user, MD5, or client IP were replaced and emitted with success.

### GREEN evidence

- Five focused output/encoding regressions: `Ran 5 tests ... OK`.
- HIP CLI + privacy suites: `Ran 12 tests ... OK`.
- `py_compile` and `git diff --check` passed.
