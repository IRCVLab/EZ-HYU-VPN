# Task 7 Report: Offline integration and adversarial verification

## RED

- Added `tests/test_offline_integration.py` with real-subprocess offline E2E and adversarial checks.
- Initial RED exposed missing documentation files:
  - `README.md` absent.
  - `docs/reverse-engineering.md` absent.
- Test-harness REDs were corrected inside the owned integration test only: generated fake executables needed proper shebang/dedent handling and the signal-during-OTP-wait assertion now checks teardown/no-orphan rather than forcing a specific interrupted exit code.

## GREEN

Implemented owned documentation and integration coverage only:

- `tests/test_offline_integration.py`
  - real subprocess connector run using temp fake OpenConnect, fake HIP wrapper, and fake oathtool;
  - password → bare portal OTP → gateway password → identical bare gateway OTP prompt sequence;
  - fake HIP wrapper invocation, XML parsing, session-established marker, SIGTERM process-group teardown, and no orphan child;
  - signal during TOTP reuse wait teardown/no-orphan;
  - malformed cookie, hostile XML escaping, missing binary, broken software-update cache, rapid crashes/backoff, concurrent supervisor lock, and offline live-posture XML signature check with synthetic cookie/MD5/documentation IPs.
- `README.md`
  - install after merge, prerequisites, Keychain service names without values, foreground use, service disabled by default, launchd load only after live acceptance, stop/rollback/recovery, and logs/privacy.
- `docs/reverse-engineering.md`
  - sanitized evidence, 38 native reports, false-positive schema correction, dual OTP, HIP flow, no native runtime dependency, and known PF n/a limitation.

## Verification

- Focused Task 7 suite: `python3 -m unittest -v tests.test_offline_integration` → 7 tests OK.
- Full offline suite: `python3 -m unittest discover -s tests -v` → 78 tests OK.
- Static/syntax: `python3 -m compileall -q src bin tests` → OK.
- Launchd plist: `plutil -lint launchd/local.hyu-openconnect.plist` → OK.
- Diff whitespace: `git diff --check` → OK.

## Offline live-posture XML generation

`test_offline_live_posture_xml_uses_synthetic_inputs_and_native_shape_signature` ran `bin/gp-hip-report` in a subprocess with a synthetic cookie, synthetic MD5, and documentation IPv4/IPv6 addresses. It parsed the XML, compared category order and the sanitized native shape signature subset, and did not print or save raw live identifiers.

## Scope notes

No runtime glue or established semantics were changed. Only Task 7 owned files were created or edited.
