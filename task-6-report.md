# Task 6 Report: reconnect supervision and launchd

## RED evidence

- Initial Task 6 tests failed because `hyu_vpn.supervisor` was absent.
- After the interrupted worker left the supervisor core, launchd tests remained RED with missing `bin/hyu-vpn-service` and `launchd/local.hyu-openconnect.plist`.
- Added regressions exposed two no-reconnect/no-spin faults: a clean child exit stopped the supervisor, and repeated launch failures ignored the test iteration bound and spun indefinitely.
- An unusable lock parent raised `FileExistsError` instead of returning a safe single-instance failure.

## Implemented behavior

- Backoff: 10, 20, 40, 80, 120 seconds capped; sessions lasting at least 300 seconds reset the failure count.
- Every unexpected child exit, including return code zero, reconnects after at least 10 seconds; no zero-delay spin.
- Native conflict requires both a native process name from bounded `/bin/ps` and the protected route on a `utun` from bounded `/sbin/route`; no native binary is invoked.
- Connector child runs in a new session/process group; SIGINT/SIGTERM is forwarded, then escalated only after a bounded wait.
- Single-instance `fcntl.flock` uses a mode-0600 file and safely rejects unusable/locked paths.
- LaunchAgent uses the final absolute service path, RunAtLoad, KeepAlive, ThrottleInterval 120, safe user logs, no embedded secrets or native references. It is not loaded or enabled by this task.

## GREEN evidence

- Supervisor + launchd suites: `Ran 15 tests ... OK`.
- Full repository suite: `Ran 70 tests ... OK`.
- `py_compile`, `compileall`, `plutil -lint`, no-`shell=True` scan, and `git diff --check` passed.
