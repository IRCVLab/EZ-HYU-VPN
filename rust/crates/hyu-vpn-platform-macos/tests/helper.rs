use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use hyu_vpn_platform_macos::{
    ActiveStartFailureScenario, CleanupAction, CleanupScenario, HelperCleanupOutcome,
    HelperCommand, HelperError, HelperProcess, HelperProcessOutput, HelperRunner,
    HelperSessionEvent, HelperSessionFailure, HelperSessionOutcome, HelperStartInput,
    HelperStartSession, HelperState, HelperStdin, HelperTotpProvider, InstalledHelperRunner,
    SecretBytes, active_start_failure_cleanup_for_test, drive_start_prompts_for_test,
    drop_start_session_cancel_signal_for_test, graceful_cleanup_sequence_for_test,
    helper_invocation_for_test, helper_start_invocation_for_test, parse_helper_action_for_test,
    parse_helper_status_for_test, production_short_overflow_launcher_for_test,
    production_start_eof_launcher_for_test, run_short_overflow_reap_for_test,
};

#[derive(Clone)]
struct SequenceTotp {
    values: Arc<Mutex<Vec<SecretBytes>>>,
}

#[async_trait]
impl HelperTotpProvider for SequenceTotp {
    async fn next_totp(&self) -> Result<SecretBytes, HelperError> {
        let mut values = self.values.lock().unwrap();
        if values.is_empty() {
            Err(HelperError::PromptInputUnavailable)
        } else {
            Ok(values.remove(0))
        }
    }
}

fn start_input() -> HelperStartInput {
    HelperStartInput::new(
        "alice.sso-1@hanyang.ac.kr",
        SecretBytes::from_utf8_for_test("PASSWORD-CANARY"),
        Arc::new(SequenceTotp {
            values: Arc::new(Mutex::new(vec![
                SecretBytes::from_utf8_for_test("111111"),
                SecretBytes::from_utf8_for_test("222222"),
            ])),
        }),
    )
    .unwrap()
}

#[test]
fn helper_invocation_uses_fixed_sudo_argv_empty_env_and_bounded_contract() {
    // Catches: shelling out, ambient environment inheritance, helper path substitution, or unbounded IO.
    for (command, verb) in [
        (HelperCommand::Stop, "stop"),
        (HelperCommand::Status, "status"),
        (HelperCommand::Repair, "repair"),
    ] {
        let invocation = helper_invocation_for_test(&command).unwrap();
        assert_eq!(invocation.program, "/usr/bin/sudo");
        assert_eq!(
            invocation.args,
            vec![
                "-n".to_owned(),
                "/Library/PrivilegedHelperTools/com.hyu.vpn.helper".to_owned(),
                verb.to_owned(),
            ]
        );
        assert!(invocation.env.is_empty());
        assert_eq!(invocation.stdin, HelperStdin::Null);
        assert!(invocation.timeout <= Duration::from_secs(10));
        assert!(invocation.max_output_bytes <= 16 * 1024);
    }
}

#[test]
fn start_invocation_uses_interactive_private_stdin_without_secrets_in_argv_or_env() {
    // Catches: leaking password/TOTP/cookie/portal data through argv/env instead of the private child stdin channel.
    let invocation = helper_start_invocation_for_test(&start_input()).unwrap();

    assert_eq!(
        invocation.args,
        vec![
            "-n".to_owned(),
            "/Library/PrivilegedHelperTools/com.hyu.vpn.helper".to_owned(),
            "start".to_owned(),
        ]
    );
    assert_eq!(
        invocation.stdin,
        HelperStdin::Interactive {
            initial_header: b"HYU-Username: alice.sso-1@hanyang.ac.kr\n\n".to_vec()
        }
    );
    assert!(invocation.env.is_empty());
    let joined = format!("{} {:?}", invocation.program, invocation.args);
    for forbidden in [
        "PASSWORD-CANARY",
        "111111",
        "222222",
        "password",
        "totp",
        "otp",
        "cookie",
        "portal",
        "secure.hanyang.ac.kr",
    ] {
        assert!(
            !joined
                .to_ascii_lowercase()
                .contains(&forbidden.to_ascii_lowercase())
        );
    }
}

#[tokio::test]
async fn start_prompt_driver_writes_header_startup_password_then_prompt_responses_in_legacy_order()
{
    // Catches: closing helper stdin after the username header or answering OpenConnect prompts out of order.
    let output = [
        b"Challenge:".as_slice(),
        b"Password:".as_slice(),
        b"gateway Challenge:".as_slice(),
        b"HIP report submitted successfully.\n".as_slice(),
        b"hyu-vpnc-wrapperd-event: network configuration verified tunnel=utun7\n".as_slice(),
    ];

    let result = drive_start_prompts_for_test(start_input(), &output, 4096)
        .await
        .unwrap();

    assert_eq!(
        result.stdin_lines,
        vec![
            b"HYU-Username: alice.sso-1@hanyang.ac.kr\n\n".to_vec(),
            b"PASSWORD-CANARY\n".to_vec(),
            b"111111\n".to_vec(),
            b"PASSWORD-CANARY\n".to_vec(),
            b"222222\n".to_vec(),
        ]
    );
    assert_eq!(
        result.events,
        vec![
            HelperSessionEvent::HipSubmitted,
            HelperSessionEvent::Connected {
                tunnel: "utun7".to_owned()
            }
        ]
    );
}

#[tokio::test]
async fn start_prompt_driver_bounds_repeated_prompts_and_redacts_secret_diagnostics() {
    // Catches: unbounded prompt loops that can repeatedly consume passwords/TOTPs or leak them in errors.
    let mut input = start_input();
    input.max_prompt_responses = 2;
    let output = [
        b"Challenge:".as_slice(),
        b"Password:".as_slice(),
        b"Challenge:".as_slice(),
    ];

    let error = drive_start_prompts_for_test(input, &output, 4096)
        .await
        .unwrap_err();
    let diagnostic = format!("{error:?} {error}");

    assert!(matches!(error, HelperError::PromptLimitExceeded));
    for forbidden in ["PASSWORD-CANARY", "111111", "222222"] {
        assert!(!diagnostic.contains(forbidden));
    }
}

#[tokio::test]
async fn start_prompt_driver_cancels_immediately_on_shared_output_cap_overflow() {
    // Catches: waiting for the overall timeout after stdout/stderr exceed the combined cap.
    let output = [b"12345".as_slice(), b"67890".as_slice(), b"X".as_slice()];

    let error = drive_start_prompts_for_test(start_input(), &output, 10)
        .await
        .unwrap_err();

    assert!(matches!(error, HelperError::OutputLimitExceeded));
}

#[tokio::test]
async fn long_lived_start_session_bounds_parser_memory_without_capping_lifetime_output() {
    // Catches: treating the 16 KiB parser-memory bound as a lifetime-output quota, which
    // killed healthy sessions when OpenConnect emitted more output at session expiry.
    let noise = b"keepalive status line\n".repeat(1_000);
    assert!(noise.len() > 16 * 1024);
    let output = [
        b"Challenge:".as_slice(),
        b"Password:".as_slice(),
        b"gateway Challenge:".as_slice(),
        b"HIP report submitted successfully.\n".as_slice(),
        b"hyu-vpnc-wrapperd-event: network configuration verified tunnel=utun7\n".as_slice(),
        noise.as_slice(),
    ];

    let result = drive_start_prompts_for_test(start_input(), &output, 16 * 1024)
        .await
        .unwrap();

    assert_eq!(
        result.events,
        vec![
            HelperSessionEvent::HipSubmitted,
            HelperSessionEvent::Connected {
                tunnel: "utun7".to_owned()
            }
        ]
    );
}

#[tokio::test]
async fn start_session_output_eof_waits_for_natural_child_exit_instead_of_forcing_cleanup() {
    // Catches: racing stdout/stderr EOF against child.wait() at VPN session expiry and
    // misclassifying an ordinary OpenConnect exit as an invalid helper protocol response.
    assert_eq!(
        production_start_eof_launcher_for_test(64).await.unwrap(),
        HelperSessionOutcome::Exited { status: 64 }
    );
}

#[tokio::test]
async fn start_event_parser_handles_fragmented_and_coalesced_lines_with_prompt_interleaving() {
    // Catches: parsing connected events only within one chunk instead of a bounded persistent line buffer.
    let output = [
        b"Chal".as_slice(),
        b"lenge:\nHIP report sub".as_slice(),
        b"mitted successfully.\nhyu-vpnc-wrapperd-event: network configuration verified tunnel=ut"
            .as_slice(),
        b"un7\nnoise\nhyu-vpnc-wrapperd-event: network configuration verified tunnel=utun8\n"
            .as_slice(),
        b"HIP report submitted successfully.\n".as_slice(),
        b"Password:".as_slice(),
    ];

    let result = drive_start_prompts_for_test(start_input(), &output, 4096)
        .await
        .unwrap();

    assert_eq!(
        result.events,
        vec![
            HelperSessionEvent::HipSubmitted,
            HelperSessionEvent::Connected {
                tunnel: "utun7".to_owned()
            }
        ]
    );
    assert_eq!(
        result.stdin_lines,
        vec![
            b"HYU-Username: alice.sso-1@hanyang.ac.kr\n\n".to_vec(),
            b"PASSWORD-CANARY\n".to_vec(),
            b"111111\n".to_vec(),
            b"PASSWORD-CANARY\n".to_vec(),
        ]
    );
}

#[tokio::test]
async fn start_event_parser_rejects_oversize_incomplete_event_line_without_leaking_content() {
    // Catches: unbounded persistent event buffers or diagnostics containing raw helper output.
    let oversized = vec![b'x'; 600];

    let error = drive_start_prompts_for_test(start_input(), &[oversized.as_slice()], 4096)
        .await
        .unwrap_err();
    let diagnostic = format!("{error:?} {error}");

    assert!(matches!(error, HelperError::InvalidResponse));
    assert!(!diagnostic.contains("xxxxx"));
}

#[tokio::test]
async fn short_command_overflow_kills_and_reaps_long_lived_process_immediately() {
    // Catches: joining readers with child.wait() so an over-cap long-lived helper hangs until timeout.
    let evidence = run_short_overflow_reap_for_test(10, Duration::from_secs(1))
        .await
        .unwrap();

    assert!(evidence.killed);
    assert!(evidence.reaped);
    assert!(evidence.elapsed < Duration::from_millis(250));
}

#[test]
fn start_rejects_usernames_that_cannot_be_helper_headers() {
    // Catches: newline/header injection or unbounded untrusted data sent to the privileged helper.
    for invalid in [
        "",
        "alice\nHYU-Username: bob",
        "alice password",
        "alice/../bob",
        &"a".repeat(129),
    ] {
        assert!(
            HelperStartInput::new(
                invalid,
                SecretBytes::from_utf8_for_test("PASSWORD-CANARY"),
                Arc::new(SequenceTotp {
                    values: Arc::new(Mutex::new(Vec::new()))
                })
            )
            .is_err()
        );
    }
}

#[test]
fn helper_status_parser_accepts_only_exact_schema_and_utun_digits_limited_to_eight() {
    // Catches: accepting undocumented helper JSON or unsafe tunnel-interface evidence.
    assert_eq!(
        parse_helper_status_for_test(
            br#"{"schema_version":1,"state":"stopped","pid":null,"session_nonce":null,"tunnel_interface":null}"#
        )
        .unwrap(),
        HelperState::Stopped
    );
    assert_eq!(
        parse_helper_status_for_test(
            br#"{"schema_version":1,"state":"running","pid":4321,"session_nonce":"nonce-1","tunnel_interface":"utun12345678"}"#
        )
        .unwrap(),
        HelperState::Running {
            tunnel: Some("utun12345678".to_owned())
        }
    );
    assert_eq!(
        parse_helper_status_for_test(
            br#"{"schema_version":1,"state":"repair-required","pid":null,"session_nonce":"nonce-1","tunnel_interface":null}"#
        )
        .unwrap(),
        HelperState::RepairRequired
    );

    for invalid in [
        br#"{"schema_version":1,"state":"running","pid":1,"session_nonce":"n","tunnel_interface":"utun"}"#.as_slice(),
        br#"{"schema_version":1,"state":"running","pid":1,"session_nonce":"n","tunnel_interface":"utun123456789"}"#.as_slice(),
        br#"{"schema_version":1,"state":"running","pid":1,"session_nonce":"n","tunnel_interface":"en0"}"#.as_slice(),
        br#"{"schema_version":1,"state":"running","pid":1,"session_nonce":"n","tunnel_interface":"utun7","extra":true}"#.as_slice(),
        br#"{"schema_version":2,"state":"stopped","pid":null,"session_nonce":null,"tunnel_interface":null}"#.as_slice(),
        br#"{"schema_version":1,"state":"repair-required","pid":null,"session_nonce":"","tunnel_interface":null}"#.as_slice(),
        br#"{"schema_version":1,"state":"repair-required","pid":null,"session_nonce":null,"tunnel_interface":null}"#.as_slice(),
    ] {
        assert!(parse_helper_status_for_test(invalid).is_err());
    }
}

#[test]
fn action_response_parser_matches_actual_swift_command_outputs_per_command() {
    // Catches: accepting generic running/started action JSON for stop/repair or widening actual helper outputs.
    assert_eq!(
        parse_helper_action_for_test(&HelperCommand::Stop, br#"{"status":"stopped"}"#).unwrap(),
        HelperState::Stopped
    );
    assert_eq!(
        parse_helper_action_for_test(&HelperCommand::Stop, br#"{"status":"inactive"}"#).unwrap(),
        HelperState::Stopped
    );
    assert_eq!(
        parse_helper_action_for_test(&HelperCommand::Repair, br#"{"status":"stopped"}"#).unwrap(),
        HelperState::Stopped
    );
    assert!(
        parse_helper_action_for_test(&HelperCommand::Stop, br#"{"status":"running"}"#).is_err()
    );
    assert!(
        parse_helper_action_for_test(&HelperCommand::Repair, br#"{"status":"started"}"#).is_err()
    );
    assert!(
        parse_helper_action_for_test(
            &HelperCommand::Stop,
            br#"{"status":"stopped","extra":true}"#
        )
        .is_err()
    );
}

#[derive(Default)]
struct RecordingProcess {
    short_calls: Mutex<Vec<hyu_vpn_platform_macos::HelperInvocation>>,
    start_calls: Mutex<Vec<hyu_vpn_platform_macos::HelperInvocation>>,
    output: Mutex<Option<HelperProcessOutput>>,
    start_session: Mutex<Option<Box<dyn HelperStartSession>>>,
}

#[async_trait]
impl HelperProcess for RecordingProcess {
    async fn run_short(
        &self,
        invocation: hyu_vpn_platform_macos::HelperInvocation,
    ) -> Result<HelperProcessOutput, HelperError> {
        self.short_calls.lock().unwrap().push(invocation);
        Ok(self.output.lock().unwrap().take().unwrap())
    }

    async fn start_session(
        &self,
        invocation: hyu_vpn_platform_macos::HelperInvocation,
        _input: HelperStartInput,
    ) -> Result<Box<dyn HelperStartSession>, HelperError> {
        self.start_calls.lock().unwrap().push(invocation);
        Ok(self.start_session.lock().unwrap().take().unwrap())
    }
}

struct FakeSession {
    cancelled: Arc<Mutex<bool>>,
    outcome: Mutex<Option<HelperSessionOutcome>>,
}

#[async_trait]
impl HelperStartSession for FakeSession {
    async fn next_event(&mut self) -> Result<Option<HelperSessionEvent>, HelperError> {
        Ok(Some(HelperSessionEvent::Connected {
            tunnel: "utun8".to_owned(),
        }))
    }

    async fn wait(&mut self) -> Result<HelperSessionOutcome, HelperError> {
        Ok(self.outcome.lock().unwrap().take().unwrap())
    }

    async fn cancel(&mut self) -> Result<(), HelperError> {
        *self.cancelled.lock().unwrap() = true;
        Ok(())
    }
}

#[tokio::test]
async fn installed_runner_exposes_start_only_as_owned_session_not_short_run() {
    // Catches: using the five-second short command path for the long-running foreground start lifecycle.
    let cancelled = Arc::new(Mutex::new(false));
    let process = Arc::new(RecordingProcess {
        short_calls: Mutex::new(Vec::new()),
        start_calls: Mutex::new(Vec::new()),
        output: Mutex::new(Some(HelperProcessOutput {
            status: 0,
            stdout: br#"{"schema_version":1,"state":"running","pid":4321,"session_nonce":"nonce-1","tunnel_interface":"utun8"}"#.to_vec(),
            stderr: Vec::new(),
        })),
        start_session: Mutex::new(Some(Box::new(FakeSession {
            cancelled: cancelled.clone(),
            outcome: Mutex::new(Some(HelperSessionOutcome::Exited { status: 0 })),
        }))),
    });
    let runner = InstalledHelperRunner::with_process_for_test(process.clone());

    let state = runner.run(HelperCommand::Status).await.unwrap();
    assert_eq!(
        state,
        HelperState::Running {
            tunnel: Some("utun8".to_owned())
        }
    );

    let mut session = runner.start_session(start_input()).await.unwrap();
    assert_eq!(
        session.next_event().await.unwrap(),
        Some(HelperSessionEvent::Connected {
            tunnel: "utun8".to_owned()
        })
    );
    session.cancel().await.unwrap();
    assert_eq!(
        session.wait().await.unwrap(),
        HelperSessionOutcome::Exited { status: 0 }
    );

    assert_eq!(process.short_calls.lock().unwrap().len(), 1);
    assert_eq!(process.start_calls.lock().unwrap().len(), 1);
    assert!(*cancelled.lock().unwrap());
}

#[tokio::test]
async fn graceful_cleanup_sends_sigterm_status_repair_status_before_success() {
    // Catches: hard-killing an active Start session instead of exercising the helper lifecycle cleanup path.
    let evidence = graceful_cleanup_sequence_for_test(CleanupScenario::NeedsRepair)
        .await
        .unwrap();

    assert_eq!(
        evidence.actions,
        vec![
            CleanupAction::SigTerm,
            CleanupAction::WaitGraceful,
            CleanupAction::Status,
            CleanupAction::Repair,
            CleanupAction::Status,
        ]
    );
    assert_eq!(evidence.outcome, HelperSessionOutcome::Stopped);
    assert!(!evidence.orphaned);
}

#[tokio::test]
async fn graceful_cleanup_uses_hard_kill_only_after_bounded_sigterm_timeout_and_still_repairs() {
    // Catches: hard kill as the first cleanup action or skipping repair/status verification after fallback.
    let evidence = graceful_cleanup_sequence_for_test(CleanupScenario::GracefulTimeoutThenRepair)
        .await
        .unwrap();

    assert_eq!(
        evidence.actions,
        vec![
            CleanupAction::SigTerm,
            CleanupAction::WaitGraceful,
            CleanupAction::SigKill,
            CleanupAction::Reap,
            CleanupAction::Status,
            CleanupAction::Repair,
            CleanupAction::Status,
        ]
    );
    assert_eq!(evidence.outcome, HelperSessionOutcome::Stopped);
    assert!(!evidence.orphaned);
}

#[tokio::test]
async fn production_short_runner_uses_shared_cap_and_reaps_local_overflowing_process() {
    // Catches: stale SystemHelperProcess override that waits on child.wait() after output cap overflow.
    let evidence = production_short_overflow_launcher_for_test(10, Duration::from_secs(2))
        .await
        .unwrap();

    assert!(evidence.killed);
    assert!(evidence.reaped);
    assert!(evidence.elapsed < Duration::from_millis(500));
}

#[tokio::test]
async fn dropping_owned_start_session_has_explicit_cancel_semantics() {
    // Catches: returning Running from run(Start) and then silently tearing down because the owned session was dropped.
    assert!(drop_start_session_cancel_signal_for_test().await);
}

#[tokio::test]
async fn active_start_output_cap_reports_primary_failure_and_cleanup_failure() {
    // Catches: discarding cleanup failure after active-session output overflow.
    let outcome = active_start_failure_cleanup_for_test(
        ActiveStartFailureScenario::OutputLimitExceeded,
        CleanupScenario::CleanupFails,
    )
    .await
    .unwrap();

    assert_eq!(
        outcome,
        HelperSessionOutcome::FailedWithCleanup {
            failure: HelperSessionFailure::OutputLimitExceeded,
            cleanup: HelperCleanupOutcome::CleanupFailed,
        }
    );
}

#[tokio::test]
async fn active_start_prompt_parser_failure_runs_cleanup_and_reports_stopped() {
    // Catches: prompt/parser `?` returns that bypass graceful cleanup and status verification.
    let outcome = active_start_failure_cleanup_for_test(
        ActiveStartFailureScenario::InvalidResponse,
        CleanupScenario::NeedsRepair,
    )
    .await
    .unwrap();

    assert_eq!(
        outcome,
        HelperSessionOutcome::FailedWithCleanup {
            failure: HelperSessionFailure::InvalidResponse,
            cleanup: HelperCleanupOutcome::Stopped,
        }
    );
}

#[tokio::test]
async fn active_start_read_error_runs_cleanup_and_reports_repair_required() {
    // Catches: stdout/stderr read errors returning only the read error while hiding repair-required cleanup state.
    let outcome = active_start_failure_cleanup_for_test(
        ActiveStartFailureScenario::ReadError,
        CleanupScenario::CleanupEndsRepairRequired,
    )
    .await
    .unwrap();

    assert_eq!(
        outcome,
        HelperSessionOutcome::FailedWithCleanup {
            failure: HelperSessionFailure::InvocationFailed,
            cleanup: HelperCleanupOutcome::RepairRequired,
        }
    );
}

#[tokio::test]
async fn active_start_prompt_input_failure_runs_cleanup_and_reports_failed_status() {
    // Catches: TOTP-provider or stdin-write failures dropping via kill_on_drop without status/repair/status evidence.
    let outcome = active_start_failure_cleanup_for_test(
        ActiveStartFailureScenario::PromptInputUnavailable,
        CleanupScenario::CleanupLeavesRunning,
    )
    .await
    .unwrap();

    assert_eq!(
        outcome,
        HelperSessionOutcome::FailedWithCleanup {
            failure: HelperSessionFailure::PromptInputUnavailable,
            cleanup: HelperCleanupOutcome::Failed,
        }
    );
}

#[tokio::test]
async fn active_start_protocol_eof_runs_cleanup_and_reports_stopped() {
    // Catches: reader-channel EOF/protocol failure loops that never cleanup or report a final outcome.
    let outcome = active_start_failure_cleanup_for_test(
        ActiveStartFailureScenario::ProtocolEof,
        CleanupScenario::NeedsRepair,
    )
    .await
    .unwrap();

    assert_eq!(
        outcome,
        HelperSessionOutcome::FailedWithCleanup {
            failure: HelperSessionFailure::InvalidResponse,
            cleanup: HelperCleanupOutcome::Stopped,
        }
    );
}

#[tokio::test]
async fn helper_errors_do_not_echo_raw_stdout_stderr_or_secrets() {
    // Catches: diagnostics that leak password/TOTP/cookie/portal responses from helper output.
    let process = Arc::new(RecordingProcess {
        short_calls: Mutex::new(Vec::new()),
        start_calls: Mutex::new(Vec::new()),
        output: Mutex::new(Some(HelperProcessOutput {
            status: 64,
            stdout: b"password=hunter2".to_vec(),
            stderr: b"totp=123456 cookie=session portal=<html>".to_vec(),
        })),
        start_session: Mutex::new(None),
    });
    let runner = InstalledHelperRunner::with_process_for_test(process);

    let error = runner.run(HelperCommand::Status).await.unwrap_err();
    let diagnostic = format!("{error:?} {error}").to_ascii_lowercase();

    for forbidden in [
        "hunter2",
        "123456",
        "cookie=session",
        "<html>",
        "password=",
        "totp=",
    ] {
        assert!(
            !diagnostic.contains(forbidden),
            "leaked {forbidden}: {diagnostic}"
        );
    }
}
