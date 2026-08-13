use std::io::Write;
use std::process::{Command, Stdio};

fn service_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hyu-vpn-macos-service")
}

fn run_status(payload: &[u8], subcommand: &str) -> std::process::Output {
    let mut child = Command::new(service_bin())
        .args(["root-util", subcommand])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn root_util_fsync_invokes_native_sync_for_file_and_directory() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("ledger");
    std::fs::write(&file, b"pending").unwrap();

    assert!(
        Command::new(service_bin())
            .args(["root-util", "fsync", file.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(service_bin())
            .args(["root-util", "fsync", dir.path().to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn root_util_accepts_exact_legacy_repair_status_only_for_install_migration() {
    let legacy_stopped = br#"{"schema_version":1,"state":"stopped"}"#;
    let stopped = run_status(legacy_stopped, "helper-state");
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&stopped.stdout).trim(), "stopped");

    let legacy = br#"{"session_nonce":"C9889669001B4345B9D9B41B4A9C0DC9","schema_version":1,"state":"repair-required"}"#;
    let state = run_status(legacy, "helper-state");
    assert!(
        state.status.success(),
        "{}",
        String::from_utf8_lossy(&state.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&state.stdout).trim(),
        "repair-required"
    );

    let nonce = run_status(legacy, "helper-repair-nonce");
    assert!(
        nonce.status.success(),
        "{}",
        String::from_utf8_lossy(&nonce.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&nonce.stdout).trim(),
        "C9889669001B4345B9D9B41B4A9C0DC9"
    );

    for invalid in [
        br#"{"session_nonce":"nonce-123","schema_version":1,"state":"running"}"#.as_slice(),
        br#"{"session_nonce":"nonce-123","schema_version":1,"state":"repair-required","extra":true}"#.as_slice(),
        br#"{"session_nonce":"bad nonce","schema_version":1,"state":"repair-required"}"#.as_slice(),
        br#"{"schema_version":1,"state":"stopped","extra":true}"#.as_slice(),
    ] {
        assert!(!run_status(invalid, "helper-state").status.success());
        assert!(!run_status(invalid, "helper-repair-nonce").status.success());
    }
}

#[test]
fn root_util_helper_status_uses_strict_schema_v1_parser() {
    let valid = br#"{"schema_version":1,"state":"running","pid":123,"session_nonce":"nonce-123","tunnel_interface":"utun7"}"#;
    let out = run_status(valid, "helper-state");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "running");

    for invalid in [
        br#"{"state":"stopped"}"#.as_slice(),
        br#"{"schema_version":1,"state":"stopped","pid":null,"session_nonce":null,"tunnel_interface":null,"extra":true}"#.as_slice(),
        br#"{"schema_version":1,"state":"running","pid":123,"session_nonce":"nonce-123","tunnel_interface":"en0"}"#.as_slice(),
        b"{\"schema_version\":1,\"state\":\"stopped\",\"pid\":null,\"session_nonce\":null,\"tunnel_interface\":null}\n{\"schema_version\":1,\"state\":\"running\"}",
    ] {
        let out = run_status(invalid, "helper-state");
        assert!(!out.status.success(), "invalid status accepted: {}", String::from_utf8_lossy(invalid));
    }
}
