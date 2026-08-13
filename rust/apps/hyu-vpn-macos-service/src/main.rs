use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use hyu_vpn_platform_macos::{HelperState, parse_helper_status_for_test};
use tokio::sync::watch;

const EX_USAGE: i32 = 64;
const EX_SOFTWARE: i32 = 70;
const EX_CONFIG: i32 = 78;
const MIN_HEALTH_TIMEOUT_MS: u64 = 10;
const MAX_HEALTH_TIMEOUT_MS: u64 = 10_000;

struct HealthArgs {
    uid: u32,
    home: PathBuf,
    timeout: Duration,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("health") {
        std::process::exit(run_health_cli(&args).await);
    }
    if args.get(1).map(String::as_str) == Some("root-util") {
        std::process::exit(run_root_util_cli(&args));
    }
    if args.len() != 1 {
        eprintln!("hyu-vpn-macos-service: unsupported arguments");
        std::process::exit(EX_USAGE);
    }
    std::process::exit(run_service_cli().await);
}

async fn run_service_cli() -> i32 {
    let home = match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home),
        None => {
            eprintln!("hyu-vpn-macos-service: missing HOME");
            return EX_CONFIG;
        }
    };
    let config = match hyu_vpn_macos_service::ServiceConfig::production(&home) {
        Ok(config) => config,
        Err(_) => {
            eprintln!("hyu-vpn-macos-service: configuration error");
            return EX_CONFIG;
        }
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let shutdown_task = tokio::spawn(async move {
        hyu_vpn_macos_service::wait_for_shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });
    let result = hyu_vpn_macos_service::run_service(config, shutdown_rx).await;
    shutdown_task.abort();
    if result.is_err() {
        eprintln!("hyu-vpn-macos-service: service error");
        return EX_SOFTWARE;
    }
    0
}

async fn run_health_cli(args: &[String]) -> i32 {
    let parsed = match parse_health_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("hyu-vpn-macos-service: {message}");
            return EX_USAGE;
        }
    };
    if !health_identity_matches(parsed.uid, &parsed.home) {
        eprintln!("hyu-vpn-macos-service: health identity rejected");
        return EX_CONFIG;
    }
    let config = match hyu_vpn_macos_service::ServiceConfig::production(&parsed.home) {
        Ok(config) => config,
        Err(_) => {
            eprintln!("hyu-vpn-macos-service: health configuration rejected");
            return EX_CONFIG;
        }
    };
    match hyu_vpn_macos_service::run_health_check(config, parsed.timeout).await {
        Ok(()) => 0,
        Err(_) => {
            eprintln!("hyu-vpn-macos-service: health check failed");
            EX_SOFTWARE
        }
    }
}

fn run_root_util_cli(args: &[String]) -> i32 {
    match args.get(2).map(String::as_str) {
        Some("fsync") if args.len() == 4 => match fsync_path(Path::new(&args[3])) {
            Ok(()) => 0,
            Err(_) => EX_SOFTWARE,
        },
        Some("helper-state") if args.len() == 3 => {
            match read_stdin_status().and_then(|bytes| parse_root_helper_state(&bytes)) {
                Ok(HelperState::Stopped) => {
                    println!("stopped");
                    0
                }
                Ok(HelperState::Running { .. }) => {
                    println!("running");
                    0
                }
                Ok(HelperState::RepairRequired) => {
                    println!("repair-required");
                    0
                }
                Err(_) => EX_SOFTWARE,
            }
        }
        Some("helper-repair-nonce") if args.len() == 3 => {
            match read_stdin_status().and_then(|bytes| repair_nonce_from_status(&bytes)) {
                Ok(nonce) => {
                    println!("{nonce}");
                    0
                }
                Err(_) => EX_SOFTWARE,
            }
        }
        _ => {
            eprintln!(
                "hyu-vpn-macos-service: usage root-util fsync <path>|helper-state|helper-repair-nonce"
            );
            EX_USAGE
        }
    }
}

fn fsync_path(path: &Path) -> Result<(), ()> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| ())?;
    file.sync_all().map_err(|_| ())
}

fn read_stdin_status() -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.is_empty()
        || bytes.len() > 16 * 1024
        || bytes.iter().filter(|&&b| b == b'\n').count() > 1
    {
        return Err(());
    }
    Ok(bytes)
}

fn parse_root_helper_state(bytes: &[u8]) -> Result<HelperState, ()> {
    match parse_helper_status_for_test(bytes) {
        Ok(state) => Ok(state),
        Err(_) => legacy_helper_state(bytes),
    }
}

fn legacy_helper_state(bytes: &[u8]) -> Result<HelperState, ()> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    let object = value.as_object().ok_or(())?;
    if value.get("schema_version").and_then(|v| v.as_u64()) != Some(1) {
        return Err(());
    }
    if object.len() == 2
        && object.contains_key("schema_version")
        && object.contains_key("state")
        && value.get("state").and_then(|v| v.as_str()) == Some("stopped")
    {
        return Ok(HelperState::Stopped);
    }
    validated_legacy_repair_nonce(&value).map(|_| HelperState::RepairRequired)
}

fn repair_nonce_from_status(bytes: &[u8]) -> Result<String, ()> {
    if parse_helper_status_for_test(bytes).is_ok() {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ())?;
        return validated_repair_nonce(&value);
    }
    legacy_repair_nonce(bytes)
}

fn legacy_repair_nonce(bytes: &[u8]) -> Result<String, ()> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    validated_legacy_repair_nonce(&value)
}

fn validated_legacy_repair_nonce(value: &serde_json::Value) -> Result<String, ()> {
    let object = value.as_object().ok_or(())?;
    if object.len() != 3
        || !object.contains_key("schema_version")
        || !object.contains_key("state")
        || !object.contains_key("session_nonce")
        || value.get("schema_version").and_then(|v| v.as_u64()) != Some(1)
    {
        return Err(());
    }
    validated_repair_nonce(value)
}

fn validated_repair_nonce(value: &serde_json::Value) -> Result<String, ()> {
    if value.get("state").and_then(|v| v.as_str()) != Some("repair-required") {
        return Err(());
    }
    let nonce = value
        .get("session_nonce")
        .and_then(|v| v.as_str())
        .ok_or(())?;
    if nonce.len() < 8
        || nonce.len() > 128
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(());
    }
    Ok(nonce.to_owned())
}

fn parse_health_args(args: &[String]) -> Result<HealthArgs, &'static str> {
    if args.len() != 8
        || args[1] != "health"
        || args[2] != "--uid"
        || args[4] != "--home"
        || args[6] != "--timeout-ms"
    {
        return Err("usage: health --uid <uid> --home <absolute-home> --timeout-ms <bounded-ms>");
    }
    let uid = args[3]
        .parse::<u32>()
        .ok()
        .filter(|uid| *uid > 0)
        .ok_or("invalid uid")?;
    let home = PathBuf::from(&args[5]);
    if !is_strict_absolute_path(&home) {
        return Err("invalid home");
    }
    let timeout_ms = args[7]
        .parse::<u64>()
        .ok()
        .filter(|ms| (MIN_HEALTH_TIMEOUT_MS..=MAX_HEALTH_TIMEOUT_MS).contains(ms))
        .ok_or("invalid timeout")?;
    Ok(HealthArgs {
        uid,
        home,
        timeout: Duration::from_millis(timeout_ms),
    })
}

fn is_strict_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

#[cfg(unix)]
fn health_identity_matches(uid: u32, home: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(metadata) = std::fs::symlink_metadata(home) else {
        return false;
    };
    metadata.uid() == uid && unsafe { libc::geteuid() } as u32 == uid
}

#[cfg(not(unix))]
fn health_identity_matches(_uid: u32, home: &Path) -> bool {
    home.exists()
}
