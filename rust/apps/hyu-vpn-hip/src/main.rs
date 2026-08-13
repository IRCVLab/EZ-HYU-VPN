use std::io::Write;

use hyu_vpn_hip::resolve_cookie_stdin_args;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use hyu_vpn_hip::build_hip_from_args;
#[cfg(target_os = "macos")]
use hyu_vpn_hip::build_macos_hip_from_args;
#[cfg(windows)]
use hyu_vpn_hip::build_windows_hip_from_args;
#[cfg(target_os = "linux")]
use hyu_vpn_platform_linux::LinuxPostureCollector;
#[cfg(windows)]
use hyu_vpn_platform_windows::WindowsPostureCollector;

fn main() {
    if let Err(code) = run() {
        std::process::exit(code);
    }
}

fn run() -> Result<(), i32> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    if raw_args == ["--smoke-test"] {
        println!("HYU VPN HIP smoke test passed");
        return Ok(());
    }
    let stdin = std::io::stdin();
    let args = Zeroizing::new(resolve_cookie_stdin_args(&raw_args, stdin.lock()).map_err(|_| 2)?);
    let generated_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| 4)?;
    #[cfg(target_os = "linux")]
    let xml = build_hip_from_args(
        &args,
        &LinuxPostureCollector::production(),
        &generated_at,
        std::env::var("APP_VERSION").ok().as_deref(),
    );
    #[cfg(windows)]
    let xml = build_windows_hip_from_args(
        &args,
        &WindowsPostureCollector::production(),
        &generated_at,
        std::env::var("APP_VERSION").ok().as_deref(),
    );
    #[cfg(target_os = "macos")]
    let xml = build_macos_hip_from_args(
        &args,
        &generated_at,
        std::env::var("APP_VERSION").ok().as_deref(),
    );
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    let xml: Result<String, hyu_vpn_hip::HipCliError> = Err(hyu_vpn_hip::HipCliError::Collection);
    let xml = xml.map_err(|error| {
        eprintln!("HYU VPN HIP failed: {error}");
        2
    })?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(xml.as_bytes()).map_err(|_| 5)?;
    stdout.flush().map_err(|_| 5)
}
