use std::io::Write;

use hyu_vpn_hip::build_hip_from_args;
use hyu_vpn_platform_linux::LinuxPostureCollector;

fn main() {
    if let Err(code) = run() {
        std::process::exit(code);
    }
}

fn run() -> Result<(), i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--smoke-test"] {
        println!("HYU VPN HIP smoke test passed");
        return Ok(());
    }
    let generated_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| 4)?;
    let xml = build_hip_from_args(
        &args,
        &LinuxPostureCollector::production(),
        &generated_at,
        std::env::var("APP_VERSION").ok().as_deref(),
    )
    .map_err(|error| {
        eprintln!("HYU VPN HIP failed: {error}");
        2
    })?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(xml.as_bytes()).map_err(|_| 5)?;
    stdout.flush().map_err(|_| 5)
}
