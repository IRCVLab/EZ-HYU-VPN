use std::path::PathBuf;

use hyu_vpn_core::openconnect::{ConnectorConfig, build_openconnect_args};

fn absolute(unix: &str, windows: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(windows)
    } else {
        PathBuf::from(unix)
    }
}

#[test]
fn builds_fixed_openconnect_arguments_without_credentials() {
    let config = ConnectorConfig {
        executable: absolute(
            "/usr/sbin/openconnect",
            r"C:\Program Files\HYU VPN\openconnect.exe",
        ),
        authgroup: "student".into(),
        vpnc_script: absolute(
            "/usr/lib/hyu-vpn/vpnc-script",
            r"C:\Program Files\HYU VPN\vpnc-script-win.js",
        ),
        hip_wrapper: absolute(
            "/usr/lib/hyu-vpn/gp-hip-report",
            r"C:\Program Files\HYU VPN\hyu-vpn-hip.exe",
        ),
        portal: "secure.hanyang.ac.kr".into(),
    };
    let args = build_openconnect_args(&config).unwrap();
    let script = if cfg!(windows) {
        r"--script=C:\Program Files\HYU VPN\vpnc-script-win.js"
    } else {
        "--script=/usr/lib/hyu-vpn/vpnc-script"
    };
    let wrapper = if cfg!(windows) {
        r"--csd-wrapper=C:\Program Files\HYU VPN\hyu-vpn-hip.exe"
    } else {
        "--csd-wrapper=/usr/lib/hyu-vpn/gp-hip-report"
    };
    assert_eq!(
        args,
        vec![
            "--protocol=gp",
            "--authgroup=student",
            "--no-dtls",
            "--passwd-on-stdin",
            script,
            wrapper,
            "secure.hanyang.ac.kr",
        ]
    );
    let joined = args.join(" ").to_ascii_lowercase();
    for forbidden in ["username", "password", "totp", "cookie", "--user="] {
        assert!(!joined.contains(forbidden));
    }
}

#[test]
fn rejects_relative_or_control_character_configuration() {
    let mut config = ConnectorConfig {
        executable: PathBuf::from("openconnect"),
        authgroup: "student".into(),
        vpnc_script: absolute(
            "/usr/lib/hyu-vpn/vpnc-script",
            r"C:\Program Files\HYU VPN\vpnc-script-win.js",
        ),
        hip_wrapper: absolute(
            "/usr/lib/hyu-vpn/gp-hip-report",
            r"C:\Program Files\HYU VPN\hyu-vpn-hip.exe",
        ),
        portal: "secure.hanyang.ac.kr".into(),
    };
    assert!(build_openconnect_args(&config).is_err());
    config.executable = absolute(
        "/usr/sbin/openconnect",
        r"C:\Program Files\HYU VPN\openconnect.exe",
    );
    config.portal = "secure.hanyang.ac.kr\n--script=evil".into();
    assert!(build_openconnect_args(&config).is_err());
}
