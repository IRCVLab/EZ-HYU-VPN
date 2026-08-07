use std::path::PathBuf;

use hyu_vpn_core::openconnect::{ConnectorConfig, build_openconnect_args};

#[test]
fn builds_fixed_openconnect_arguments_without_credentials() {
    let config = ConnectorConfig {
        executable: PathBuf::from("/usr/sbin/openconnect"),
        authgroup: "student".into(),
        vpnc_script: PathBuf::from("/usr/lib/hyu-vpn/vpnc-script"),
        hip_wrapper: PathBuf::from("/usr/lib/hyu-vpn/gp-hip-report"),
        portal: "secure.hanyang.ac.kr".into(),
    };
    let args = build_openconnect_args(&config).unwrap();
    assert_eq!(
        args,
        vec![
            "--protocol=gp",
            "--authgroup=student",
            "--no-dtls",
            "--passwd-on-stdin",
            "--script=/usr/lib/hyu-vpn/vpnc-script",
            "--csd-wrapper=/usr/lib/hyu-vpn/gp-hip-report",
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
        vpnc_script: PathBuf::from("/usr/lib/hyu-vpn/vpnc-script"),
        hip_wrapper: PathBuf::from("/usr/lib/hyu-vpn/gp-hip-report"),
        portal: "secure.hanyang.ac.kr".into(),
    };
    assert!(build_openconnect_args(&config).is_err());
    config.executable = PathBuf::from("/usr/sbin/openconnect");
    config.portal = "secure.hanyang.ac.kr\n--script=evil".into();
    assert!(build_openconnect_args(&config).is_err());
}
