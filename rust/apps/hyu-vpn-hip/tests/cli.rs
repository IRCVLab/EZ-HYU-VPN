use hyu_vpn_hip::{HipCliError, build_hip_from_args};
use hyu_vpn_platform_linux::LinuxPostureCollector;

#[test]
fn hip_cli_decodes_identity_escapes_xml_and_never_emits_cookie() {
    let fixture = LinuxPostureCollector::from_fixture_dir("tests/fixtures/linux-posture");
    let cookie = "user=alice%2Dvpn&domain=HYU&computer=lab%26desk";
    let args = vec![
        "--cookie".to_owned(),
        cookie.to_owned(),
        "--client-ip=192.0.2.10".to_owned(),
        "--md5=0123456789abcdef0123456789abcdef".to_owned(),
        "--client-os=Linux".to_owned(),
        "--app-version=OpenConnect-9.12".to_owned(),
    ];
    let xml = build_hip_from_args(&args, &fixture, "2026-08-08T00:00:00Z", None).unwrap();
    assert!(xml.contains("<user-name>alice-vpn</user-name>"));
    assert!(xml.contains("<domain>HYU</domain>"));
    assert!(!xml.contains(cookie));
}

#[test]
fn hip_cli_rejects_unknown_duplicate_and_missing_required_options() {
    let fixture = LinuxPostureCollector::from_fixture_dir("tests/fixtures/linux-posture");
    for args in [
        vec!["--unknown=x".to_owned()],
        vec![
            "--cookie=user=a".to_owned(),
            "--cookie=user=b".to_owned(),
            "--client-ip=1.2.3.4".to_owned(),
            "--md5=0123456789abcdef0123456789abcdef".to_owned(),
        ],
        vec![
            "--cookie=user=a".to_owned(),
            "--md5=0123456789abcdef0123456789abcdef".to_owned(),
        ],
    ] {
        assert_eq!(
            build_hip_from_args(&args, &fixture, "2026-08-08T00:00:00Z", None).unwrap_err(),
            HipCliError::InvalidInvocation
        );
    }
}
