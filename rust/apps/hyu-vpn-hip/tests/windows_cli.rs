#[cfg(windows)]
#[test]
fn windows_hip_cli_uses_windows_posture_and_escapes_identity() {
    use hyu_vpn_hip::build_windows_hip_from_args;
    use hyu_vpn_platform_windows::{WindowsEvidence, WindowsPostureCollector};

    let args = vec![
        "--cookie".to_owned(),
        "user=alice&domain=HYU&computer=WIN%3CLAB%3E".to_owned(),
        "--md5".to_owned(),
        "0123456789abcdef0123456789abcdef".to_owned(),
        "--client-ip".to_owned(),
        "192.0.2.10".to_owned(),
    ];
    let collector = WindowsPostureCollector::from_evidence(WindowsEvidence {
        product_name: Some("Windows 11 Pro".into()),
        display_version: Some("24H2".into()),
        build_number: Some("26100".into()),
        hostname: Some("ORIGINAL".into()),
        firewall_enabled: Some(true),
        defender_enabled: Some(true),
        encryption: Some("encrypted".into()),
    });
    let xml = build_windows_hip_from_args(&args, &collector, "2026-08-08T00:00:00Z", Some("9.21"))
        .unwrap();
    assert!(xml.contains("<os-vendor>Microsoft</os-vendor>"));
    assert!(xml.contains("<host-name>WIN&lt;LAB&gt;</host-name>"));
    assert!(!xml.contains("WIN<LAB>"));
}
