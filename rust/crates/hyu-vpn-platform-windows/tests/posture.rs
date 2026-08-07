use hyu_vpn_platform_windows::{
    WindowsEvidence, WindowsHipContext, WindowsPostureCollector, WindowsPostureError,
};

fn context() -> WindowsHipContext {
    WindowsHipContext {
        md5: "0123456789abcdef0123456789abcdef".into(),
        user: "alice".into(),
        domain: "HYU".into(),
        client_ip: "192.0.2.10".into(),
        client_ipv6: "::".into(),
        client_version: "9.12".into(),
        generated_at: "2026-08-08T00:00:00Z".into(),
    }
}

#[test]
fn windows_fixture_produces_windows_specific_escaped_hip_xml() {
    let collector = WindowsPostureCollector::from_evidence(WindowsEvidence {
        product_name: Some("Windows 11 Pro & Lab".into()),
        display_version: Some("24H2".into()),
        build_number: Some("26100".into()),
        hostname: Some("DESKTOP<SAFE>".into()),
        firewall_enabled: Some(true),
        defender_enabled: Some(true),
        encryption: Some("encrypted".into()),
    });
    let posture = collector.collect().unwrap();
    let xml = posture.to_hip_xml(&context()).unwrap();

    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    assert!(xml.contains("<os-vendor>Microsoft</os-vendor>"));
    assert!(xml.contains("Windows 11 Pro &amp; Lab 24H2 (build 26100)"));
    assert!(xml.contains("<host-name>DESKTOP&lt;SAFE&gt;</host-name>"));
    assert!(xml.contains("Microsoft Defender Antivirus"));
    assert!(xml.contains("Windows Defender Firewall"));
    assert!(xml.contains("<enc-state>encrypted</enc-state>"));
    assert!(!xml.contains("DESKTOP<SAFE>"));
}

#[test]
fn windows_posture_rejects_control_characters_and_oversize_xml_values() {
    let collector = WindowsPostureCollector::from_evidence(WindowsEvidence {
        product_name: Some("Windows".into()),
        display_version: Some("24H2".into()),
        build_number: Some("26100".into()),
        hostname: Some("bad\nhost".into()),
        firewall_enabled: None,
        defender_enabled: None,
        encryption: None,
    });
    assert_eq!(collector.collect().unwrap().hostname, "unknown");

    let mut invalid = context();
    invalid.user = "x".repeat(1025);
    let posture = WindowsPostureCollector::production().collect().unwrap();
    assert_eq!(
        posture.to_hip_xml(&invalid).unwrap_err(),
        WindowsPostureError::InvalidEvidence
    );
}
