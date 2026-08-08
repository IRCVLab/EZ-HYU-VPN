use std::fs;

use hyu_vpn_platform_linux::{HipContext, LinuxPostureCollector};
use tempfile::tempdir;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/linux-posture"
);

fn context() -> HipContext {
    HipContext {
        md5: "00000000000000000000000000000000".into(),
        user: "TEST-USER".into(),
        domain: String::new(),
        client_ip: "192.0.2.10".into(),
        client_ipv6: String::new(),
        client_version: "OpenConnect TEST".into(),
        generated_at: "08/04/2026 01:02:03".into(),
    }
}

#[test]
fn fixture_posture_matches_exact_hip_xml() {
    let posture = LinuxPostureCollector::from_fixture_dir(FIXTURES)
        .collect()
        .unwrap();
    let actual = posture.to_hip_xml(&context()).unwrap();
    let expected = fs::read_to_string(format!("{FIXTURES}/expected-hip.xml")).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn missing_evidence_is_unknown_and_hostile_text_is_escaped_and_bounded() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("hostname.txt"),
        "host<&\\\"'$(touch /tmp/never)\n",
    )
    .unwrap();
    let posture = LinuxPostureCollector::from_fixture_dir(dir.path())
        .collect()
        .unwrap();
    assert_eq!(posture.firewall, "unknown");
    assert_eq!(posture.encryption, "unknown");
    assert_eq!(posture.endpoint, "unknown");
    let xml = posture.to_hip_xml(&context()).unwrap();
    assert!(xml.contains("host&lt;&amp;"));
    assert!(!xml.contains("<host-name>host<&"));
    assert!(xml.len() < 64 * 1024);
    for secret_field in ["password", "totp_seed", "authcookie", "COOKIE-CANARY"] {
        assert!(!xml.contains(secret_field));
    }
}
